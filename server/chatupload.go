package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const (
	// maxChatUpload caps the combined file data in one attachment upload.
	maxChatUpload = 512 << 20 // 512 MiB
	// Allow multipart headers and boundaries in addition to the file data.
	chatUploadMultipartOverhead = 1 << 20 // 1 MiB
	chatUploadLimitMessage      = "files exceed the 512 MiB upload limit"
	// maxUploadNameTries bounds the name-1, name-2, … exclusive-create search.
	maxUploadNameTries = 10000
	// Each admitted request may spool up to maxChatUpload plus multipart overhead.
	// Keep the process-wide parser concurrency bounded even if the operational
	// setting is misconfigured.
	defaultUploadConcurrency = 4
	maxUploadConcurrency     = 16
)

// acquireUploadSlot limits all multipart upload parsers in this server process.
// The old chat-specific setting remains an alias for existing deployments.
func (s *Server) acquireUploadSlot() bool {
	s.uploadOnce.Do(func() {
		limit := defaultUploadConcurrency
		configured := strings.TrimSpace(os.Getenv("ARTEX_UPLOAD_CONCURRENCY"))
		if configured == "" {
			configured = strings.TrimSpace(os.Getenv("ARTEX_CHAT_UPLOAD_CONCURRENCY"))
		}
		if n, err := strconv.Atoi(configured); err == nil && n >= 1 && n <= maxUploadConcurrency {
			limit = n
		}
		s.uploadSlots = make(chan struct{}, limit)
	})
	select {
	case s.uploadSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

// safeChatID guards the {id} path segment against traversal — task ids are numeric,
// session ids are alnum/_/- ; anything with "/" or ".." is rejected.
var safeChatID = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// chatAttachment is one uploaded file as the frontend + agent see it. Path is relative
// to the chat's working dir (e.g. "uploads/report.txt"), which is the agent's CWD, so
// it can Read/Bash the file directly; Name/Size drive the UI card.
type chatAttachment struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	// Abs is the absolute on-disk path (m.dir is already absolute). For pre-task staging
	// (scope=staging) the frontend uses it to write the prompt into the description; task/session use composeAgentMessage, which builds the path in the backend.
	Abs string `json:"abs,omitempty"`
}

// chatUpload implements method-1 file support: it saves one or more files into a chat's
// working dir under uploads/, so the agent opens them with its existing Read/Bash tools
// and the sent message carries their paths. No LLM-layer change, no multimodal.
//
// POST /api/chat/upload?scope=task|session|staging&id=<id>, multipart field "file"
// (repeatable). Returns {attachments:[{name,path,size,abs}]}. Target dir mirrors the
// agent CWD layout (the run directory is created like the agent creates it):
//
//	scope=task    → <workDir>/tasks/<id>/main/uploads/   (the main agent's run directory)
//	scope=session → <workDir>/sessions/<id>/uploads/
//	scope=staging → <workDir>/drafts/<id>/uploads/   (pre-task staging: the task has no ID yet;
//	                files land here first and the frontend writes their abs paths into the task description)
func (s *Server) chatUpload(w http.ResponseWriter, r *http.Request) {
	var sub string
	taskScoped := false
	switch r.URL.Query().Get("scope") {
	case "task":
		sub = "tasks"
		taskScoped = true
	case "session":
		sub = "sessions"
	case "staging":
		sub = "drafts"
	default:
		writeErr(w, 400, "scope must be task / session / staging")
		return
	}
	id := r.URL.Query().Get("id")
	if !safeChatID.MatchString(id) {
		writeErr(w, 400, "invalid id")
		return
	}
	if !s.acquireUploadSlot() {
		w.Header().Set("Retry-After", "1")
		writeErr(w, http.StatusTooManyRequests, "too many concurrent uploads; retry shortly")
		return
	}
	defer func() { <-s.uploadSlots }()
	base := filepath.Join(s.m.dir, sub, id) // the directory uploads/ goes in
	var taskID int64
	if taskScoped {
		t := s.m.ResolveTask(id)
		if t == nil {
			writeErr(w, 404, "task not found")
			return
		}
		if !s.engine.beginTaskOperation(id) {
			writeErr(w, http.StatusConflict, "Task is being deleted; cannot upload attachments")
			return
		}
		defer s.engine.decInflight(id)
		taskID, _ = strconv.ParseInt(t.ID, 10, 64)
		base = agent.EnsureRunDir(s.m.dir, taskID, 0)
	} else if sub == "sessions" {
		base = agent.EnsureSessionDir(s.m.dir, id)
	}
	if sub == "drafts" {
		dataRoot, err := os.OpenRoot(s.m.dir)
		if err != nil {
			writeErr(w, 500, "failed to open upload root")
			return
		}
		defer dataRoot.Close()
		if err := dataRoot.MkdirAll(filepath.Join(sub, id), 0o755); err != nil {
			writeErr(w, 500, "failed to create staging directory")
			return
		}
	}
	dir := filepath.Join(base, "uploads")
	// Task uploads pin each run-directory ancestor below the data root. A link
	// inside uploads cannot lead to a sibling campaign.
	var root *os.Root
	var err error
	if taskScoped {
		root, err = openTaskRunRoot(s.m.dir, taskID)
	} else {
		root, err = os.OpenRoot(base)
	}
	if err != nil {
		writeErr(w, 500, "failed to open upload root")
		return
	}
	defer root.Close()
	if err := root.MkdirAll("uploads", 0o755); err != nil {
		writeErr(w, 500, "failed to create directory: "+err.Error())
		return
	}
	uploadDir, err := root.OpenRoot("uploads")
	if err != nil {
		writeErr(w, 500, "failed to open upload directory")
		return
	}
	defer uploadDir.Close()
	var savedNames []string
	committed := false
	defer func() {
		if !committed {
			for _, name := range savedNames {
				_ = uploadDir.Remove(name)
			}
		}
	}()
	r.Body = http.MaxBytesReader(w, r.Body, maxChatUpload+chatUploadMultipartOverhead)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, chatUploadLimitMessage)
			return
		}
		writeErr(w, 400, "failed to parse the upload: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "missing upload file (form field file)")
		return
	}
	var totalSize int64
	for _, hdr := range files {
		totalSize += hdr.Size
	}
	if totalSize > maxChatUpload {
		writeErr(w, http.StatusRequestEntityTooLarge, chatUploadLimitMessage)
		return
	}
	out := make([]chatAttachment, 0, len(files))
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			writeErr(w, 400, "invalid upload filename")
			return
		}
		savedName, digest, err := saveChatUploadWithDigest(uploadDir, hdr, name, r.Context())
		if err != nil {
			writeErr(w, 500, "Save failed: "+err.Error())
			return
		}
		savedNames = append(savedNames, savedName)
		att := chatAttachment{Name: savedName, Path: "uploads/" + savedName, Size: hdr.Size, SHA256: digest}
		if sub == "drafts" {
			att.Abs = filepath.Join(dir, savedName)
		}
		out = append(out, att)
	}
	committed = true
	writeJSON(w, 200, map[string]any{"attachments": out})
}

// createUniqueChatFile reserves a name and opens it in one confined operation.
// An existing file, link or concurrent creator causes a suffix retry.
func createUniqueChatFile(dir *os.Root, name string) (*os.File, string, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return nil, "", fmt.Errorf("invalid upload name")
	}
	open := func(candidate string) (*os.File, error) {
		return dir.OpenFile(candidate, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	}
	if f, err := open(name); err == nil {
		return f, name, nil
	} else if !errors.Is(err, os.ErrExist) {
		return nil, "", err
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; i <= maxUploadNameTries; i++ {
		candidate := fmt.Sprintf("%s-%d%s", stem, i, ext)
		if f, err := open(candidate); err == nil {
			return f, candidate, nil
		} else if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", fmt.Errorf("no free name for upload %q", name)
}

// saveChatUpload rejects incomplete or cancelled copies and removes the name
// through the same directory descriptor. Header Size comes from multipart
// parsing, and the request body and aggregate sizes are bounded above.
func saveChatUpload(dir *os.Root, hdr *multipart.FileHeader, name string, ctx context.Context) (string, error) {
	savedName, _, err := saveChatUploadWithDigest(dir, hdr, name, ctx)
	return savedName, err
}

func saveChatUploadWithDigest(dir *os.Root, hdr *multipart.FileHeader, name string, ctx context.Context) (string, string, error) {
	if hdr.Size < 0 || hdr.Size > maxChatUpload {
		return "", "", fmt.Errorf("upload exceeds size limit")
	}
	src, err := hdr.Open()
	if err != nil {
		return "", "", err
	}
	defer src.Close()
	out, savedName, err := createUniqueChatFile(dir, name)
	if err != nil {
		return "", "", err
	}
	complete := false
	defer func() {
		_ = out.Close()
		if !complete {
			_ = dir.Remove(savedName)
		}
	}()
	hasher := sha256.New()
	if err := copyUploadBounded(ctx, io.MultiWriter(out, hasher), src, hdr.Size, maxChatUpload); err != nil {
		return "", "", err
	}
	if err := out.Close(); err != nil {
		return "", "", err
	}
	complete = true
	return savedName, hex.EncodeToString(hasher.Sum(nil)), nil
}

// composeAgentMessage appends an attachment manifest to the user's message so the agent
// knows which files were uploaded and where to Read them. baseDir is the agent's working
// dir (its CWD); we emit ABSOLUTE paths (baseDir + relative) so the agent can Read/Bash
// them unambiguously regardless of how it interprets relative paths.
func composeAgentMessage(msg string, atts []chatAttachment, baseDir string) string {
	if len(atts) == 0 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg)
	b.WriteString("\n\n[User-uploaded attachments] (absolute paths; use Read/Bash to view them):")
	for _, a := range atts {
		attachmentPath := filepath.Join(baseDir, a.Path)
		if baseDir == "/campaign/main" {
			attachmentPath = path.Join(baseDir, a.Path)
		}
		fmt.Fprintf(&b, "\n- %s (%s)", attachmentPath, humanBytes(a.Size))
	}
	return b.String()
}

// userActivityWithAttachments builds the persisted 'user' activity. With attachments,
// Detail holds JSON {text, attachments} so the transcript renders text + attachment
// cards; Summary stays the plain text (the list payload omits Detail, lazy-loaded).
func userActivityWithAttachments(worker, text string, atts []chatAttachment) db.Activity {
	a := db.Activity{Worker: worker, Kind: "user", Summary: text}
	if len(atts) > 0 {
		blob, _ := json.Marshal(map[string]any{"text": text, "attachments": atts})
		a.Detail = string(blob)
	}
	return a
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
