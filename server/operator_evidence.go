package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const operatorEvidenceDir = "operator-evidence"

type operatorEvidenceMetadata struct {
	TaskID   int64  `json:"task_id"`
	IntentID int64  `json:"intent_id"`
	Name     string `json:"name"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// openOperatorEvidenceDir rejects inherited directories that an executor could
// enter or replace. The data root is controlled by the server; each child is
// created with owner-only access before the next child is touched.
func openOperatorEvidenceDir(dataDir string, taskID int64) (*os.Root, string, error) {
	return openOperatorEvidenceDirMode(dataDir, taskID, true)
}

func openExistingOperatorEvidenceDir(dataDir string, taskID int64) (*os.Root, string, error) {
	return openOperatorEvidenceDirMode(dataDir, taskID, false)
}

func openOperatorEvidenceDirMode(dataDir string, taskID int64, create bool) (*os.Root, string, error) {
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return nil, "", err
	}
	base, err := root.Open(".")
	if err != nil {
		root.Close()
		return nil, "", err
	}
	baseInfo, err := base.Stat()
	base.Close()
	if err != nil || !baseInfo.IsDir() || baseInfo.Mode().Perm()&0o022 != 0 || !evidenceOwnedByServer(baseInfo) {
		root.Close()
		return nil, "", fmt.Errorf("data directory is not private from executors")
	}
	parts := []string{operatorEvidenceDir, "tasks", strconv.FormatInt(taskID, 10)}
	for i := range parts {
		rel := filepath.Join(parts[:i+1]...)
		if create {
			if err := root.Mkdir(rel, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
				root.Close()
				return nil, "", err
			}
		}
		path := filepath.Join(dataDir, rel)
		lst, err := os.Lstat(path)
		if err != nil || !lst.IsDir() || lst.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, "", fmt.Errorf("operator evidence directory is unsafe")
		}
		f, err := root.Open(rel)
		if err != nil {
			root.Close()
			return nil, "", err
		}
		fi, err := f.Stat()
		f.Close()
		if err != nil || !fi.IsDir() || !os.SameFile(lst, fi) || fi.Mode().Perm() != 0o700 || !evidenceOwnedByServer(fi) {
			root.Close()
			return nil, "", fmt.Errorf("operator evidence directory is not private")
		}
	}
	return root, filepath.Join(parts...), nil
}

func saveOperatorEvidence(ctx context.Context, root *os.Root, dir string, taskID, intentID int64, name string, in io.Reader, expected int64) (operatorEvidenceMetadata, error) {
	var meta operatorEvidenceMetadata
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return meta, fmt.Errorf("invalid evidence name")
	}
	path := filepath.Join(dir, name)
	out, err := root.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return meta, err
	}
	complete := false
	metadataCreated := false
	defer func() {
		out.Close()
		if !complete {
			root.Remove(path)
			if metadataCreated {
				root.Remove(path + ".json")
			}
		}
	}()
	h := sha256.New()
	if err := copyUploadBounded(ctx, io.MultiWriter(out, h), in, expected, askOperatorMaxImage); err != nil {
		return meta, err
	}
	if err := out.Sync(); err != nil {
		return meta, err
	}
	check, err := openWorkspaceCandidate(root, path)
	if err != nil {
		return meta, err
	}
	data, err := io.ReadAll(io.LimitReader(check, askOperatorMaxImage+1))
	check.Close()
	if err != nil || int64(len(data)) != expected {
		return meta, fmt.Errorf("image changed while staging")
	}
	if err := validateOperatorEvidenceImage(data, filepath.Ext(name)); err != nil {
		return meta, err
	}
	meta = operatorEvidenceMetadata{TaskID: taskID, IntentID: intentID, Name: name, Size: expected, SHA256: hex.EncodeToString(h.Sum(nil))}
	blob, err := json.Marshal(meta)
	if err != nil {
		return meta, err
	}
	index, err := root.OpenFile(path+".json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return meta, err
	}
	metadataCreated = true
	_, err = index.Write(blob)
	if err == nil {
		err = index.Sync()
	}
	if closeErr := index.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return meta, err
	}
	complete = true
	return meta, nil
}

func validateOperatorEvidenceImage(data []byte, extension string) error {
	ext := strings.ToLower(extension)
	mime := http.DetectContentType(data)
	want := map[string]string{".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}[ext]
	if want == "" || mime != want {
		return fmt.Errorf("image content does not match its extension")
	}
	if ext == ".webp" {
		if len(data) < 20 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" || int64(binary.LittleEndian.Uint32(data[4:8])) != int64(len(data)-8) {
			return fmt.Errorf("invalid WebP container")
		}
		chunk := string(data[12:16])
		if chunk != "VP8 " && chunk != "VP8L" && chunk != "VP8X" || int64(binary.LittleEndian.Uint32(data[16:20])) > int64(len(data)-20) {
			return fmt.Errorf("invalid WebP image chunk")
		}
		return nil
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > 8192 || config.Height > 8192 || "image/"+format != want {
		return fmt.Errorf("invalid image content")
	}
	return nil
}

func (s *Server) taskOperatorEvidence(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	name := r.PathValue("name")
	if err != nil || taskID <= 0 || name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) || !strings.HasPrefix(name, "ask-operator-") {
		writeErr(w, http.StatusBadRequest, "invalid evidence reference")
		return
	}
	root, dir, err := openExistingOperatorEvidenceDir(s.m.dir, taskID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "evidence not found")
		return
	}
	defer root.Close()
	path := filepath.Join(dir, name)
	index, err := openWorkspaceCandidate(root, path+".json")
	if err != nil {
		writeErr(w, http.StatusNotFound, "evidence not found")
		return
	}
	metaBytes, err := io.ReadAll(io.LimitReader(index, 4097))
	index.Close()
	if err != nil || len(metaBytes) > 4096 {
		writeErr(w, http.StatusNotFound, "evidence not found")
		return
	}
	var meta operatorEvidenceMetadata
	if json.Unmarshal(metaBytes, &meta) != nil || meta.TaskID != taskID || meta.Name != name || meta.Size < 0 || meta.Size > askOperatorMaxImage {
		writeErr(w, http.StatusNotFound, "evidence not found")
		return
	}
	f, err := openWorkspaceCandidate(root, path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "evidence not found")
		return
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != meta.Size {
		f.Close()
		writeErr(w, http.StatusNotFound, "evidence not found")
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, askOperatorMaxImage+1))
	f.Close()
	digest := sha256.Sum256(data)
	if err != nil || int64(len(data)) != meta.Size || hex.EncodeToString(digest[:]) != meta.SHA256 {
		writeErr(w, http.StatusNotFound, "evidence not found")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}
