package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type cancellingEvidenceReader struct {
	cancel context.CancelFunc
	read   bool
}

func (r *cancellingEvidenceReader) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	r.cancel()
	copy(p, "partial")
	return len("partial"), nil
}

func TestAskOperatorEvidenceIsOutsideExecutorTree(t *testing.T) {
	dataDir, taskDir := askOperatorRunDirs(t)
	att, err := stageAskOperatorImage(dataDir, 7, 3, "shot.png")
	if err != nil || len(att) != 1 {
		t.Fatalf("stage image: %v, %v", att, err)
	}
	if strings.HasPrefix(att[0].Path, "uploads/") {
		t.Fatal("operator evidence remains in the task uploads tree")
	}
	if _, err := os.Lstat(filepath.Join(taskDir, "uploads", att[0].Name)); !os.IsNotExist(err) {
		t.Fatalf("executor tree contains evidence copy: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, filepath.FromSlash(att[0].Path))); err != nil {
		t.Fatalf("protected copy missing: %v", err)
	}
}

func TestAskOperatorEvidenceSnapshotAndIntegrity(t *testing.T) {
	dataDir, taskDir := askOperatorRunDirs(t)
	att, err := stageAskOperatorImage(dataDir, 7, 3, "shot.png")
	if err != nil || len(att) != 1 {
		t.Fatalf("stage: %v, %v", att, err)
	}
	if att[0].URL == "" || att[0].SHA256 == "" {
		t.Fatalf("missing evidence reference: %+v", att[0])
	}
	if _, ok := newTestWorkspaceServer(dataDir).wsResolveConfined(att[0].Path); ok {
		t.Fatal("protected evidence is writable through the workspace API")
	}
	metaBytes, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(att[0].Path)+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta operatorEvidenceMetadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		t.Fatal(err)
	}
	pngBytes := testOperatorPNG(t)
	wantHash := sha256.Sum256(pngBytes)
	if meta.TaskID != 7 || meta.IntentID != 3 || meta.SHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("wrong evidence attribution: %+v", meta)
	}
	if err := os.WriteFile(filepath.Join(taskDir, "i3", "shot.png"), []byte("changed source"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestWorkspaceServer(dataDir)
	unauthenticated := httptest.NewRecorder()
	s.Handler().ServeHTTP(unauthenticated, httptest.NewRequest("GET", att[0].URL, nil))
	if unauthenticated.Code != 401 {
		t.Fatalf("evidence route without credentials returned %d", unauthenticated.Code)
	}
	request := func() (int, string) {
		r := httptest.NewRequest("GET", att[0].URL, nil)
		r.SetPathValue("id", "7")
		r.SetPathValue("name", att[0].Name)
		w := httptest.NewRecorder()
		s.taskOperatorEvidence(w, r)
		return w.Code, w.Body.String()
	}
	if code, body := request(); code != 200 || !bytes.Equal([]byte(body), pngBytes) {
		t.Fatalf("snapshot: %d bytes=%d", code, len(body))
	}
	if err := os.WriteFile(filepath.Join(dataDir, filepath.FromSlash(att[0].Path)), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := request(); code != 404 {
		t.Fatalf("tampered evidence returned %d", code)
	}
}

func TestAskOperatorEvidenceRejectsSharedDirectory(t *testing.T) {
	dataDir, _ := askOperatorRunDirs(t)
	root, prefix, err := openOperatorEvidenceDir(dataDir, 7)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if err := os.Chmod(filepath.Join(dataDir, prefix), 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := stageAskOperatorImage(dataDir, 7, 3, "shot.png"); err == nil {
		t.Fatal("accepted an evidence directory writable by a shared group")
	}
}

func TestAskOperatorEvidenceCancellationLeavesNoCopy(t *testing.T) {
	dataDir, _ := askOperatorRunDirs(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stageAskOperatorImageContext(ctx, dataDir, 7, 3, "shot.png"); err == nil {
		t.Fatal("cancelled staging succeeded")
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "operator-evidence", "tasks", "7"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled staging left %d entries: %v", len(entries), err)
	}
}

func TestAskOperatorEvidenceRejectsDisguisedImage(t *testing.T) {
	dataDir, taskDir := askOperatorRunDirs(t)
	if err := os.WriteFile(filepath.Join(taskDir, "i3", "bad.png"), []byte("not an image"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := stageAskOperatorImage(dataDir, 7, 3, "bad.png"); err == nil {
		t.Fatal("accepted non-image content with a PNG extension")
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "operator-evidence", "tasks", "7"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejected image left %d entries: %v", len(entries), err)
	}
	if err := validateOperatorEvidenceImage([]byte("RIFF\x04\x00\x00\x00WEBP"), ".webp"); err == nil {
		t.Fatal("accepted a truncated WebP container")
	}
}

func TestAskOperatorEvidencePartialCopyIsRemoved(t *testing.T) {
	dataDir, _ := askOperatorRunDirs(t)
	root, prefix, err := openOperatorEvidenceDir(dataDir, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	reader := &cancellingEvidenceReader{cancel: cancel}
	if _, err := saveOperatorEvidence(ctx, root, prefix, 7, 3, "ask-operator-partial.png", reader, 100); err == nil {
		t.Fatal("cancelled copy succeeded")
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, prefix))
	if err != nil || len(entries) != 0 {
		t.Fatalf("partial copy left %d entries: %v", len(entries), err)
	}
}

func TestAskOperatorImageParentSwapCannotEscape(t *testing.T) {
	dataDir, taskDir := askOperatorRunDirs(t)
	runDir := filepath.Join(taskDir, "i3")
	child := filepath.Join(runDir, "child")
	outside := filepath.Join(dataDir, "outside")
	for _, dir := range []string{child, outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	image := testOperatorPNG(t)
	insidePath := filepath.Join(child, "shot.png")
	if err := os.WriteFile(insidePath, image, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "shot.png"), []byte("outside secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(insidePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(child, filepath.Join(runDir, "child-old")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, child); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if f, err := openAskOperatorImage(runDir, insidePath, st); err == nil {
		f.Close()
		t.Fatal("opened an image through a swapped parent outside the run directory")
	}
}

func TestMissingOperatorEvidenceReadDoesNotCreateStore(t *testing.T) {
	dataDir := t.TempDir()
	s := newTestWorkspaceServer(dataDir)
	r := httptest.NewRequest("GET", "/api/tasks/99/evidence/ask-operator-missing.png", nil)
	r.SetPathValue("id", "99")
	r.SetPathValue("name", "ask-operator-missing.png")
	w := httptest.NewRecorder()
	s.taskOperatorEvidence(w, r)
	if w.Code != 404 {
		t.Fatalf("missing evidence returned %d", w.Code)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "operator-evidence")); !os.IsNotExist(err) {
		t.Fatalf("read created an evidence store: %v", err)
	}
}
