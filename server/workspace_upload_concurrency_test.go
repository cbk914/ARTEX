package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type countedUploadBody struct{ reads int }

func (b *countedUploadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*countedUploadBody) Close() error               { return nil }

func TestWorkspaceUploadSharesProcessAdmission(t *testing.T) {
	t.Setenv("ARTEX_CHAT_UPLOAD_CONCURRENCY", "1")
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "workspace", "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: data}}
	if !s.acquireUploadSlot() {
		t.Fatal("could not reserve upload slot")
	}
	body := &countedUploadBody{}
	r := httptest.NewRequest(http.MethodPost, "/api/workspace/upload?path=workspace/target", body)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=fixture")
	w := httptest.NewRecorder()
	s.wsUpload(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429: %s", w.Code, w.Body.String())
	}
	if body.reads != 0 {
		t.Fatalf("multipart body read before admission: %d", body.reads)
	}
	<-s.uploadSlots

	retry := chatUploadRequest(t, "unused", nil)
	retry.URL.Path = "/api/workspace/upload"
	retry.URL.RawQuery = "path=workspace/target"
	w = httptest.NewRecorder()
	s.wsUpload(w, retry)
	if w.Code != http.StatusOK {
		t.Fatalf("retry status=%d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(filepath.Join(data, "workspace", "target", "sample.txt")); err != nil {
		t.Fatal(err)
	}
}

func TestUploadConcurrencyPrefersSharedSetting(t *testing.T) {
	t.Setenv("ARTEX_CHAT_UPLOAD_CONCURRENCY", "4")
	t.Setenv("ARTEX_UPLOAD_CONCURRENCY", "1")
	s := &Server{}
	if !s.acquireUploadSlot() {
		t.Fatal("first upload was refused")
	}
	if s.acquireUploadSlot() {
		t.Fatal("shared limit did not take precedence")
	}
	<-s.uploadSlots
}
