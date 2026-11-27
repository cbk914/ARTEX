package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type uploadReadCounter struct{ reads int }

func (r *uploadReadCounter) Read(p []byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func TestSkillUploadSharesMultipartAdmissionPool(t *testing.T) {
	t.Setenv("ARTEX_UPLOAD_CONCURRENCY", "1")
	s := &Server{skillDir: t.TempDir()}
	if !s.acquireUploadSlot() {
		t.Fatal("could not reserve the only upload slot")
	}
	reader := &uploadReadCounter{}
	req := httptest.NewRequest(http.MethodPost, "/api/skills/upload", reader)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
	rec := httptest.NewRecorder()
	s.fsUploadSkill(rec, req)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "1" || reader.reads != 0 {
		t.Fatalf("response %d, retry %q, body reads %d", rec.Code, rec.Header().Get("Retry-After"), reader.reads)
	}
	<-s.uploadSlots
	req = httptest.NewRequest(http.MethodPost, "/api/skills/upload", strings.NewReader("invalid multipart"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=test")
	rec = httptest.NewRecorder()
	s.fsUploadSkill(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("after release: response %d, want 400 for malformed body", rec.Code)
	}
}
