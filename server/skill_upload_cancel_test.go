package server

import (
	"archive/zip"
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCancelledSkillUploadDoesNotInstallOrLeaveTemporaryFiles(t *testing.T) {
	data := buildZip(t, zipFile{name: "SKILL.md", body: "---\nname: synthetic-skill\n---\ncontent", method: zip.Deflate})
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "synthetic-skill.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	req := httptest.NewRequest(http.MethodPost, "/api/skills/upload", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", form.FormDataContentType())
	// Make parsing complete before cancellation to exercise installation admission.
	if err := req.ParseMultipartForm(32 << 20); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	(&Server{skillDir: dir}).fsUploadSkill(rec, req)
	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("cancelled upload status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "synthetic-skill")); !os.IsNotExist(err) {
		t.Fatalf("cancelled upload installed skill: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled upload left files: %v, %v", entries, err)
	}
	// A later request retains the normal installation path.
	rec, _ = uploadZip(t, dir, "synthetic-skill.zip", data)
	if rec.Code != http.StatusCreated {
		t.Fatalf("retry status=%d body=%s", rec.Code, rec.Body.String())
	}
}
