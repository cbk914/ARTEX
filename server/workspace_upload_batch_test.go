package server

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceUploadRejectsInvalidBatchBeforeReplacingExistingFile(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "workspace", "target")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(dir, "existing.txt")
	if err := os.WriteFile(existing, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	for _, file := range []struct{ name, content string }{{"existing.txt", "replacement"}, {"..", "invalid"}} {
		writer, err := form.CreateFormFile("file", file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(file.content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/workspace/upload?path=workspace/target", &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	response := httptest.NewRecorder()
	server := &Server{m: &Manager{dir: data}}
	server.wsUpload(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid batch status=%d, body=%s", response.Code, response.Body.String())
	}
	if got, err := os.ReadFile(existing); err != nil || string(got) != "original" {
		t.Fatalf("invalid batch changed existing file: %q, %v", got, err)
	}
}

func TestWorkspaceUploadStripsBrowserPathFromFilename(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "workspace", "target")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	writer, err := form.CreateFormFile("file", `C:\fakepath\report.txt`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("report")); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/workspace/upload?path=workspace/target", &body)
	request.Header.Set("Content-Type", form.FormDataContentType())
	response := httptest.NewRecorder()
	server := &Server{m: &Manager{dir: data}}
	server.wsUpload(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("browser filename status=%d, body=%s", response.Code, response.Body.String())
	}
	if got, err := os.ReadFile(filepath.Join(dir, "report.txt")); err != nil || string(got) != "report" {
		t.Fatalf("browser filename was not reduced to its basename: %q, %v", got, err)
	}
}
