package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type pausedUploadBody struct {
	reader  io.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func TestChatUploadRejectsBatchWithInvalidLaterFilename(t *testing.T) {
	dataDir := t.TempDir()
	s := &Server{m: &Manager{dir: dataDir}}
	var payload bytes.Buffer
	form := multipart.NewWriter(&payload)
	for _, name := range []string{"valid.txt", ".."} {
		file, err := form.CreateFormFile("file", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte("synthetic")); err != nil {
			t.Fatal(err)
		}
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/chat/upload?scope=staging&id=batch", &payload)
	req.Header.Set("Content-Type", form.FormDataContentType())
	result := httptest.NewRecorder()
	s.chatUpload(result, req)
	if result.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "drafts", "batch", "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected batch left %d upload entries", len(entries))
	}
}

func (b *pausedUploadBody) Read(p []byte) (int, error) {
	b.once.Do(func() {
		close(b.started)
		<-b.release
	})
	return b.reader.Read(p)
}

func (*pausedUploadBody) Close() error { return nil }

func chatUploadRequest(t *testing.T, id string, body io.Reader) *http.Request {
	t.Helper()
	var payload bytes.Buffer
	form := multipart.NewWriter(&payload)
	file, err := form.CreateFormFile("file", "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("sample")); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	if body == nil {
		body = bytes.NewReader(payload.Bytes())
	}
	r := httptest.NewRequest(http.MethodPost, "/api/chat/upload?scope=staging&id="+id, body)
	r.Header.Set("Content-Type", form.FormDataContentType())
	return r
}

func TestChatUploadConcurrencyRefusesBeforeParsing(t *testing.T) {
	t.Setenv("ARTEX_CHAT_UPLOAD_CONCURRENCY", "1")
	s := &Server{m: &Manager{dir: t.TempDir()}}
	var payload bytes.Buffer
	form := multipart.NewWriter(&payload)
	file, err := form.CreateFormFile("file", "sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("sample")); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	paused := &pausedUploadBody{reader: bytes.NewReader(payload.Bytes()), started: make(chan struct{}), release: make(chan struct{})}
	first := httptest.NewRequest(http.MethodPost, "/api/chat/upload?scope=staging&id=first", paused)
	first.Header.Set("Content-Type", form.FormDataContentType())
	firstResult := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.chatUpload(firstResult, first)
	}()
	select {
	case <-paused.started:
	case <-time.After(5 * time.Second):
		close(paused.release)
		t.Fatal("first upload did not reach body parsing")
	}
	secondResult := httptest.NewRecorder()
	s.chatUpload(secondResult, chatUploadRequest(t, "second", nil))
	close(paused.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("first upload did not finish")
	}
	if firstResult.Code != http.StatusOK {
		t.Fatalf("first upload status=%d body=%s", firstResult.Code, firstResult.Body.String())
	}
	if secondResult.Code != http.StatusTooManyRequests {
		t.Fatalf("parallel upload status=%d want 429 body=%s", secondResult.Code, secondResult.Body.String())
	}
	thirdResult := httptest.NewRecorder()
	s.chatUpload(thirdResult, chatUploadRequest(t, "third", nil))
	if thirdResult.Code != http.StatusOK {
		t.Fatalf("upload after slot release status=%d body=%s", thirdResult.Code, thirdResult.Body.String())
	}
}
