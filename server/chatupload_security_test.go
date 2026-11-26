package server

import (
	"bytes"
	"context"
	"errors"
	"mime/multipart"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestChatUploadExclusiveCreationUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	const count = 24
	names := make(chan string, count)
	errs := make(chan error, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			f, name, err := createUniqueChatFile(root, "note.txt")
			if err != nil {
				errs <- err
				return
			}
			if _, err := f.Write([]byte(name)); err != nil {
				errs <- err
			}
			if err := f.Close(); err != nil {
				errs <- err
			}
			names <- name
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	close(names)
	seen := make(map[string]bool)
	for name := range names {
		if seen[name] {
			t.Errorf("duplicate reserved name %q", name)
		}
		seen[name] = true
		data, err := root.ReadFile(name)
		if err != nil || string(data) != name {
			t.Errorf("file %q changed: %q, %v", name, data, err)
		}
	}
	if len(seen) != count {
		t.Fatalf("reserved %d names, want %d", len(seen), count)
	}
}

func TestChatUploadRootRejectsEscapingParent(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "uploads")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.OpenRoot("uploads"); err == nil {
		t.Fatal("opened a symlinked upload parent outside the root")
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
		t.Fatalf("outside sentinel changed: %q, %v", data, err)
	}
}

func TestChatUploadRootRejectsSiblingCampaignLink(t *testing.T) {
	data := t.TempDir()
	a := filepath.Join(data, "tasks", "a", "main")
	b := filepath.Join(data, "tasks", "b", "main")
	for _, dir := range []string{a, b} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("..", "..", "b", "main"), filepath.Join(a, "uploads")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root, err := os.OpenRoot(a)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := root.OpenRoot("uploads"); err == nil {
		t.Fatal("upload directory reached a sibling campaign")
	}
	entries, err := os.ReadDir(b)
	if err != nil || len(entries) != 0 {
		t.Fatalf("sibling campaign changed: %v entries, %v", len(entries), err)
	}
}

func testChatFileHeader(t *testing.T, data string) (*multipart.Form, *multipart.FileHeader) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	f, err := w.CreateFormFile("file", "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte(data)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	form, err := multipart.NewReader(&body, w.Boundary()).ReadForm(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = form.RemoveAll() })
	return form, form.File["file"][0]
}

func TestChatUploadCancelAndQuotaCleanIncompleteFiles(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, hdr := testChatFileHeader(t, "content")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := saveChatUpload(root, hdr, "cancelled.txt", ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled upload error = %v", err)
	}
	if _, err := root.Lstat("cancelled.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled upload left a file: %v", err)
	}
	hdr.Size = 1
	if _, err := saveChatUpload(root, hdr, "over-quota.txt", context.Background()); err == nil {
		t.Fatal("accepted content larger than its declared limit")
	}
	if _, err := root.Lstat("over-quota.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected upload left a file: %v", err)
	}
	hdr.Size = maxChatUpload + 1
	if _, err := saveChatUpload(root, hdr, "too-large.txt", context.Background()); err == nil {
		t.Fatal("accepted a file above the upload ceiling")
	}
}

func TestChatUploadRejectsMalformedName(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"", ".", "..", "../escape", "sub/file", `sub\file`} {
		if f, _, err := createUniqueChatFile(root, name); err == nil {
			_ = f.Close()
			t.Errorf("accepted malformed name %q", name)
		}
	}
}
