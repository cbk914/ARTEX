package server

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The path is validated while parent is a real directory. An attacker then
// replaces that directory with a link before the privileged open.
func TestWorkspaceReadParentSwapCannotEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(root, "run"), outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for path, body := range map[string]string{
		filepath.Join(root, "run", "note.txt"): "INSIDE",
		filepath.Join(outside, "note.txt"):     "OUTSIDE_SECRET",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("run/note.txt")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	if err := os.Rename(filepath.Join(root, "run"), filepath.Join(root, "run-old")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(root, "run"))
	f, err := openWorkspaceResolved(cp)
	if err == nil {
		defer f.Close()
		body, readErr := io.ReadAll(f)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(body) == "OUTSIDE_SECRET" {
			t.Fatal("privileged read escaped the workspace after parent swap")
		}
	}
	if body, err := os.ReadFile(filepath.Join(outside, "note.txt")); err != nil || string(body) != "OUTSIDE_SECRET" {
		t.Fatalf("outside sentinel changed: %q, %v", body, err)
	}
}

func TestWorkspaceWriteParentSwapCannotEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(root, "run"), outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	inside := filepath.Join(root, "run", "note.txt")
	sentinel := filepath.Join(outside, "note.txt")
	for path, body := range map[string]string{inside: "INSIDE", sentinel: "KEEP"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("run/note.txt")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	if err := os.Rename(filepath.Join(root, "run"), filepath.Join(root, "run-old")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(root, "run"))
	_ = writeWorkspaceResolved(context.Background(), cp, []byte("REPLACED"))
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "KEEP" {
		t.Fatalf("outside sentinel changed after parent swap: %q, %v", body, err)
	}
}

func TestWorkspaceWritePreservesExistingModeAndCreatesParent(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "note.txt")
	if err := os.WriteFile(existing, []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := os.Stat(existing)
	if err != nil {
		t.Fatal(err)
	}
	s := newTestWorkspaceServer(root)
	for _, tc := range []struct{ path, content string }{
		{"note.txt", "after"},
		{"new/sub/note.txt", "created"},
	} {
		w := doJSONReq(t, "POST", "/api/workspace/write", map[string]string{"path": tc.path, "content": tc.content}, s.wsWrite)
		if w.Code != 200 {
			t.Fatalf("write %q = %d: %s", tc.path, w.Code, w.Body.String())
		}
		body, err := os.ReadFile(filepath.Join(root, tc.path))
		if err != nil || string(body) != tc.content {
			t.Fatalf("written %q = %q, %v", tc.path, body, err)
		}
	}
	fi, err := os.Stat(existing)
	if err != nil || fi.Mode().Perm() != initial.Mode().Perm() {
		t.Fatalf("existing mode changed from %v to %v: %v", initial.Mode().Perm(), fi, err)
	}
}

func TestWorkspaceCancelledUploadPreservesExistingFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "note.txt")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("note.txt")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	_, hdr := testChatFileHeader(t, "replacement")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := saveUpload(ctx, hdr, cp); err == nil {
		t.Fatal("cancelled upload unexpectedly succeeded")
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "original" {
		t.Fatalf("cancelled upload damaged existing file: %q, %v", body, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "note.txt" {
		t.Fatalf("cancelled upload left temporary entries: %v, %v", entries, err)
	}
	if err := saveUpload(context.Background(), hdr, cp); err != nil {
		t.Fatalf("retry after cancellation failed: %v", err)
	}
	if body, err := os.ReadFile(path); err != nil || string(body) != "replacement" {
		t.Fatalf("retry did not replace file: %q, %v", body, err)
	}
}

func TestWorkspaceOverwriteDoesNotMutateOutsideHardlink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(root, "note.txt")); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("note.txt")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	if err := writeWorkspaceResolved(context.Background(), cp, []byte("inside")); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(outside); err != nil || string(body) != "outside" {
		t.Fatalf("outside hardlink target was mutated: %q, %v", body, err)
	}
	if body, err := os.ReadFile(filepath.Join(root, "note.txt")); err != nil || string(body) != "inside" {
		t.Fatalf("workspace file not replaced: %q, %v", body, err)
	}
}

func TestWorkspaceMkdirParentSwapCannotEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(root, "run"), outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("run/newdir")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	if err := os.Rename(filepath.Join(root, "run"), filepath.Join(root, "run-old")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(root, "run"))
	_ = mkdirWorkspaceResolved(cp)
	if _, err := os.Lstat(filepath.Join(outside, "newdir")); !os.IsNotExist(err) {
		t.Fatalf("created a directory outside workspace after parent swap: %v", err)
	}
}

func TestWorkspaceDeleteParentSwapCannotEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(root, "run", "victim"), filepath.Join(outside, "victim")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(outside, "victim", "keep.txt")
	if err := os.WriteFile(sentinel, []byte("KEEP"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("run/victim")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	if err := os.Rename(filepath.Join(root, "run"), filepath.Join(root, "run-old")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(root, "run"))
	_ = deleteWorkspaceResolved(cp)
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "KEEP" {
		t.Fatalf("outside sentinel deleted after parent swap: %q, %v", body, err)
	}
}

func TestWorkspaceUploadParentSwapCannotEscape(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(root, "run"), outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := filepath.Join(outside, "note.txt")
	if err := os.WriteFile(sentinel, []byte("KEEP"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("run/note.txt")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	if err := os.Rename(filepath.Join(root, "run"), filepath.Join(root, "run-old")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(root, "run"))
	_, hdr := testChatFileHeader(t, "REPLACED")
	_ = saveUpload(context.Background(), hdr, cp)
	if body, err := os.ReadFile(sentinel); err != nil || string(body) != "KEEP" {
		t.Fatalf("outside sentinel overwritten after parent swap: %q, %v", body, err)
	}
}

func TestWorkspaceDownloadRangeStillWorks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestWorkspaceServer(root)
	r := httptest.NewRequest("GET", "/api/workspace/download?path=note.txt", nil)
	r.Header.Set("Range", "bytes=1-3")
	w := httptest.NewRecorder()
	s.wsDownload(w, r)
	if w.Code != 206 || w.Body.String() != "bcd" {
		t.Fatalf("range download = %d %q, want 206 bcd", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Disposition"); got == "" {
		t.Fatal("download filename header missing")
	}
}

func TestWorkspaceListUsesOpenedDirectoryAfterParentSwap(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(root, "run"), outside} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "run", "inside.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestWorkspaceServer(root)
	cp, ok := s.wsResolveConfined("run")
	if !ok {
		t.Fatal("fixture path was not accepted")
	}
	dir, err := openWorkspaceResolved(cp)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := os.Rename(filepath.Join(root, "run"), filepath.Join(root, "run-old")); err != nil {
		t.Fatal(err)
	}
	mustSymlink(t, outside, filepath.Join(root, "run"))
	entries, err := dir.ReadDir(-1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "inside.txt" {
		t.Fatalf("directory listing followed swapped parent: %+v, %v", entries, err)
	}
	info, err := entries[0].Info()
	if err != nil || info.Size() != int64(len("inside")) {
		t.Fatalf("directory metadata followed swapped parent: %+v, %v", info, err)
	}
}
