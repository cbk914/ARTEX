//go:build !windows

package server

import (
	"net/http/httptest"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWorkspaceReadRejectsFIFOWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	s := newTestWorkspaceServer(root)
	w := httptest.NewRecorder()
	s.wsRead(w, httptest.NewRequest("GET", "/api/workspace/read?path=pipe", nil))
	if w.Code != 400 {
		t.Fatalf("FIFO read returned %d, want 400: %s", w.Code, w.Body.String())
	}
}
