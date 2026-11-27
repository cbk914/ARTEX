//go:build unix

package server

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAskOperatorImageRejectsFIFOWithoutBlocking(t *testing.T) {
	_, taskDir := askOperatorRunDirs(t)
	runDir := filepath.Join(taskDir, "i3")
	path := filepath.Join(runDir, "pipe.png")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		f, err := openAskOperatorImage(runDir, path, st)
		if f != nil {
			f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("opened FIFO as an image")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening substituted FIFO blocked")
	}
}
