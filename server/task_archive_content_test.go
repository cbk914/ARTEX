package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type archiveMutatingWriter struct {
	output bytes.Buffer
	mutate func() error
}

func (w *archiveMutatingWriter) Write(p []byte) (int, error) {
	n, err := w.output.Write(p)
	if err == nil && w.mutate != nil {
		mutate := w.mutate
		w.mutate = nil
		if mutationErr := mutate(); mutationErr != nil {
			return n, mutationErr
		}
	}
	return n, err
}

func TestCopyArchiveSourceRejectsSameSizeSameTimeRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	selected, err := input.Stat()
	if err != nil {
		t.Fatal(err)
	}
	output := &archiveMutatingWriter{mutate: func() error {
		if _, err := input.WriteAt([]byte("modified"), 0); err != nil {
			return err
		}
		return os.Chtimes(path, selected.ModTime(), selected.ModTime())
	}}
	if err := copyArchiveSource(context.Background(), output, input, selected, "source"); err == nil || !strings.Contains(err.Error(), "archive source changed") {
		t.Fatalf("copy error = %v, want source change", err)
	}
	if output.output.String() != "original" {
		t.Fatalf("first pass copied %q", output.output.String())
	}
}
