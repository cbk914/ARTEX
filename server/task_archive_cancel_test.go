package server

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
)

type cancelAfterRead struct {
	cancel context.CancelFunc
	read   bool
}

func (r *cancelAfterRead) Read(p []byte) (int, error) {
	if r.read {
		return 0, io.EOF
	}
	r.read = true
	r.cancel()
	p[0] = 'x'
	return 1, nil
}

func TestArchiveContextReaderStopsBetweenChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &cancelAfterRead{cancel: cancel}
	buffer := make([]byte, 1)
	reader := archiveContextReader{ctx: ctx, r: source}
	if n, err := reader.Read(buffer); n != 1 || err != nil {
		t.Fatalf("first read = %d, %v", n, err)
	}
	if n, err := reader.Read(buffer); n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("read after cancellation = %d, %v", n, err)
	}
}

func TestTaskArchivePackageCancelBeforePublish(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	if err := os.Mkdir(payload, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "package.tar.zst")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot := &pgdb.TaskArchiveSnapshot{FormatVersion: pgdb.TaskArchiveFormatVersion, TaskID: 42}
	if _, _, _, err := writeTaskArchivePackageContext(ctx, path, payload, snapshot); !errors.Is(err, context.Canceled) {
		t.Fatalf("package error = %v, want cancellation", err)
	}
	for _, target := range []string{path, path + ".partial", filepath.Join(payload, "manifest.json")} {
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("cancelled package left %s: %v", target, err)
		}
	}
}

func TestTaskArchiveExtractCancelBeforeInstall(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(root, "restore")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := extractTaskArchivePackageContext(ctx, filepath.Join(root, "unused.tar.zst"), "", destination); !errors.Is(err, context.Canceled) {
		t.Fatalf("extract error = %v, want cancellation", err)
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("cancelled extraction created destination: %v", err)
	}
}
