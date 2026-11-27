//go:build unix

package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	pgdb "github.com/Autumn-27/artex/db"
)

// A named pipe or a socket must make the archive fail without losing the hot
// workspace. Silently skipping them would publish an incomplete snapshot.
func TestTaskArchiveRejectsSpecialFiles(t *testing.T) {
	// A short root: a socket path is limited to about 100 bytes.
	dataDir, err := os.MkdirTemp("/tmp", "arch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dataDir) })
	taskID := "42"
	runDir := filepath.Join(dataDir, "tasks", taskID, "main")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	evidence := filepath.Join(runDir, "evidence.txt")
	if err := os.WriteFile(evidence, []byte("task evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(runDir, "backpipe"), 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	ln, err := net.Listen("unix", filepath.Join(runDir, "ctl.sock"))
	if err != nil {
		t.Skipf("unix socket: %v", err)
	}
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	ln.Close()

	stage, err := stageTaskArchiveFiles(dataDir, 1, taskID, 7)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := taskArchivePath(dataDir, 1, taskID)
	snapshot := &pgdb.TaskArchiveSnapshot{FormatVersion: pgdb.TaskArchiveFormatVersion, TaskID: 42, ExplorationID: 7}
	_, _, _, err = writeTaskArchivePackage(archivePath, stage.payload, snapshot)
	if err == nil || !strings.Contains(err.Error(), "unsupported special file") {
		t.Fatalf("archive error = %v, want unsupported special file", err)
	}
	if err := stage.rollback(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{archivePath, archivePath + ".partial"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("rejected archive left %s: %v", path, err)
		}
	}
	if got, err := os.ReadFile(evidence); err != nil || string(got) != "task evidence" {
		t.Fatalf("hot workspace %s = %q, %v", evidence, got, err)
	}
	for _, name := range []string{"backpipe", "ctl.sock"} {
		if _, err := os.Lstat(filepath.Join(runDir, name)); err != nil {
			t.Fatalf("hot special file %s: %v", name, err)
		}
	}
}
