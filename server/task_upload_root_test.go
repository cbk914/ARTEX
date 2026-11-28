package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenTaskRunRootRejectsLinkedAncestors(t *testing.T) {
	data := t.TempDir()
	tasks := filepath.Join(data, "tasks")
	private := filepath.Join(data, "private")
	for _, dir := range []string{tasks, private, filepath.Join(tasks, "7", "main")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := openTaskRunRoot(data, 7)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if err := os.Symlink(private, filepath.Join(tasks, "8")); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if root, err := openTaskRunRoot(data, 8); err == nil {
		root.Close()
		t.Fatal("accepted a linked task directory")
	}
	linkedMain := filepath.Join(tasks, "9")
	if err := os.Mkdir(linkedMain, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, filepath.Join(linkedMain, "main")); err != nil {
		t.Fatal(err)
	}
	if root, err := openTaskRunRoot(data, 9); err == nil {
		root.Close()
		t.Fatal("accepted a linked main directory")
	}
}
