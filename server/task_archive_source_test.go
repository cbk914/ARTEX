package server

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestArchiveSourceRejectsChangedEntry(t *testing.T) {
	payload := t.TempDir()
	selectedPath := filepath.Join(payload, "selected.txt")
	otherPath := filepath.Join(payload, "other.txt")
	if err := os.WriteFile(selectedPath, []byte("selected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(otherPath, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err := os.Lstat(selectedPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Remove(selectedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(otherPath, selectedPath); err != nil {
		t.Fatal(err)
	}
	if file, err := openArchiveSource(root, "selected.txt", selected); err == nil {
		file.Close()
		t.Fatal("archive accepted a different file at the selected path")
	}
}

func TestArchiveSourceRejectsParentSwapOutsideStage(t *testing.T) {
	base := t.TempDir()
	payload := filepath.Join(base, "payload")
	parent := filepath.Join(payload, "files")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{parent, outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	selectedPath := filepath.Join(parent, "note.txt")
	if err := os.WriteFile(selectedPath, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "note.txt"), []byte("OUTSIDE_SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected, err := os.Lstat(selectedPath)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(parent, parent+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, parent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if file, err := openArchiveSource(root, "files/note.txt", selected); err == nil {
		body, _ := io.ReadAll(file)
		file.Close()
		t.Fatalf("archive opened a swapped parent, content=%q", body)
	}
	if body, err := os.ReadFile(filepath.Join(outside, "note.txt")); err != nil || string(body) != "OUTSIDE_SECRET" {
		t.Fatalf("outside sentinel changed: %q, %v", body, err)
	}
}

func TestArchiveRootRemainsBoundAfterPathSwap(t *testing.T) {
	base := t.TempDir()
	payload := filepath.Join(base, "payload")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{payload, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(payload, "note.txt"), []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "note.txt"), []byte("OUTSIDE_SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(payload, payload+"-old"); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		// Windows holds the root handle open and refuses this rename. That is
		// another valid way to keep the selected root stable.
		t.Logf("root path swap was refused while the descriptor was open: %v", err)
	} else if err := os.Symlink(outside, payload); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	file, err := root.FS().Open("note.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if body, err := io.ReadAll(file); err != nil || string(body) != "inside" {
		t.Fatalf("root followed the swapped path: %q, %v", body, err)
	}
}
