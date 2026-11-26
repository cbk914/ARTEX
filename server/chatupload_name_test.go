package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUniqueUploadPathSuffixesCollisions(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "note-1.txt"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, got, err := createUniqueChatFile(root, "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if got != "note-2.txt" {
		t.Fatalf("got %s", got)
	}
}

func TestUniqueUploadPathStopsOnUnstorableName(t *testing.T) {
	dir := t.TempDir()
	name := strings.Repeat("a", 300) + ".txt"
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, _, err := createUniqueChatFile(root, name); err == nil {
		t.Fatal("an overlong file name must not be searched forever")
	}
}

// Two uploads can select names before either starts writing. A name selection
// must reserve the destination so the second upload cannot truncate the first.
func TestUniqueUploadPathReservesConcurrentName(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f1, first, err := createUniqueChatFile(root, "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f1.Close()
	f2, second, err := createUniqueChatFile(root, "note.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	if first == second {
		t.Fatalf("two uploads selected the same destination %q", first)
	}
}
