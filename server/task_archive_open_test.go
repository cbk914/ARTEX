package server

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLocalTaskArchivePackageConfinesSource(t *testing.T) {
	data := t.TempDir()
	root := taskArchiveRoot(data)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	packagePath := taskArchivePath(data, 2, "1")
	if err := os.WriteFile(packagePath, []byte("original package"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := openLocalTaskArchivePackage(data, packagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// Consumption stays on the opened inode even if the path is replaced.
	if err := os.Rename(packagePath, packagePath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(file)
	if err != nil || string(got) != "original package" {
		t.Fatalf("opened source changed: %q, %v", got, err)
	}
	if _, err := openLocalTaskArchivePackage(data, filepath.Join(root, "sub", "other.tar.zst")); err == nil {
		t.Fatal("accepted a nested archive path")
	}
}

func TestOpenLocalTaskArchivePackageRejectsLinks(t *testing.T) {
	data := t.TempDir()
	root := taskArchiveRoot(data)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.tar.zst")
	if err := os.WriteFile(outside, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	packagePath := taskArchivePath(data, 2, "1")
	if err := os.Symlink(outside, packagePath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := openLocalTaskArchivePackage(data, packagePath); err == nil {
		t.Fatal("accepted linked archive package")
	}
	if err := os.Remove(packagePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), root); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	if _, err := openLocalTaskArchivePackage(data, packagePath); err == nil {
		t.Fatal("accepted linked archive directory")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "sentinel" {
		t.Fatalf("outside sentinel changed: %q, %v", got, err)
	}
}
