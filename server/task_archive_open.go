package server

import (
	"errors"
	"os"
	"path/filepath"
)

// openLocalTaskArchivePackage opens a stored package beneath the private
// archive directory without following a substituted directory or file link.
// The caller owns the returned descriptor and must use it through verification
// and consumption rather than reopening the path.
func openLocalTaskArchivePackage(dataDir, candidate string) (*os.File, error) {
	if err := validateArchivePath(dataDir, candidate); err != nil {
		return nil, err
	}
	name, err := filepath.Rel(taskArchiveRoot(dataDir), candidate)
	if err != nil || name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("archive package must be a direct child of the archive directory")
	}
	dataRoot, err := os.OpenRoot(dataDir)
	if err != nil {
		return nil, err
	}
	defer dataRoot.Close()
	archives, err := openArchiveDirectory(dataRoot, "archives")
	if err != nil {
		return nil, err
	}
	defer archives.Close()
	tasks, err := openArchiveDirectory(archives, "tasks")
	if err != nil {
		return nil, err
	}
	defer tasks.Close()
	selected, err := tasks.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !selected.Mode().IsRegular() {
		return nil, errors.New("archive package is not a regular file")
	}
	file, err := tasks.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(selected, opened) {
		file.Close()
		return nil, errors.New("archive package changed during open")
	}
	return file, nil
}

func openArchiveDirectory(parent *os.Root, name string) (*os.Root, error) {
	selected, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !selected.IsDir() {
		return nil, errors.New("archive directory is not a directory")
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	entry, err := child.Open(".")
	if err != nil {
		child.Close()
		return nil, err
	}
	opened, statErr := entry.Stat()
	closeErr := entry.Close()
	if err := errors.Join(statErr, closeErr); err != nil || !os.SameFile(selected, opened) {
		child.Close()
		return nil, errors.New("archive directory changed during open")
	}
	return child, nil
}
