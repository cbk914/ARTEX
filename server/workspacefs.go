package server

import (
	"os"
	"path/filepath"
	"strings"
)

// openWorkspaceRoot turns the canonical path result into a descriptor-rooted
// relative path. Callers must keep the Root for the entire operation; the
// earlier path validation alone is not an authorization boundary.
func openWorkspaceRoot(cp confinedPath) (*os.Root, string, error) {
	return openWorkspaceRootPath(cp.realRoot, cp.realPath)
}

func openWorkspaceRootPath(realRoot, target string) (*os.Root, string, error) {
	rel, err := filepath.Rel(realRoot, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, "", errPathEscape
	}
	if rel == "." {
		root, err := os.OpenRoot(realRoot)
		return root, rel, err
	}
	parts := strings.SplitN(rel, string(filepath.Separator), 2)
	if !workspacePathAllowed(realRoot, filepath.Join(realRoot, parts[0])) {
		return nil, "", errPathEscape
	}
	namespace := filepath.Join(realRoot, parts[0])
	before, err := os.Lstat(namespace)
	if err != nil {
		return nil, "", err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, "", errPathEscape
	}
	root, err := os.OpenRoot(namespace)
	if err != nil {
		return nil, "", err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		root.Close()
		return nil, "", errPathEscape
	}
	if len(parts) == 1 {
		return root, ".", nil
	}
	return root, parts[1], nil
}
