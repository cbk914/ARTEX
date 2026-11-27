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
	root, err := os.OpenRoot(realRoot)
	if err != nil {
		return nil, "", err
	}
	return root, rel, nil
}
