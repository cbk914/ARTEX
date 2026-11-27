//go:build windows

package server

import "os"

func openWorkspaceWriteCandidate(root *os.Root, rel string) (*os.File, error) {
	return root.OpenFile(rel, os.O_WRONLY|os.O_CREATE, 0o644)
}
