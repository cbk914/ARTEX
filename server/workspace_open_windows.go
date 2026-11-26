//go:build windows

package server

import "os"

func openWorkspaceCandidate(root *os.Root, rel string) (*os.File, error) {
	return root.OpenFile(rel, os.O_RDONLY, 0)
}
