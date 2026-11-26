//go:build !windows

package server

import (
	"os"
	"syscall"
)

// Do not block on a FIFO substituted for a regular file, and do not follow a
// final-component link installed after path validation.
func openWorkspaceCandidate(root *os.Root, rel string) (*os.File, error) {
	return root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
