//go:build !windows

package server

import (
	"os"
	"syscall"
)

// Open without truncation so a substituted FIFO or device can be rejected by
// f.Stat before any write. The final component must not be a new symlink.
func openWorkspaceWriteCandidate(root *os.Root, rel string) (*os.File, error) {
	return root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0o644)
}
