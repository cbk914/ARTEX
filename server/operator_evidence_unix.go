//go:build unix

package server

import (
	"os"
	"syscall"
)

func evidenceOwnedByServer(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid())
}
