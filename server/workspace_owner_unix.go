//go:build !windows

package server

import (
	"fmt"
	"os"
	"syscall"
)

func preserveWorkspaceOwner(f *os.File, old os.FileInfo) error {
	oldStat, ok := old.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("workspace file owner is unavailable")
	}
	current, err := f.Stat()
	if err != nil {
		return err
	}
	newStat, ok := current.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("workspace temporary owner is unavailable")
	}
	if oldStat.Uid == newStat.Uid && oldStat.Gid == newStat.Gid {
		return nil
	}
	return f.Chown(int(oldStat.Uid), int(oldStat.Gid))
}
