//go:build windows

package server

import "os"

// Windows ACL verification needs an explicit implementation before native
// Windows staging is supported. Docker Desktop uses the Linux implementation.
func evidenceOwnedByServer(os.FileInfo) bool { return false }
