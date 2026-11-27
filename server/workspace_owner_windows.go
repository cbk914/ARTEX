//go:build windows

package server

import "os"

// Windows creates the replacement under the same parent directory, inheriting
// that directory's ACL. Preserving a file-specific ACL needs a separate review.
func preserveWorkspaceOwner(_ *os.File, _ os.FileInfo) error { return nil }
