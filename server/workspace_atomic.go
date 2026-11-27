package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// replaceWorkspaceResolved writes a complete replacement beside the target and
// publishes it with a descriptor-relative rename. A failed or cancelled write
// leaves the previous file intact and removes only its own temporary entry.
func replaceWorkspaceResolved(ctx context.Context, cp confinedPath, write func(io.Writer) error) error {
	root, rel, err := openWorkspaceRoot(cp)
	if err != nil {
		return err
	}
	defer root.Close()
	if rel == "." {
		return errPathEscape
	}
	parent := filepath.Dir(rel)
	if err := root.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	dir, err := root.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	name := filepath.Base(rel)
	old, err := dir.Lstat(name)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !old.Mode().IsRegular() {
		return fmt.Errorf("target is not a regular file")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tempName := ".artex-write-" + hex.EncodeToString(nonce[:])
	f, err := dir.OpenFile(tempName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer dir.Remove(tempName)
	defer f.Close()
	if err := write(f); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	perm := os.FileMode(0o644)
	if old != nil {
		perm = old.Mode().Perm()
		if err := preserveWorkspaceOwner(f, old); err != nil {
			return err
		}
	}
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return dir.Rename(tempName, name)
}
