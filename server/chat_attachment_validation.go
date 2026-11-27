package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
)

const maxChatAttachmentsPerMessage = 1024

// validateChatAttachments resolves client-supplied metadata to regular files in
// this chat's upload directory. The returned metadata is server-derived; a
// client cannot make the agent read an arbitrary path by forging an attachment.
// The run-directory file remains mutable until protected artifact delivery is
// implemented, so this is an admission check rather than an immutability claim.
func validateChatAttachments(ctx context.Context, baseDir string, attachments []chatAttachment) ([]chatAttachment, error) {
	if len(attachments) == 0 {
		return nil, nil
	}
	if len(attachments) > maxChatAttachmentsPerMessage {
		return nil, errors.New("too many attachments")
	}
	baseRoot, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, err
	}
	defer baseRoot.Close()
	selectedDir, err := baseRoot.Lstat("uploads")
	if err != nil || !selectedDir.IsDir() {
		return nil, errors.New("upload directory is unavailable or unsafe")
	}
	uploadRoot, err := baseRoot.OpenRoot("uploads")
	if err != nil {
		return nil, err
	}
	defer uploadRoot.Close()
	openedDir, err := uploadRoot.Open(".")
	if err != nil {
		return nil, err
	}
	actualDir, statErr := openedDir.Stat()
	closeErr := openedDir.Close()
	if err := errors.Join(statErr, closeErr); err != nil || !os.SameFile(selectedDir, actualDir) {
		return nil, errors.New("upload directory changed at open")
	}
	canonical := make([]chatAttachment, 0, len(attachments))
	var total int64
	for _, attachment := range attachments {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := strings.TrimPrefix(attachment.Path, "uploads/")
		if !strings.HasPrefix(attachment.Path, "uploads/") || name == "" || name == "." || name == ".." ||
			strings.ContainsAny(name, `/\`) || attachment.Name != name {
			return nil, errors.New("invalid attachment path")
		}
		selected, err := uploadRoot.Lstat(name)
		if err != nil {
			return nil, err
		}
		if !selected.Mode().IsRegular() || selected.Size() < 0 || selected.Size() > maxChatUpload-total || attachment.Size != selected.Size() {
			return nil, errors.New("attachment is unsafe or exceeds its limit")
		}
		file, err := uploadRoot.Open(name)
		if err != nil {
			return nil, err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(selected, opened) || opened.Size() != selected.Size() {
			file.Close()
			return nil, errors.New("attachment changed at open")
		}
		hasher := sha256.New()
		n, readErr := io.Copy(hasher, archiveContextReader{ctx: ctx, r: io.LimitReader(file, selected.Size()+1)})
		final, finalErr := file.Stat()
		closeErr := file.Close()
		if err := errors.Join(readErr, finalErr, closeErr, ctx.Err()); err != nil {
			return nil, err
		}
		if n != selected.Size() || !os.SameFile(selected, final) || final.Size() != selected.Size() || !final.ModTime().Equal(selected.ModTime()) {
			return nil, errors.New("attachment changed during validation")
		}
		digest := hex.EncodeToString(hasher.Sum(nil))
		if attachment.SHA256 != "" && attachment.SHA256 != digest {
			return nil, errors.New("attachment content changed since upload")
		}
		canonical = append(canonical, chatAttachment{Name: name, Path: "uploads/" + name, Size: selected.Size(), SHA256: digest})
		total += selected.Size()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return canonical, nil
}
