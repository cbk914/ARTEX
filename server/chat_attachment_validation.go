package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/sandboxbroker"
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

// transferTaskChatAttachments reopens the server-validated files through an
// os.Root and sends their bytes to the campaign's read-only upload volume.
// The broker independently checks length and digest before publication.
func (c *taskSandboxController) transferTaskChatAttachments(ctx context.Context, info agent.RunInfo, baseDir string, attachments []chatAttachment) error {
	if len(attachments) == 0 {
		return nil
	}
	for _, attachment := range attachments {
		if !sandboxbroker.ValidCampaignUploadName(attachment.Name) || attachment.Path != "uploads/"+attachment.Name || attachment.Size < 0 || attachment.Size > maxChatUpload || len(attachment.SHA256) != 64 {
			return errors.New("attachment is incompatible with campaign upload storage")
		}
	}
	baseRoot, err := os.OpenRoot(baseDir)
	if err != nil {
		return err
	}
	defer baseRoot.Close()
	selectedDir, err := baseRoot.Lstat("uploads")
	if err != nil || !selectedDir.IsDir() {
		return errors.New("upload directory is unavailable or unsafe")
	}
	uploadRoot, err := baseRoot.OpenRoot("uploads")
	if err != nil {
		return err
	}
	defer uploadRoot.Close()
	openedDir, err := uploadRoot.Open(".")
	if err != nil {
		return err
	}
	actualDir, statErr := openedDir.Stat()
	closeErr := openedDir.Close()
	if err := errors.Join(statErr, closeErr); err != nil || !os.SameFile(selectedDir, actualDir) {
		return errors.New("upload directory changed at open")
	}
	for _, attachment := range attachments {
		if err := ctx.Err(); err != nil {
			return err
		}
		selected, err := uploadRoot.Lstat(attachment.Name)
		if err != nil || !selected.Mode().IsRegular() || selected.Size() != attachment.Size {
			return errors.New("attachment changed before transfer")
		}
		file, err := uploadRoot.Open(attachment.Name)
		if err != nil {
			return err
		}
		opened, statErr := file.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(selected, opened) || opened.Size() != attachment.Size {
			file.Close()
			return errors.New("attachment changed at transfer open")
		}
		transferErr := c.UploadAttachment(ctx, info, attachment.Name, file, attachment.Size, attachment.SHA256)
		final, finalErr := file.Stat()
		closeErr := file.Close()
		if err := errors.Join(transferErr, finalErr, closeErr); err != nil {
			return err
		}
		if !os.SameFile(selected, final) || final.Size() != selected.Size() || !final.ModTime().Equal(selected.ModTime()) {
			return errors.New("attachment changed during transfer")
		}
	}
	return ctx.Err()
}
