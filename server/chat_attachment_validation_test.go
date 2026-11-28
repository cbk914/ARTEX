package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestValidateChatAttachmentsCanonicalizesMetadata(t *testing.T) {
	base := t.TempDir()
	uploads := filepath.Join(base, "uploads")
	if err := os.Mkdir(uploads, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("synthetic attachment\n")
	if err := os.WriteFile(filepath.Join(uploads, "report.txt"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	got, err := validateChatAttachments(context.Background(), base, []chatAttachment{{
		Name: "report.txt", Path: "uploads/report.txt", Size: int64(len(data)),
		SHA256: digest, Abs: "/outside/secret", URL: "https://example.invalid/secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "report.txt" || got[0].Path != "uploads/report.txt" ||
		got[0].Size != int64(len(data)) || got[0].SHA256 != digest || got[0].Abs != "" || got[0].URL != "" {
		t.Fatalf("unexpected canonical metadata: %+v", got)
	}
	// Older clients may omit the digest. The server still derives it for the
	// persisted activity and rejects a digest that no longer matches.
	legacy := []chatAttachment{{Name: "report.txt", Path: "uploads/report.txt", Size: int64(len(data))}}
	got, err = validateChatAttachments(context.Background(), base, legacy)
	if err != nil || len(got) != 1 || got[0].SHA256 != digest {
		t.Fatalf("legacy attachment: got %+v, err %v", got, err)
	}
	legacy[0].SHA256 = strings.Repeat("0", 64)
	if _, err := validateChatAttachments(context.Background(), base, legacy); err == nil {
		t.Fatal("changed content accepted")
	}
}

func TestTaskChatAttachmentTransferUsesTaskHandle(t *testing.T) {
	c, _, backend, _ := newSandboxTestController(t)
	base := t.TempDir()
	uploads := filepath.Join(base, "uploads")
	if err := os.Mkdir(uploads, 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("synthetic attachment")
	name := "análisis.txt"
	if err := os.WriteFile(filepath.Join(uploads, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	attachments, err := validateChatAttachments(ctx, base, []chatAttachment{{Name: name, Path: "uploads/" + name, Size: int64(len(data))}})
	if err != nil {
		t.Fatal(err)
	}
	info := agent.RunInfo{TaskID: 7, ExplorationID: 70, Interactive: true}
	if err := c.transferTaskChatAttachments(ctx, info, base, attachments); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.uploaded) != 1 || backend.uploaded[0] != "handle-7:"+name+":"+attachments[0].SHA256 || string(backend.uploadBytes) != string(data) {
		t.Fatalf("attachment did not reach the task handle: %+v", backend.uploaded)
	}
}

func TestTaskChatAttachmentManifestUsesSandboxPath(t *testing.T) {
	message := composeAgentMessage("inspect", []chatAttachment{{Name: "report.txt", Path: "uploads/report.txt", Size: 4}}, "/campaign/main")
	if !strings.Contains(message, "/campaign/main/uploads/report.txt") {
		t.Fatalf("sandbox attachment path missing: %q", message)
	}
}

func TestTaskChatAttachmentTransferRejectsChangedAndUnsupportedFiles(t *testing.T) {
	c, _, backend, _ := newSandboxTestController(t)
	base := t.TempDir()
	uploads := filepath.Join(base, "uploads")
	if err := os.Mkdir(uploads, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "report.txt"
	path := filepath.Join(uploads, name)
	if err := os.WriteFile(path, []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	attachments, err := validateChatAttachments(ctx, base, []chatAttachment{{Name: name, Path: "uploads/" + name, Size: 4}})
	if err != nil {
		t.Fatal(err)
	}
	info := agent.RunInfo{TaskID: 7, ExplorationID: 70, Interactive: true}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.transferTaskChatAttachments(ctx, info, base, attachments); err == nil {
		t.Fatal("changed attachment transferred")
	}
	attachments[0].Name = "bad\nname"
	attachments[0].Path = "uploads/bad\nname"
	if err := c.transferTaskChatAttachments(ctx, info, base, attachments); err == nil {
		t.Fatal("unsupported attachment name transferred")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.uploaded) != 0 {
		t.Fatal("rejected attachment reached the broker")
	}
}

func TestSaveChatUploadReturnsContentDigest(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, header := testChatFileHeader(t, "synthetic content")
	name, digest, err := saveChatUploadWithDigest(root, header, "report.txt", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if name != "report.txt" || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("name %q or digest %q does not match stored content", name, digest)
	}
}

func TestValidateChatAttachmentsRejectsForgedPathsAndMetadata(t *testing.T) {
	base := t.TempDir()
	uploads := filepath.Join(base, "uploads")
	if err := os.Mkdir(uploads, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(uploads, "ok.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]chatAttachment{
		"traversal":  {Name: "outside.txt", Path: "uploads/../outside.txt", Size: 9},
		"absolute":   {Name: "outside.txt", Path: outside, Size: 9},
		"wrong name": {Name: "outside.txt", Path: "uploads/ok.txt", Size: 2},
		"wrong size": {Name: "ok.txt", Path: "uploads/ok.txt", Size: 3},
		"backslash":  {Name: `..\outside.txt`, Path: `uploads/..\outside.txt`, Size: 9},
		"nested":     {Name: "nested/ok.txt", Path: "uploads/nested/ok.txt", Size: 2},
		"missing":    {Name: "missing.txt", Path: "uploads/missing.txt", Size: 0},
	}
	for name, attachment := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := validateChatAttachments(context.Background(), base, []chatAttachment{attachment}); err == nil {
				t.Fatal("forged attachment accepted")
			}
		})
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "untouched" {
		t.Fatalf("outside file changed: %q, %v", data, err)
	}
}

func TestValidateChatAttachmentsRejectsLinksAndCancellation(t *testing.T) {
	base := t.TempDir()
	uploads := filepath.Join(base, "uploads")
	if err := os.Mkdir(uploads, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(uploads, "link.txt")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	attachment := chatAttachment{Name: "link.txt", Path: "uploads/link.txt", Size: 6}
	if _, err := validateChatAttachments(context.Background(), base, []chatAttachment{attachment}); err == nil {
		t.Fatal("linked attachment accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validateChatAttachments(ctx, base, []chatAttachment{attachment}); err == nil {
		t.Fatal("cancelled validation accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(uploads); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, uploads); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	attachment = chatAttachment{Name: "outside.txt", Path: "uploads/outside.txt", Size: 6}
	if _, err := validateChatAttachments(context.Background(), base, []chatAttachment{attachment}); err == nil {
		t.Fatal("linked upload directory accepted")
	}
}
