package traffic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImportArchiveBudgetRejectsOversizeAndSymlinkedBlob(t *testing.T) {
	store, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	content := []byte("synthetic restored traffic blob")
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	archiveDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(archiveDir, "blobs"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(ArchiveSnapshot{Version: archiveVersionV2, Blobs: []string{hash}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveDir, "traffic.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveBudget(context.Background(), archiveDir, int64(len(manifest)-1), 1<<20); !errors.Is(err, errTrafficArchiveBudget) {
		t.Fatalf("oversized manifest error=%v", err)
	}
	source := filepath.Join(archiveDir, "blobs", hash+".bin")
	secret := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(secret, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, source); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	if _, err := store.ImportArchiveBudget(context.Background(), archiveDir, 1<<20, 1<<20); err == nil {
		t.Fatal("import followed a symlink outside the extracted archive")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveBudget(context.Background(), archiveDir, 1<<20, 1); err == nil {
		t.Fatal("import exceeded the single-blob budget")
	}
	if _, err := store.ImportArchiveBudget(context.Background(), archiveDir, 1<<20, 1<<20); err != nil {
		t.Fatalf("valid archive import failed: %v", err)
	}
	destination := filepath.Join(store.dir, "_blobs", "sha256", hash[:2], hash+".bin")
	if got, err := os.ReadFile(destination); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("restored blob=%q err=%v", got, err)
	}
	if err := os.WriteFile(destination, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ImportArchiveBudget(context.Background(), archiveDir, 1<<20, 1<<20); err == nil {
		t.Fatal("import accepted a corrupt existing blob")
	}
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	bucket := filepath.Dir(destination)
	if err := os.Remove(bucket); err != nil {
		t.Fatal(err)
	}
	outsideBucket := t.TempDir()
	if err := os.Symlink(outsideBucket, bucket); err != nil {
		t.Skipf("destination symlink fixture unavailable: %v", err)
	}
	if _, err := store.ImportArchiveBudget(context.Background(), archiveDir, 1<<20, 1<<20); err == nil {
		t.Fatal("import followed a symlinked destination bucket")
	}
	if _, err := os.Lstat(filepath.Join(outsideBucket, hash+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("restore wrote outside traffic store: %v", err)
	}
}

func TestExportHostsManifestBudgetPreservesPriorSnapshot(t *testing.T) {
	store, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const host = "bounded-archive.example"
	if _, err := store.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "bounded-exchange", 1, host, "GET", "/", "https://"+host+"/", 200, "text/plain", 0, 2000, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,resp_head,resp_body)
VALUES(?,?,?,?,?)`, "bounded-exchange", "GET / HTTP/1.1", nil, "HTTP/1.1 200 OK", bytes.Repeat([]byte("x"), 2000)); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "export")
	if count, err := store.ExportHostsBudget(context.Background(), []string{host}, destination, 1<<20, 1<<20); err != nil || count != 1 {
		t.Fatalf("valid export count=%d err=%v", count, err)
	}
	before, err := os.ReadFile(filepath.Join(destination, "traffic.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ExportHostsBudget(context.Background(), []string{host}, destination, 1<<20, 128); !errors.Is(err, errTrafficArchiveBudget) {
		t.Fatalf("small manifest budget returned %v", err)
	}
	after, err := os.ReadFile(filepath.Join(destination, "traffic.json"))
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("rejected export changed prior manifest: err=%v", err)
	}
	entries, err := os.ReadDir(destination)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if bytes.HasPrefix([]byte(entry.Name()), []byte(".traffic-")) {
			t.Fatalf("rejected export left temporary file %q", entry.Name())
		}
	}
}

func TestExportHostsRejectsSymlinkedBlob(t *testing.T) {
	root := t.TempDir()
	store, err := Open(root, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	content := bytes.Repeat([]byte("synthetic body"), maxInlineBody/len("synthetic body")+2)
	blob := store.spill(content, "application/octet-stream")
	if blob.hash == "" {
		t.Fatal("fixture did not create a blob")
	}
	const host = "archive-symlink.example"
	if _, err := store.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "symlink-exchange", 1, host, "GET", "/", "https://"+host+"/", 200, "application/octet-stream", 0, len(content), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB().Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, "symlink-exchange", "GET / HTTP/1.1", nil, nil, "HTTP/1.1 200 OK", nil, blob.hash); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "_blobs", "sha256", blob.hash[:2], blob.hash+".bin")
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(secret, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, source); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	destination := filepath.Join(t.TempDir(), "archive")
	if _, err := store.ExportHostsContext(context.Background(), []string{host}, destination, int64(len(content))); err == nil {
		t.Fatal("export followed a symlink outside the traffic store")
	}
	if _, err := os.Lstat(filepath.Join(destination, "traffic.json")); !os.IsNotExist(err) {
		t.Fatalf("export published traffic manifest after rejection: %v", err)
	}
}

func TestArchiveBlobCopyConfinesAndVerifiesSource(t *testing.T) {
	root := t.TempDir()
	destination := filepath.Join(t.TempDir(), "blobs")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte("synthetic private traffic body")
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	bucket := filepath.Join(root, "_blobs", "sha256", hash[:2])
	if err := os.MkdirAll(bucket, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(bucket, hash+".bin")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &Traffic{dir: root}
	if err := store.copyArchiveBlob(context.Background(), hash, destination, int64(len(content))); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(destination, hash+".bin")); err != nil || string(got) != string(content) {
		t.Fatalf("copied blob=%q err=%v", got, err)
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(secret, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, source); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	if err := store.copyArchiveBlob(context.Background(), hash, destination, int64(len(content))); err == nil {
		t.Fatal("followed symlinked traffic blob outside the store")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("tampered private traffic body"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.copyArchiveBlob(context.Background(), hash, destination, int64(len(content))); err == nil {
		t.Fatal("accepted content that did not match its blob hash")
	}
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.copyArchiveBlob(context.Background(), hash, destination, 1); err == nil {
		t.Fatal("read blob beyond the archive file limit")
	}
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(bucket, hash[2:4], hash+".bin")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.copyArchiveBlob(context.Background(), hash, destination, int64(len(content))); err != nil {
		t.Fatalf("legacy layout rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.copyArchiveBlob(ctx, hash, destination, int64(len(content))); err == nil {
		t.Fatal("ignored cancellation")
	}
}
