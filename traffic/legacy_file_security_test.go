package traffic

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyTrafficReadConfinesPathAndFile(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "old", "exchange")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	request := filepath.Join(legacy, "request.http")
	if err := os.WriteFile(request, []byte("GET / HTTP/1.1"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &Traffic{dir: root}
	if body, err := store.readLegacyExchangeFile(filepath.Join("old", "exchange"), "request.http"); err != nil || string(body) != "GET / HTTP/1.1" {
		t.Fatalf("legacy body=%q err=%v", body, err)
	}
	for _, path := range []string{"..", filepath.Join("old", "exchange", "..", ".."), root} {
		if _, err := store.readLegacyExchangeFile(path, "request.http"); err == nil {
			t.Fatalf("accepted unsafe legacy path %q", path)
		}
	}
	if err := os.Remove(request); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "outside-secret")
	if err := os.WriteFile(secret, []byte("synthetic secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, request); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	if _, err := store.readLegacyExchangeFile(filepath.Join("old", "exchange"), "request.http"); err == nil {
		t.Fatal("read symlinked legacy file outside the traffic store")
	}
	if err := os.Remove(request); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxLegacyExchangeFile + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.readLegacyExchangeFile(filepath.Join("old", "exchange"), "request.http"); err == nil {
		t.Fatal("read oversized legacy traffic file")
	}
}

func TestLegacyTrafficRoutesRejectUntrustedIndexPath(t *testing.T) {
	store, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const host = "legacy-archive.example"
	if _, err := store.DB().Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`, "legacy-unsafe", 1, host, "GET", "/", "https://"+host+"/", 200, "text/plain", 0, 0, "../outside"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get("legacy-unsafe"); err == nil {
		t.Fatal("Get accepted an escaping legacy path")
	}
	if _, err := store.ExportHostsContext(context.Background(), []string{host}, filepath.Join(t.TempDir(), "export"), 1<<20); err == nil {
		t.Fatal("archive export accepted an escaping legacy path")
	}
}
