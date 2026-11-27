package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceAllowlistCoversEveryRoute(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"tasks", "sessions", "drafts", "workspace", "traffic", "exec-home", "spill", "transcripts", "operator-evidence"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	private := filepath.Join(dir, "traffic", "secret.txt")
	if err := os.WriteFile(private, []byte("private marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: dir}}
	request := func(h http.HandlerFunc, method, target string, payload any) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		if payload != nil {
			if err := json.NewEncoder(&body).Encode(payload); err != nil {
				t.Fatal(err)
			}
		}
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(method, target, &body))
		return w
	}
	root := request(s.wsList, "GET", "/api/workspace/list", nil)
	if root.Code != 200 {
		t.Fatalf("root listing status = %d: %s", root.Code, root.Body.String())
	}
	var listing struct {
		Entries []wsEntry `json:"entries"`
	}
	if err := json.Unmarshal(root.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range listing.Entries {
		if !workspaceAllowedRoots[entry.Name] || !entry.Dir {
			t.Fatalf("root listing exposed a private entry: %+v", entry)
		}
		seen[entry.Name] = true
	}
	if len(seen) != len(workspaceAllowedRoots) {
		t.Fatalf("root listing = %v, want four allowed roots", seen)
	}
	for _, tc := range []struct {
		name, method, target string
		handler              http.HandlerFunc
		payload              any
	}{
		{"list private", "GET", "/api/workspace/list?path=traffic", s.wsList, nil},
		{"read private", "GET", "/api/workspace/read?path=traffic/secret.txt", s.wsRead, nil},
		{"download private", "GET", "/api/workspace/download?path=traffic/secret.txt", s.wsDownload, nil},
		{"write private", "POST", "/api/workspace/write", s.wsWrite, map[string]string{"path": "exec-home/cache", "content": "changed"}},
		{"write namespace root", "POST", "/api/workspace/write", s.wsWrite, map[string]string{"path": "drafts", "content": "file"}},
		{"mkdir private", "POST", "/api/workspace/mkdir", s.wsMkdir, map[string]string{"path": "spill/new"}},
		{"delete private", "DELETE", "/api/workspace/delete?path=transcripts", s.wsDelete, nil},
		{"upload private", "POST", "/api/workspace/upload?path=traffic", s.wsUpload, nil},
		{"upload at data root", "POST", "/api/workspace/upload", s.wsUpload, nil},
		{"delete namespace", "DELETE", "/api/workspace/delete?path=workspace", s.wsDelete, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(tc.handler, tc.method, tc.target, tc.payload)
			if w.Code != 400 || bytes.Contains(w.Body.Bytes(), []byte("private marker")) {
				t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
			}
		})
	}
	if body, err := os.ReadFile(private); err != nil || string(body) != "private marker" {
		t.Fatalf("private file changed: %q, %v", body, err)
	}
	alias := filepath.Join(dir, "workspace", "private-alias")
	if err := os.Symlink(filepath.Join(dir, "traffic"), alias); err == nil {
		for _, tc := range []struct {
			method, target string
			handler        http.HandlerFunc
		}{
			{"GET", "/api/workspace/read?path=workspace/private-alias/secret.txt", s.wsRead},
			{"DELETE", "/api/workspace/delete?path=workspace/private-alias", s.wsDelete},
		} {
			if w := request(tc.handler, tc.method, tc.target, nil); w.Code != 400 {
				t.Errorf("alias request %s returned %d", tc.target, w.Code)
			}
		}
		if _, err := os.Lstat(alias); err != nil {
			t.Errorf("refused alias delete removed the link: %v", err)
		}
	}
	w := request(s.wsWrite, "POST", "/api/workspace/write", map[string]string{"path": "workspace/note.txt", "content": "ok"})
	if w.Code != 200 {
		t.Fatalf("ordinary workspace write = %d: %s", w.Code, w.Body.String())
	}
	if body, err := os.ReadFile(filepath.Join(dir, "workspace", "note.txt")); err != nil || string(body) != "ok" {
		t.Fatalf("ordinary workspace write = %q, %v", body, err)
	}
}

func TestPrepareWorkspaceRootPreservesExistingData(t *testing.T) {
	dir := t.TempDir()
	if err := prepareWorkspaceRoot(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "workspace", "note.txt")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareWorkspaceRoot(dir); err != nil {
		t.Fatal(err)
	}
	if body, err := os.ReadFile(file); err != nil || string(body) != "keep" {
		t.Fatalf("existing workspace file changed: %q, %v", body, err)
	}
	for _, kind := range []string{"file", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			other := t.TempDir()
			target := filepath.Join(other, "workspace")
			if kind == "file" {
				if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				private := filepath.Join(other, "private")
				if err := os.Mkdir(private, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(private, target); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			if err := prepareWorkspaceRoot(other); err == nil {
				t.Fatal("accepted a non-directory workspace root")
			}
			if _, err := os.Lstat(target); err != nil {
				t.Fatalf("rejected entry was changed: %v", err)
			}
		})
	}
}

func TestWorkspaceDescriptorRejectsReplacedNamespace(t *testing.T) {
	data := t.TempDir()
	private := filepath.Join(data, "traffic")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, filepath.Join(data, "workspace")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if root, _, err := openWorkspaceRootPath(data, filepath.Join(data, "workspace", "secret.txt")); err == nil {
		root.Close()
		t.Fatal("descriptor opened a symlinked namespace")
	}
}

func TestWorkspaceDeniesPlatformPaths(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"traffic/_ca", "traffic/_index", "traffic/host", "other", "workspace"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(dir, "traffic", "_ca", "mitmproxy-ca.pem")
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: dir}}

	for _, rel := range []string{
		"traffic/_ca",
		"traffic/_ca/mitmproxy-ca.pem",
		"traffic/_index",
		"traffic/_index/index.sqlite",
		"TRAFFIC/_CA/mitmproxy-ca.pem",
		"traffic/_ca.",
		"traffic/_ca./mitmproxy-ca.pem",
	} {
		if _, ok := s.wsResolveConfined(rel); ok {
			t.Errorf("%q resolved, want a refusal", rel)
		}
	}

	for _, rel := range []string{"", "workspace", "workspace/note.txt", "tasks", "sessions", "drafts"} {
		if _, ok := s.wsResolveConfined(rel); !ok {
			t.Errorf("%q refused, want a resolution", rel)
		}
	}
	for _, rel := range []string{"traffic", "traffic/host", "traffic/_caX", "other", "exec-home", "spill", "transcripts"} {
		if _, ok := s.wsResolveConfined(rel); ok {
			t.Errorf("%q resolved outside the allowlist", rel)
		}
	}

	link := filepath.Join(dir, "alias")
	if err := os.Symlink(filepath.Join(dir, "traffic", "_ca"), link); err == nil {
		if _, ok := s.wsResolveConfined("alias/mitmproxy-ca.pem"); ok {
			t.Error("symlink alias to traffic/_ca resolved")
		}
	}
}

func TestWorkspacePathDenied(t *testing.T) {
	root := filepath.Clean("/data")
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/data/traffic/_ca", true},
		{"/data/traffic/_ca/x", true},
		{"/data/traffic/_index/index.sqlite", true},
		{"/data/traffic/_caX", false},
		{"/data/traffic", false},
		{"/data/other", false},
		{"/elsewhere/traffic/_ca", true}, // outside the root: fail closed
	} {
		if got := workspacePathDenied(root, filepath.FromSlash(tc.path)); got != tc.want {
			t.Errorf("workspacePathDenied(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// Deleting a directory that holds a platform-internal subtree would remove the
// capture CA key and the exchange index with it, and the blob store is as
// internal as the index. Neither is reachable through the file manager.
func TestWorkspaceDeleteKeepsPlatformPathsAndBlobsAreDenied(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"traffic/_ca", "traffic/_index", "traffic/_blobs/sha256/ab", "traffic/host", "workspace/other/sub"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	kept := []string{"traffic/_ca/mitmproxy-ca.pem", "traffic/_index/index.sqlite", "traffic/_blobs/sha256/ab/abcd.bin", "traffic/host/note.txt"}
	for _, p := range append(kept, "workspace/other/sub/note.txt") {
		if err := os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{m: &Manager{dir: dir}}
	call := func(h http.HandlerFunc, method, target string) int {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(method, target, nil))
		return rec.Code
	}

	// The parent of the denied subtrees, in the spellings that reach it.
	for _, rel := range []string{"traffic", "traffic/", "TRAFFIC", "traffic."} {
		if code := call(s.wsDelete, "DELETE", "/api/workspace/delete?path="+url.QueryEscape(rel)); code != 400 {
			t.Errorf("DELETE %q: status=%d, want 400", rel, code)
		}
	}
	for _, p := range kept {
		if _, err := os.Stat(filepath.Join(dir, p)); err != nil {
			t.Errorf("%s is gone after the refused deletes: %v", p, err)
		}
	}

	// The blob store is denied like the CA and the index.
	for _, rel := range []string{"traffic/_blobs", "traffic/_blobs/sha256/ab/abcd.bin", "TRAFFIC/_BLOBS/sha256"} {
		for name, h := range map[string]http.HandlerFunc{"list": s.wsList, "read": s.wsRead, "download": s.wsDownload} {
			if code := call(h, "GET", "/api/workspace/"+name+"?path="+url.QueryEscape(rel)); code != 400 {
				t.Errorf("%s %q: status=%d, want 400", name, rel, code)
			}
		}
		if code := call(s.wsDelete, "DELETE", "/api/workspace/delete?path="+url.QueryEscape(rel)); code != 400 {
			t.Errorf("DELETE %q: status=%d, want 400", rel, code)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "traffic/_blobs/sha256/ab/abcd.bin")); err != nil {
		t.Errorf("the blob is gone: %v", err)
	}

	// An allowed-root symlink into the private traffic tree is refused.
	alias := filepath.Join(dir, "workspace", "alias")
	if err := os.Symlink(filepath.Join(dir, "traffic"), alias); err == nil {
		if code := call(s.wsDelete, "DELETE", "/api/workspace/delete?path=workspace/alias"); code != 400 {
			t.Errorf("DELETE of an alias into traffic: status=%d, want 400", code)
		}
		if _, err := os.Lstat(alias); err != nil {
			t.Errorf("the refused delete removed the alias: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "traffic/_ca/mitmproxy-ca.pem")); err != nil {
			t.Errorf("deleting the symlink removed the CA key: %v", err)
		}
	}

	// Ordinary trees below the user workspace remain deletable.
	for _, rel := range []string{"workspace/other"} {
		if code := call(s.wsDelete, "DELETE", "/api/workspace/delete?path="+url.QueryEscape(rel)); code != 200 {
			t.Errorf("DELETE %q: status=%d, want 200", rel, code)
		}
		if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
			t.Errorf("%s still exists after its delete", rel)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "traffic", "host", "note.txt")); err != nil {
		t.Errorf("traffic data changed through the workspace: %v", err)
	}
}
