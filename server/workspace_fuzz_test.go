package server

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// FuzzWorkspacePathConfinement opens accepted paths through the real workspace
// resolver and root, then compares file identities with sibling sentinels. The
// fixture is read-only during fuzzing so every input sees the same filesystem.
func FuzzWorkspacePathConfinement(f *testing.F) {
	for _, path := range []string{
		"inside.txt", "subdir/nested.txt", "in-file-rel", "in-dir-rel/nested.txt",
		"out-file", "out-dir/secret.txt", "broken-out", "loop-a",
		"subdir/rel-escape-file", "subdir/rel-escape-dir/secret.txt",
		"../outside/secret.txt", "..\\outside\\secret.txt", "in-dir-rel/../../outside/secret.txt",
		"/out-file", "\\out-file", "C:\\outside\\secret.txt", "a\x00b", "é/../out-file",
	} {
		f.Add(path)
	}
	base := f.TempDir()
	root := filepath.Join(base, "data", "workspace")
	outside := filepath.Join(base, "outside")
	for _, dir := range []string{filepath.Join(root, "subdir"), filepath.Join(outside, "dir")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			f.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		filepath.Join(root, "inside.txt"):           "INSIDE_OK",
		filepath.Join(root, "subdir", "nested.txt"): "NESTED_OK",
		filepath.Join(outside, "secret.txt"):        "TOP_SECRET",
		filepath.Join(outside, "dir", "secret.txt"): "DIR_SECRET",
	} {
		if err := os.WriteFile(name, []byte(content), 0o644); err != nil {
			f.Fatal(err)
		}
	}
	links := [][2]string{
		{filepath.Join(outside, "secret.txt"), filepath.Join(root, "out-file")},
		{filepath.Join(outside, "dir"), filepath.Join(root, "out-dir")},
		{"inside.txt", filepath.Join(root, "in-file-rel")},
		{"subdir", filepath.Join(root, "in-dir-rel")},
		{"loop-b", filepath.Join(root, "loop-a")},
		{"loop-a", filepath.Join(root, "loop-b")},
		{filepath.Join("..", "..", "..", "outside", "secret.txt"), filepath.Join(root, "subdir", "rel-escape-file")},
		{filepath.Join("..", "..", "..", "outside", "dir"), filepath.Join(root, "subdir", "rel-escape-dir")},
	}
	for _, link := range links {
		if err := os.Symlink(link[0], link[1]); err != nil {
			if runtime.GOOS == "windows" && isWindowsSymlinkPrivilegeErr(err) {
				f.Log("symlink privilege unavailable; fuzzing lexical and regular-file paths")
				break
			}
			f.Fatal(err)
		}
	}
	outsideInfo := make([]os.FileInfo, 0, 2)
	for _, name := range []string{filepath.Join(outside, "secret.txt"), filepath.Join(outside, "dir", "secret.txt")} {
		info, err := os.Stat(name)
		if err != nil {
			f.Fatal(err)
		}
		outsideInfo = append(outsideInfo, info)
	}
	server := newTestWorkspaceServer(root)
	f.Fuzz(func(t *testing.T, path string) {
		if len(path) > 256 {
			return
		}
		cp, allowed := server.wsResolveConfined(wsTestPath(path))
		if !allowed {
			return
		}
		if !isWithinRoot(filepath.Dir(root), cp.realPath) || !workspacePathAllowed(cp.realRoot, cp.realPath) {
			t.Fatalf("workspace accepted a path outside an allowed root: %q", path)
		}
		file, err := openWorkspaceResolved(cp)
		if err != nil {
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return
		}
		for _, outside := range outsideInfo {
			if os.SameFile(info, outside) {
				t.Fatalf("workspace opened an outside sentinel through %q", path)
			}
		}
		content, err := io.ReadAll(io.LimitReader(file, 64))
		if err != nil {
			t.Fatal(err)
		}
		if string(content) == "TOP_SECRET" || string(content) == "DIR_SECRET" {
			t.Fatalf("workspace read an outside sentinel through %q", path)
		}
	})
}
