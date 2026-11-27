//go:build linux

package sandboxbroker

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func identityFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root identity fixture requires root")
	}
	dir, err := os.MkdirTemp("/run", "artex-identity-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "broker.sock")
}

func TestBrokerIdentityPersistsAndLocks(t *testing.T) {
	path := identityFixture(t)
	first, err := OpenBrokerIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if !brokerOwner.MatchString(first.Owner) {
		t.Fatalf("invalid owner %q", first.Owner)
	}
	if _, err := OpenBrokerIdentity(path); err == nil {
		t.Fatal("accepted concurrent broker identity")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := OpenBrokerIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Owner != first.Owner {
		t.Fatalf("owner changed on restart: %q != %q", second.Owner, first.Owner)
	}
}

func TestBrokerIdentityRejectsUnsafeFiles(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		prepare    func(string) error
	}{
		{"symlink owner", "broker.owner", func(p string) error { return os.Symlink("/dev/null", p) }},
		{"loose owner", "broker.owner", func(p string) error { return os.WriteFile(p, []byte(strings.Repeat("a", 32)+"\n"), 0o644) }},
		{"invalid owner", "broker.owner", func(p string) error { return os.WriteFile(p, []byte("invalid\n"), 0o600) }},
		{"symlink lock", "broker.lock", func(p string) error { return os.Symlink("/dev/null", p) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := identityFixture(t)
			if err := tc.prepare(filepath.Join(filepath.Dir(path), tc.file)); err != nil {
				t.Fatal(err)
			}
			if identity, err := OpenBrokerIdentity(path); err == nil {
				_ = identity.Close()
				t.Fatal("accepted unsafe identity state")
			}
		})
	}
}

func TestBrokerIdentityPreparesOnlyStaleSocket(t *testing.T) {
	path := identityFixture(t)
	identity, err := OpenBrokerIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	if err := identity.PrepareSocket(path); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := identity.PrepareSocket(path); err == nil {
		t.Fatal("removed active socket")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := identity.PrepareSocket(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket remains: %v", err)
	}
	if err := os.WriteFile(path, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := identity.PrepareSocket(path); err == nil {
		t.Fatal("removed foreign file")
	}
}
