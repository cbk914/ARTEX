//go:build linux

package sandboxbroker

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestServeUnixUsesRootOnlySocket(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned socket fixture requires root")
	}
	dir, err := os.MkdirTemp("/run", "artex-broker-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "broker.sock")
	engine := &fakeEngine{}
	broker, _ := New(engine, testImage)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeUnix(ctx, path, broker) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server stopped before socket appeared: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", info, err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	request, _ := http.NewRequest(http.MethodPost, "http://broker/v1/sandboxes", strings.NewReader(`{"campaign_id":1}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("root client status=%d", response.StatusCode)
	}
	// Make the socket connectable to a non-root process for this test only. A
	// kernel peer-credential check must still close that connection.
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	helperPath := filepath.Join(dir, "nonroot-helper")
	helper, err := os.OpenFile(helperPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(helper, source); err != nil {
		helper.Close()
		t.Fatal(err)
	}
	if err := helper.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	childCtx, childCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer childCancel()
	child := exec.CommandContext(childCtx, helperPath, "-test.run=^TestBrokerUnixNonRootHelper$", "-test.v")
	child.Env = append(os.Environ(), "ARTEX_BROKER_NONROOT_SOCKET="+path)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 10001, Gid: 10001}}
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("non-root peer test failed: %v: %s", err, output)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if engine.removed != 1 {
		t.Fatalf("shutdown retained %d owned sandboxes", 1-engine.removed)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remained after shutdown: %v", err)
	}
}

func TestBrokerUnixNonRootHelper(t *testing.T) {
	path := os.Getenv("ARTEX_BROKER_NONROOT_SOCKET")
	if path == "" {
		return
	}
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatalf("test socket was not connectable: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET /v1/sandboxes HTTP/1.1\r\nHost: broker\r\n\r\n"))
	var first [1]byte
	n, err := conn.Read(first[:])
	if n != 0 || err == nil {
		t.Fatalf("non-root peer received HTTP response: bytes=%d err=%v", n, err)
	}
}

func TestBrokerSocketRejectsWorldWritableAncestor(t *testing.T) {
	if err := validateBrokerSocketPath(filepath.Join(t.TempDir(), "broker.sock")); err == nil {
		t.Fatal("accepted socket path under world-writable /tmp")
	}
	if err := validateBrokerSocketPath("broker.sock"); err == nil {
		t.Fatal("accepted relative broker socket path")
	}
}
