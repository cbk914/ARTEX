//go:build linux && isolation_probe

package server

import (
	"context"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Opt-in diagnostic only. This uses an unapproved loopback fixture inside a
// disposable container and demonstrates the missing child-process network gate.
func TestUnscopedExecutorCanReachLocalMockProbe(t *testing.T) {
	f := newExecRootFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			served <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, err = io.ReadFull(conn, buf)
		if err == nil && string(buf) != "PING" {
			err = io.ErrUnexpectedEOF
		}
		if err == nil {
			_, err = conn.Write([]byte("PONG"))
		}
		served <- err
	}()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	code := `import os, socket
host, port = os.environ["MOCK_ADDR"].rsplit(":", 1)
with socket.create_connection((host, int(port)), timeout=2) as conn:
    conn.sendall(b"PING")
    print(conn.recv(4).decode())`
	out, err := execPython(context.Background(), py, "probe", code, nil, f.work, []string{"MOCK_ADDR=" + listener.Addr().String()}, 10*time.Second, f.priv)
	if err != nil || !strings.Contains(out, "PONG") {
		t.Fatalf("executor mock connection: %v %q", err, out)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mock service did not receive the executor connection")
	}
	t.Log("observed: unapproved custom-tool executor reached the local mock TCP destination")
}
