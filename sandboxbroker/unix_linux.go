//go:build linux

package sandboxbroker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ServeUnix exposes the broker only on a root-owned control-plane socket.
// The socket directory must already exist and must be under root-owned,
// non-writable ancestors. Executor UIDs cannot open it or pass SO_PEERCRED.
func ServeUnix(ctx context.Context, socketPath string, broker *Broker) (retErr error) {
	if err := validateBrokerSocketPath(socketPath); err != nil {
		return err
	}
	handler, err := newHTTPHandler(broker)
	if err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, broker.Shutdown(cleanupCtx))
	}()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return err
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       15 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(rootPeerListener{listener}) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			return err
		}
		<-done
		return nil
	}
}

func validateBrokerSocketPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Base(path) != "broker.sock" {
		return errors.New("broker socket requires an absolute broker.sock path")
	}
	if _, err := os.Lstat(path); err == nil {
		return errors.New("broker socket path already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	for current := dir; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("broker socket ancestor %q is not root-controlled", current)
		}
		if current == dir && info.Mode().Perm()&0o100 == 0 {
			return errors.New("broker socket directory cannot be traversed by root")
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

type rootPeerListener struct{ *net.UnixListener }

func (l rootPeerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		uid, err := unixPeerUID(conn)
		if err == nil && uid == 0 {
			return conn, nil
		}
		_ = conn.Close()
	}
}

func unixPeerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = cred.Uid
	}); err != nil {
		return 0, err
	}
	return uid, controlErr
}
