//go:build linux

package sandboxbroker

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// BrokerIdentity holds the installation owner and an exclusive service lock.
// The caller must keep it open until the broker has stopped and cleaned up.
type BrokerIdentity struct {
	Owner string
	lock  *os.File
}

func (i *BrokerIdentity) Close() error {
	if i == nil || i.lock == nil {
		return nil
	}
	err := i.lock.Close()
	i.lock = nil
	return err
}

// PrepareSocket removes only a stale broker socket while the exclusive lock
// is held. An active or unrecognized file requires operator intervention.
func (i *BrokerIdentity) PrepareSocket(socketPath string) error {
	if i == nil || i.lock == nil || filepath.Dir(socketPath) != filepath.Dir(i.lock.Name()) || filepath.Base(socketPath) != "broker.sock" {
		return errors.New("broker identity does not control socket path")
	}
	if err := validateBrokerSocketDirectory(socketPath); err != nil {
		return err
	}
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 || info.Mode().Perm() != 0o600 {
		return errors.New("existing broker socket is not root-owned mode 0600")
	}
	conn, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return errors.New("broker socket is active")
	}
	var opErr *net.OpError
	if !errors.As(dialErr, &opErr) || !errors.Is(opErr.Err, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot prove broker socket is stale: %w", dialErr)
	}
	check, err := os.Lstat(socketPath)
	if err != nil {
		return err
	}
	checkStat, ok := check.Sys().(*syscall.Stat_t)
	if !ok || check.Mode()&os.ModeSocket == 0 || checkStat.Uid != 0 || check.Mode().Perm() != 0o600 || checkStat.Dev != stat.Dev || checkStat.Ino != stat.Ino {
		return errors.New("broker socket changed while checking staleness")
	}
	return os.Remove(socketPath)
}

// OpenBrokerIdentity accepts only a root-controlled socket directory. A
// durable owner ID prevents a restarted broker from treating another
// installation's containers as its own.
func OpenBrokerIdentity(socketPath string) (_ *BrokerIdentity, retErr error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("broker identity requires root")
	}
	if err := validateBrokerSocketDirectory(socketPath); err != nil {
		return nil, err
	}
	dir := filepath.Dir(socketPath)
	lock, err := openPrivateFile(filepath.Join(dir, "broker.lock"), syscall.O_CREAT|syscall.O_RDWR)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = lock.Close()
		}
	}()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("broker identity is already locked: %w", err)
	}
	ownerPath := filepath.Join(dir, "broker.owner")
	ownerFile, err := openPrivateFile(ownerPath, syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		owner, randomErr := randomHex(16)
		if randomErr != nil {
			return nil, randomErr
		}
		ownerFile, err = openPrivateFile(ownerPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY)
		if err != nil {
			return nil, err
		}
		if _, err = ownerFile.WriteString(owner + "\n"); err == nil {
			err = ownerFile.Sync()
		}
		closeErr := ownerFile.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		directory, err := os.Open(dir)
		if err != nil {
			return nil, err
		}
		err = directory.Sync()
		_ = directory.Close()
		if err != nil {
			return nil, err
		}
		return &BrokerIdentity{Owner: owner, lock: lock}, nil
	}
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(ownerFile, 34))
	closeErr := ownerFile.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	owner := strings.TrimSuffix(string(data), "\n")
	if len(data) != 33 || !brokerOwner.MatchString(owner) {
		return nil, errors.New("invalid durable broker owner ID")
	}
	return &BrokerIdentity{Owner: owner, lock: lock}, nil
}

func openPrivateFile(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != 0 || info.Mode().Perm() != 0o600 {
		_ = file.Close()
		return nil, errors.New("broker identity file must be root-owned mode 0600")
	}
	return file, nil
}
