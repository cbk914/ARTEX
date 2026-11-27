// Package sandboxbroker holds the host-side lifecycle for disposable campaign sandboxes.
// It does not route ARTEX execution into a sandbox.
package sandboxbroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

var pinnedImage = regexp.MustCompile(`^(?:[a-zA-Z0-9][a-zA-Z0-9._/:-]*@)?sha256:[a-f0-9]{64}$`)

type Spec struct{ Name, Image, Token string }

// Engine is implemented only by a trusted host-side container controller.
type Engine interface {
	CheckImage(context.Context, string) error
	Create(context.Context, Spec) (string, error)
	Start(context.Context, string) error
	Verify(context.Context, string, Spec) error
	Exec(context.Context, string, string) (string, error)
	Remove(context.Context, string) error
}

type sandbox struct {
	campaignID int64
	container  string
	spec       Spec
	opMu       sync.Mutex
	poisoned   bool
}
type Broker struct {
	engine     Engine
	image      string
	mu         sync.Mutex
	byHandle   map[string]*sandbox
	byCampaign map[int64]string
}

func New(engine Engine, image string) (*Broker, error) {
	if engine == nil || !pinnedImage.MatchString(image) {
		return nil, errors.New("sandbox broker requires an engine and pinned image digest")
	}
	return &Broker{engine: engine, image: image, byHandle: make(map[string]*sandbox), byCampaign: make(map[int64]string)}, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Create reserves one sandbox per campaign. A failed operation removes its container.
func (b *Broker) Create(ctx context.Context, campaignID int64) (_ string, err error) {
	if campaignID <= 0 {
		return "", errors.New("invalid campaign ID")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, exists := b.byCampaign[campaignID]; exists {
		return "", errors.New("campaign already has a sandbox")
	}
	if err := b.engine.CheckImage(ctx, b.image); err != nil {
		return "", fmt.Errorf("check sandbox image: %w", err)
	}
	handle, err := randomHex(32)
	if err != nil {
		return "", err
	}
	nameID, err := randomHex(16)
	if err != nil {
		return "", err
	}
	token, err := randomHex(32)
	if err != nil {
		return "", err
	}
	spec := Spec{Name: "artex-campaign-" + nameID, Image: b.image, Token: token}
	container, err := b.engine.Create(ctx, spec)
	if err != nil {
		return "", fmt.Errorf("create sandbox: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if cleanupErr := b.engine.Remove(cleanupCtx, container); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("remove failed sandbox %s: %w", container, cleanupErr))
			}
		}
	}()
	if err := b.engine.Start(ctx, container); err != nil {
		return "", fmt.Errorf("start sandbox: %w", err)
	}
	if err := b.engine.Verify(ctx, container, spec); err != nil {
		return "", fmt.Errorf("verify sandbox: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b.byHandle[handle] = &sandbox{campaignID: campaignID, container: container, spec: spec}
	b.byCampaign[campaignID] = handle
	committed = true
	return handle, nil
}

// Remove destroys the ephemeral sandbox associated with an opaque handle.
func (b *Broker) Remove(ctx context.Context, handle string) error {
	s, err := b.lockSandbox(handle)
	if err != nil {
		return err
	}
	defer s.opMu.Unlock()
	if err := b.engine.Remove(ctx, s.container); err != nil {
		s.poisoned = true
		return fmt.Errorf("remove sandbox: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byHandle, handle)
	delete(b.byCampaign, s.campaignID)
	return nil
}

// Shutdown removes every sandbox still owned by this broker after its control
// listener has stopped accepting requests. It never enumerates or removes
// unrelated Docker containers. Abrupt process failure still needs recovery.
func (b *Broker) Shutdown(ctx context.Context) error {
	b.mu.Lock()
	handles := make([]string, 0, len(b.byHandle))
	for handle := range b.byHandle {
		handles = append(handles, handle)
	}
	b.mu.Unlock()
	var failures []error
	for _, handle := range handles {
		if err := ctx.Err(); err != nil {
			failures = append(failures, err)
			break
		}
		if err := b.Remove(ctx, handle); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (b *Broker) lockSandbox(handle string) (*sandbox, error) {
	b.mu.Lock()
	s := b.byHandle[handle]
	b.mu.Unlock()
	if s == nil {
		return nil, errors.New("unknown sandbox handle")
	}
	s.opMu.Lock()
	b.mu.Lock()
	valid := b.byHandle[handle] == s
	b.mu.Unlock()
	if !valid {
		s.opMu.Unlock()
		return nil, errors.New("unknown sandbox handle")
	}
	return s, nil
}

// retireLocked removes an unsafe sandbox. The caller must hold its operation lock.
func (b *Broker) retireLocked(handle string, s *sandbox) error {
	s.poisoned = true
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := b.engine.Remove(cleanupCtx, s.container); err != nil {
		return fmt.Errorf("retire unsafe sandbox: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.byHandle[handle] == s {
		delete(b.byHandle, handle)
		delete(b.byCampaign, s.campaignID)
	}
	return nil
}

// Run executes a bounded shell command through an opaque handle. The caller must
// first authorize the campaign; this in-memory prototype has no server API.
func (b *Broker) Run(ctx context.Context, handle, command string) (string, error) {
	if command == "" || len(command) > 64<<10 || strings.IndexByte(command, 0) >= 0 {
		return "", errors.New("invalid sandbox command")
	}
	s, err := b.lockSandbox(handle)
	if err != nil {
		return "", err
	}
	defer s.opMu.Unlock()
	if s.poisoned {
		return "", errors.New("sandbox is unsafe and requires removal")
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := b.engine.Verify(runCtx, s.container, s.spec); err != nil {
		return "", errors.Join(fmt.Errorf("verify sandbox before command: %w", err), b.retireLocked(handle, s))
	}
	output, err := b.engine.Exec(runCtx, s.container, command)
	if runCtx.Err() != nil || errors.Is(err, errDockerOutputLimit) {
		return output, errors.Join(err, runCtx.Err(), b.retireLocked(handle, s))
	}
	return output, err
}
