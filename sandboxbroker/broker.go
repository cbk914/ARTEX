// Package sandboxbroker holds the host-side lifecycle for disposable campaign sandboxes.
// It does not route ARTEX execution into a sandbox.
package sandboxbroker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

var pinnedImage = regexp.MustCompile(`^(?:[a-zA-Z0-9][a-zA-Z0-9._/:-]*@)?sha256:[a-f0-9]{64}$`)

// DefaultSandboxLimit caps active containers unless the operator sets a
// stricter or larger reviewed limit at broker startup.
const DefaultSandboxLimit = 8

// MaxSandboxLimit is the fixed upper bound for the startup setting.
const MaxSandboxLimit = 64

type Spec struct {
	Name, Image, Token, Owner string
	UploadVolume              bool
}

// CommandExitError reports a completed sandbox command's nonzero exit status.
// It carries no output or Docker diagnostics; callers receive output separately.
type CommandExitError struct{ Code int }

func (e *CommandExitError) Error() string {
	return fmt.Sprintf("sandbox command exited with code %d", e.Code)
}

// Engine is implemented only by a trusted host-side container controller.
type Engine interface {
	CheckImage(context.Context, string) error
	Create(context.Context, Spec) (string, error)
	Start(context.Context, string) error
	Verify(context.Context, string, Spec) error
	Exec(context.Context, string, string) (string, error)
	ExecInput(context.Context, string, string, []byte) (string, error)
	PutArtifact(context.Context, string, string, []byte) error
	PutUpload(context.Context, Spec, string, io.Reader, int64, string) error
	Remove(context.Context, string) error
	CreateUploadVolume(context.Context, Spec) (string, error)
	VerifyUploadVolume(context.Context, Spec) error
	RemoveUploadVolume(context.Context, Spec) error
}

// Journal durably records creation intent before Docker can create a sandbox.
// A recovery service must inspect these records before accepting requests.
type Journal interface {
	Record(Spec) error
	Forget(Spec) error
}

type sandbox struct {
	campaignID       int64
	container        string
	spec             Spec
	opMu             sync.Mutex
	poisoned         bool
	containerRemoved bool
}
type Broker struct {
	engine         Engine
	image          string
	owner          string
	journal        Journal
	limit          int
	creationUnsafe bool
	mu             sync.Mutex
	byHandle       map[string]*sandbox
	byCampaign     map[int64]string
}

func New(engine Engine, image string) (*Broker, error) {
	owner, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	return NewWithOwner(engine, image, owner)
}

// NewWithOwner binds every sandbox to a durable, installation-specific owner
// identity supplied by the trusted broker service, never by an agent request.
func NewWithOwner(engine Engine, image, owner string) (*Broker, error) {
	return NewWithJournal(engine, image, owner, nil)
}

// NewWithJournal is used by the Linux service after its private journal has
// been recovered. Tests and in-memory prototypes may omit a journal.
func NewWithJournal(engine Engine, image, owner string, journal Journal) (*Broker, error) {
	return NewWithJournalLimit(engine, image, owner, journal, DefaultSandboxLimit)
}

// NewWithJournalLimit bounds the total number of active sandboxes. A service
// may choose a smaller site-specific limit, but cannot remove the ceiling.
func NewWithJournalLimit(engine Engine, image, owner string, journal Journal, limit int) (*Broker, error) {
	if engine == nil || !pinnedImage.MatchString(image) || !brokerOwner.MatchString(owner) {
		return nil, errors.New("sandbox broker requires an engine, pinned image digest and valid owner ID")
	}
	if limit < 1 || limit > MaxSandboxLimit {
		return nil, errors.New("sandbox limit must be between 1 and 64")
	}
	return &Broker{engine: engine, image: image, owner: owner, journal: journal, limit: limit, byHandle: make(map[string]*sandbox), byCampaign: make(map[int64]string)}, nil
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
	if b.creationUnsafe {
		return "", errors.New("sandbox creation requires broker recovery")
	}
	if _, exists := b.byCampaign[campaignID]; exists {
		return "", errors.New("campaign already has a sandbox")
	}
	if len(b.byHandle) >= b.limit {
		return "", errors.New("sandbox capacity reached")
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
	spec := Spec{Name: "artex-campaign-" + nameID, Image: b.image, Token: token, Owner: b.owner, UploadVolume: true}
	if b.journal != nil {
		if err := b.journal.Record(spec); err != nil {
			return "", fmt.Errorf("record sandbox intent: %w", err)
		}
	}
	if _, err := b.engine.CreateUploadVolume(ctx, spec); err != nil {
		b.creationUnsafe = true
		return "", fmt.Errorf("create campaign upload volume: %w", err)
	}
	container, err := b.engine.Create(ctx, spec)
	if err != nil {
		// Docker may have created a container before the client lost its result.
		// Only journal recovery can establish whether that happened.
		b.creationUnsafe = true
		return "", fmt.Errorf("create sandbox: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if cleanupErr := b.engine.Remove(cleanupCtx, container); cleanupErr != nil {
				b.creationUnsafe = true
				err = errors.Join(err, fmt.Errorf("remove failed sandbox %s: %w", container, cleanupErr))
			} else if cleanupErr := b.engine.RemoveUploadVolume(cleanupCtx, spec); cleanupErr != nil {
				b.creationUnsafe = true
				err = errors.Join(err, fmt.Errorf("remove failed upload volume: %w", cleanupErr))
			} else if b.journal != nil {
				if forgetErr := b.journal.Forget(spec); forgetErr != nil {
					b.creationUnsafe = true
					err = errors.Join(err, forgetErr)
				}
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
	if !s.containerRemoved {
		if err := b.engine.Remove(ctx, s.container); err != nil {
			s.poisoned = true
			return fmt.Errorf("remove sandbox: %w", err)
		}
		s.containerRemoved = true
	}
	if err := b.engine.RemoveUploadVolume(ctx, s.spec); err != nil {
		s.poisoned = true
		return fmt.Errorf("remove campaign upload volume: %w", err)
	}
	var journalErr error
	if b.journal != nil {
		journalErr = b.journal.Forget(s.spec)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.byHandle, handle)
	delete(b.byCampaign, s.campaignID)
	return journalErr
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
	if !s.containerRemoved {
		if err := b.engine.Remove(cleanupCtx, s.container); err != nil {
			return fmt.Errorf("retire unsafe sandbox: %w", err)
		}
		s.containerRemoved = true
	}
	if err := b.engine.RemoveUploadVolume(cleanupCtx, s.spec); err != nil {
		return fmt.Errorf("retire unsafe sandbox upload volume: %w", err)
	}
	var journalErr error
	if b.journal != nil {
		journalErr = b.journal.Forget(s.spec)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.byHandle[handle] == s {
		delete(b.byHandle, handle)
		delete(b.byCampaign, s.campaignID)
	}
	return journalErr
}

// Run executes a bounded shell command through an opaque handle. The caller must
// first authorize the campaign; this in-memory prototype has no server API.
func (b *Broker) Run(ctx context.Context, handle, command string) (string, error) {
	return b.run(ctx, handle, command, nil)
}

// RunInput supplies bounded stdin to a command in the same isolated sandbox.
// It is intended for script parameters and later stdio-capable tool routing.
func (b *Broker) RunInput(ctx context.Context, handle, command string, input []byte) (string, error) {
	if len(input) == 0 || len(input) > maxBrokerStdinBytes {
		return "", errors.New("invalid sandbox stdin")
	}
	return b.run(ctx, handle, command, append([]byte(nil), input...))
}

const maxBrokerStdinBytes = 1 << 20

func (b *Broker) run(ctx context.Context, handle, command string, input []byte) (string, error) {
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
	var output string
	if input == nil {
		output, err = b.engine.Exec(runCtx, s.container, command)
	} else {
		output, err = b.engine.ExecInput(runCtx, s.container, command, input)
	}
	if runCtx.Err() != nil || errors.Is(err, errDockerOutputLimit) || errors.Is(err, errDockerStatusInvalid) {
		return output, errors.Join(err, runCtx.Err(), b.retireLocked(handle, s))
	}
	return output, err
}

// PutArtifact publishes one immutable, root-owned file to a campaign sandbox.
// Only a separately authorized control-plane caller may use a handle.
func (b *Broker) PutArtifact(ctx context.Context, handle, name string, data []byte) error {
	if !validArtifactName(name) || len(data) == 0 || len(data) > maxArtifactBytes {
		return errors.New("invalid sandbox artifact")
	}
	s, err := b.lockSandbox(handle)
	if err != nil {
		return err
	}
	defer s.opMu.Unlock()
	if s.poisoned {
		return errors.New("sandbox is unsafe and requires removal")
	}
	putCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := b.engine.Verify(putCtx, s.container, s.spec); err != nil {
		return errors.Join(fmt.Errorf("verify sandbox before artifact: %w", err), b.retireLocked(handle, s))
	}
	if err := b.engine.PutArtifact(putCtx, s.container, name, data); err != nil {
		return errors.Join(fmt.Errorf("publish sandbox artifact: %w", err), b.retireLocked(handle, s))
	}
	if err := putCtx.Err(); err != nil {
		return errors.Join(err, b.retireLocked(handle, s))
	}
	return nil
}

// PutUpload publishes an integrity-bound attachment to the campaign's
// read-only upload mount. A caller must authorize the task before using its
// opaque handle; the broker serializes publication with sandbox operations.
func (b *Broker) PutUpload(ctx context.Context, handle, name string, input io.Reader, size int64, digest string) error {
	if !validCampaignUploadName(name) || input == nil || size <= 0 || size > maxCampaignUploadBytes || !uploadDigest.MatchString(digest) {
		return errors.New("invalid campaign upload")
	}
	s, err := b.lockSandbox(handle)
	if err != nil {
		return err
	}
	defer s.opMu.Unlock()
	if s.poisoned || !s.spec.UploadVolume {
		return errors.New("sandbox upload volume unavailable")
	}
	putCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := b.engine.Verify(putCtx, s.container, s.spec); err != nil {
		return errors.Join(fmt.Errorf("verify sandbox before upload: %w", err), b.retireLocked(handle, s))
	}
	if err := b.engine.PutUpload(putCtx, s.spec, name, input, size, digest); err != nil {
		return errors.Join(fmt.Errorf("publish campaign upload: %w", err), b.retireLocked(handle, s))
	}
	if err := putCtx.Err(); err != nil {
		return errors.Join(err, b.retireLocked(handle, s))
	}
	return nil
}
