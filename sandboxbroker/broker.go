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
	"sync"
	"time"
)

var pinnedImage = regexp.MustCompile(`^(?:[a-zA-Z0-9][a-zA-Z0-9._/:-]*@)?sha256:[a-f0-9]{64}$`)

type Spec struct{ Name, Image string }

// Engine is implemented only by a trusted host-side container controller.
type Engine interface {
	CheckImage(context.Context, string) error
	Create(context.Context, Spec) (string, error)
	Start(context.Context, string) error
	Verify(context.Context, string, Spec) error
	Remove(context.Context, string) error
}

type sandbox struct {
	campaignID int64
	container  string
}
type Broker struct {
	engine     Engine
	image      string
	mu         sync.Mutex
	byHandle   map[string]sandbox
	byCampaign map[int64]string
}

func New(engine Engine, image string) (*Broker, error) {
	if engine == nil || !pinnedImage.MatchString(image) {
		return nil, errors.New("sandbox broker requires an engine and pinned image digest")
	}
	return &Broker{engine: engine, image: image, byHandle: make(map[string]sandbox), byCampaign: make(map[int64]string)}, nil
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
	spec := Spec{Name: "artex-campaign-" + nameID, Image: b.image}
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
	b.byHandle[handle] = sandbox{campaignID: campaignID, container: container}
	b.byCampaign[campaignID] = handle
	committed = true
	return handle, nil
}

// Remove destroys the ephemeral sandbox associated with an opaque handle.
func (b *Broker) Remove(ctx context.Context, handle string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	s, exists := b.byHandle[handle]
	if !exists {
		return errors.New("unknown sandbox handle")
	}
	if err := b.engine.Remove(ctx, s.container); err != nil {
		return fmt.Errorf("remove sandbox: %w", err)
	}
	delete(b.byHandle, handle)
	delete(b.byCampaign, s.campaignID)
	return nil
}
