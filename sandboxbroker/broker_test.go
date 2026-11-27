package sandboxbroker

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
)

const testImage = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeEngine struct {
	created, started, verified, removed int
	failure                             string
}

func (f *fakeEngine) CheckImage(context.Context, string) error {
	if f.failure == "image" {
		return errors.New("image failure")
	}
	return nil
}
func (f *fakeEngine) Create(_ context.Context, s Spec) (string, error) {
	f.created++
	if !strings.HasPrefix(s.Name, "artex-campaign-") || s.Image != testImage {
		return "", errors.New("bad spec")
	}
	return strings.Repeat("a", 64), nil
}
func (f *fakeEngine) Start(context.Context, string) error {
	f.started++
	if f.failure == "start" {
		return errors.New("start failure")
	}
	return nil
}
func (f *fakeEngine) Verify(context.Context, string, Spec) error {
	f.verified++
	if f.failure == "verify" {
		return errors.New("verify failure")
	}
	return nil
}
func (f *fakeEngine) Remove(context.Context, string) error {
	f.removed++
	if f.failure == "remove" {
		return errors.New("remove failure")
	}
	return nil
}

func TestBrokerLifecycle(t *testing.T) {
	engine := &fakeEngine{}
	broker, err := New(engine, testImage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Create(context.Background(), 0); err == nil {
		t.Fatal("accepted invalid campaign")
	}
	handle, err := broker.Create(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(handle) != 64 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(handle) {
		t.Fatalf("handle is not opaque: %q", handle)
	}
	if _, err := broker.Create(context.Background(), 42); err == nil {
		t.Fatal("accepted duplicate campaign")
	}
	if err := broker.Remove(context.Background(), "unknown"); err == nil {
		t.Fatal("accepted unknown handle")
	}
	if err := broker.Remove(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if engine.created != 1 || engine.started != 1 || engine.verified != 1 || engine.removed != 1 {
		t.Fatalf("unexpected lifecycle counts: %+v", engine)
	}
	second, err := broker.Create(context.Background(), 42)
	if err != nil || second == handle {
		t.Fatalf("failed clean re-creation: %q %v", second, err)
	}
}

func TestBrokerCleansFailedSandbox(t *testing.T) {
	for _, failure := range []string{"start", "verify"} {
		t.Run(failure, func(t *testing.T) {
			engine := &fakeEngine{failure: failure}
			broker, _ := New(engine, testImage)
			if _, err := broker.Create(context.Background(), 1); err == nil {
				t.Fatal("expected failure")
			}
			if engine.removed != 1 {
				t.Fatalf("failed sandbox not removed: %+v", engine)
			}
			engine.failure = ""
			if _, err := broker.Create(context.Background(), 1); err != nil {
				t.Fatalf("campaign left reserved: %v", err)
			}
		})
	}
}

func TestBrokerRejectsUnpinnedImage(t *testing.T) {
	for _, image := range []string{"artex:latest", "sha256:abc", "repo@sha256:" + strings.Repeat("g", 64)} {
		if _, err := New(&fakeEngine{}, image); err == nil {
			t.Errorf("accepted image %q", image)
		}
	}
}
