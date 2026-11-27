package sandboxbroker

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestDockerBrokerSmoke is opt-in because it creates a disposable container.
// Use only a reviewed local image digest that contains /bin/sh and sleep.
func TestDockerBrokerSmoke(t *testing.T) {
	image := os.Getenv("ARTEX_SANDBOX_BROKER_SMOKE_IMAGE")
	if image == "" {
		t.Skip("set ARTEX_SANDBOX_BROKER_SMOKE_IMAGE to run Docker smoke test")
	}
	path, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewDockerEngine(path)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := New(engine, image)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handle, err := broker.Create(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cleanupCancel()
	if err := broker.Remove(cleanupCtx, handle); err != nil {
		t.Fatal(err)
	}
}
