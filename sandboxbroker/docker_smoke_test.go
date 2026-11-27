package sandboxbroker

import (
	"context"
	"os"
	"os/exec"
	"strings"
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

func TestDockerNameConflictSmoke(t *testing.T) {
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
	nameID, err := randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	name := "artex-campaign-" + nameID
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := engine.runner.Run(ctx, "create", "--pull=never", "--name", name, "--network=none", image, "sleep", "infinity")
	if err != nil {
		t.Fatal(err)
	}
	id := strings.TrimSpace(string(created))
	if !containerID.MatchString(id) {
		t.Fatalf("unexpected fixture container ID %q", id)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := engine.runner.Run(cleanupCtx, "rm", "-f", "-v", id); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
	})
	token, err := randomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Create(ctx, Spec{Name: name, Image: image, Token: token}); err == nil {
		t.Fatal("name collision unexpectedly created a sandbox")
	}
	if _, err := engine.runner.Run(ctx, "inspect", id); err != nil {
		t.Fatalf("broker removed a foreign container on name collision: %v", err)
	}
}
