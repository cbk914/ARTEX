package sandboxbroker

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
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

// TestDockerCampaignIsolationSmoke exercises the broker-created containers with
// synthetic markers. It does not route any ARTEX tool through the broker.
func TestDockerCampaignIsolationSmoke(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	first, err := broker.Create(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	var second string
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		for _, handle := range []string{first, second} {
			if handle != "" {
				if err := broker.Remove(cleanupCtx, handle); err != nil {
					t.Errorf("remove sandbox: %v", err)
				}
			}
		}
	}()
	second, err = broker.Create(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	a := broker.byHandle[first].container
	b := broker.byHandle[second].container
	type result struct {
		name, output string
		err          error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, item := range []struct{ name, id, marker string }{{"A", a, "A_PRIVATE"}, {"B", b, "B_PRIVATE"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			output, err := engine.runner.Run(ctx, "exec", item.id, "/bin/sh", "-c", "printf %s "+item.marker+" > /campaign/marker; printf %s "+item.marker+" > \"$HOME/home-marker\"; touch /campaign/"+item.name+"-only; id -u")
			results <- result{item.name, strings.TrimSpace(string(output)), err}
		}()
	}
	wg.Wait()
	close(results)
	for got := range results {
		if got.err != nil || got.output != "10001" {
			t.Fatalf("sandbox %s identity/write: %q %v", got.name, got.output, got.err)
		}
	}
	for _, item := range []struct{ id, own, other string }{{a, "A_PRIVATE", "B"}, {b, "B_PRIVATE", "A"}} {
		output, err := engine.runner.Run(ctx, "exec", item.id, "/bin/sh", "-c", "cat /campaign/marker; cat \"$HOME/home-marker\"; test ! -e /campaign/"+item.other+"-only")
		if err != nil || string(output) != item.own+item.own {
			t.Fatalf("cross-campaign marker check: %q %v", output, err)
		}
	}
	pidText, err := engine.runner.Run(ctx, "inspect", "--format", "{{.State.Pid}}", a)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidText)))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid sandbox host PID %q: %v", pidText, err)
	}
	if _, err := engine.runner.Run(ctx, "exec", b, "/bin/sh", "-c", "kill -0 "+strconv.Itoa(pid)); err == nil {
		t.Fatal("campaign B can signal campaign A host PID")
	}
	if err := broker.Remove(ctx, first); err != nil {
		t.Fatal(err)
	}
	first = ""
	newHandle, err := broker.Create(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	first = newHandle
	newID := broker.byHandle[first].container
	if _, err := engine.runner.Run(ctx, "exec", newID, "/bin/sh", "-c", "test ! -e /campaign/marker && test ! -e \"$HOME/home-marker\""); err != nil {
		t.Fatalf("sequential sandbox reused stale state: %v", err)
	}
}
