package sandboxbroker

import (
	"context"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// corruptingArtifactRunner simulates a damaged Docker stdin transfer while
// leaving the broker's expected digest unchanged.
type corruptingArtifactRunner struct{ commandRunner }

func (r corruptingArtifactRunner) RunInput(ctx context.Context, input io.Reader, args ...string) ([]byte, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	if len(data) > 0 {
		data[0] ^= 1
	}
	return r.commandRunner.RunInput(ctx, strings.NewReader(string(data)), args...)
}

func TestDockerCorruptArtifactTransferRetiresSandbox(t *testing.T) {
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
	engine.runner = corruptingArtifactRunner{engine.runner}
	broker, err := New(engine, image)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	handle, err := broker.Create(ctx, 101)
	if err != nil {
		t.Fatal(err)
	}
	id := broker.byHandle[handle].container
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := engine.runner.Run(cleanupCtx, "inspect", id); err == nil {
			_ = broker.Remove(cleanupCtx, handle)
			t.Errorf("corrupt transfer left sandbox %s running", id)
		}
	}()
	if err := broker.PutArtifact(ctx, handle, "fixture", []byte("TRUSTED")); err == nil {
		t.Fatal("published corrupted artifact")
	}
	if _, err := broker.Run(ctx, handle, "test ! -e /artifacts/fixture"); err == nil {
		t.Fatal("corrupt transfer left the sandbox handle usable")
	}
}

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
	owner, err := randomHex(16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Create(ctx, Spec{Name: name, Image: image, Token: token, Owner: owner}); err == nil {
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
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
	if _, err := broker.Run(ctx, first, "test -r /artifacts && test ! -w /artifacts && ! touch /artifacts/forbidden 2>/dev/null"); err != nil {
		t.Fatalf("executor can write artifacts directory: %v", err)
	}
	if err := broker.PutArtifact(ctx, first, "fixture", []byte("TRUSTED")); err != nil {
		t.Fatalf("publish synthetic artifact through broker: %v", err)
	}
	if out, err := broker.Run(ctx, first, "cat /artifacts/fixture && test ! -w /artifacts/fixture && ! mv /artifacts/fixture /artifacts/replaced 2>/dev/null"); err != nil || out != "TRUSTED" {
		t.Fatalf("executor artifact read-only check: %q %v", out, err)
	}
	if _, err := broker.Run(ctx, second, "test ! -e /artifacts/fixture"); err != nil {
		t.Fatalf("other campaign can see artifact: %v", err)
	}
	type result struct {
		name, output string
		err          error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, item := range []struct{ name, handle, marker string }{{"A", first, "A_PRIVATE"}, {"B", second, "B_PRIVATE"}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			output, err := broker.Run(ctx, item.handle, "printf %s "+item.marker+" > /campaign/marker; printf %s "+item.marker+" > \"$HOME/home-marker\"; for dir in \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" \"$XDG_DATA_HOME\" \"$XDG_STATE_HOME\" \"$XDG_RUNTIME_DIR\"; do printf %s "+item.marker+" > \"$dir/marker\" || exit; done; touch /campaign/"+item.name+"-only; id -u")
			results <- result{item.name, strings.TrimSpace(output), err}
		}()
	}
	wg.Wait()
	close(results)
	for got := range results {
		if got.err != nil || got.output != "10001" {
			t.Fatalf("sandbox %s identity/write: %q %v", got.name, got.output, got.err)
		}
	}
	for _, item := range []struct{ handle, own, other string }{{first, "A_PRIVATE", "B"}, {second, "B_PRIVATE", "A"}} {
		output, err := broker.Run(ctx, item.handle, "cat /campaign/marker; cat \"$HOME/home-marker\"; for dir in \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" \"$XDG_DATA_HOME\" \"$XDG_STATE_HOME\" \"$XDG_RUNTIME_DIR\"; do cat \"$dir/marker\" || exit; done; test ! -e /campaign/"+item.other+"-only")
		if err != nil || output != strings.Repeat(item.own, 7) {
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
	if _, err := broker.Run(ctx, second, "kill -0 "+strconv.Itoa(pid)); err == nil {
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
	if _, err := broker.Run(ctx, first, "test ! -e /campaign/marker && test ! -e \"$HOME/home-marker\" && for dir in \"$XDG_CONFIG_HOME\" \"$XDG_CACHE_HOME\" \"$XDG_DATA_HOME\" \"$XDG_STATE_HOME\" \"$XDG_RUNTIME_DIR\"; do test ! -e \"$dir/marker\" || exit; done"); err != nil {
		t.Fatalf("sequential sandbox reused stale state: %v", err)
	}
}

func TestDockerRunCancellationRetiresSandbox(t *testing.T) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	handle, err := broker.Create(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	id := broker.byHandle[handle].container
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if _, err := engine.runner.Run(cleanupCtx, "inspect", id); err == nil {
			if err := engine.Remove(cleanupCtx, id); err != nil {
				t.Errorf("cleanup cancelled sandbox: %v", err)
			}
		}
	})
	runCtx, runCancel := context.WithTimeout(ctx, 2*time.Second)
	defer runCancel()
	if _, err := broker.Run(runCtx, handle, "sleep 30"); err == nil {
		t.Fatal("cancelled command succeeded")
	}
	if _, exists := broker.byHandle[handle]; exists {
		t.Fatal("cancelled handle remained active")
	}
	if _, err := engine.runner.Run(ctx, "inspect", id); err == nil {
		t.Fatal("cancelled sandbox container still exists")
	}
}
