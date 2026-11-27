//go:build linux

package sandboxbroker

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestBrokerCrossContainerServeUnix is an opt-in disposable Docker fixture.
// The orchestrator supplies a private socket volume and writes a stop marker.
func TestBrokerCrossContainerServeUnix(t *testing.T) {
	path := os.Getenv("ARTEX_BROKER_CROSS_CONTAINER_SOCKET")
	if path == "" {
		t.Skip("cross-container socket fixture not configured")
	}
	engine := &fakeEngine{}
	broker, err := New(engine, testImage)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeUnix(ctx, path, broker) }()
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	marker := filepath.Join(filepath.Dir(path), "stop")
	for {
		select {
		case err := <-done:
			t.Fatalf("broker service stopped before fixture completed: %v", err)
		case <-deadline.C:
			t.Fatal("cross-container fixture did not receive stop marker")
		default:
		}
		if _, err := os.Stat(marker); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if engine.created != 1 || engine.removed != 1 {
		t.Fatalf("broker did not clean up its fixture sandbox: created=%d removed=%d", engine.created, engine.removed)
	}
}
