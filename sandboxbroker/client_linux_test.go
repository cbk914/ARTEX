//go:build linux

package sandboxbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUnixClientRoundTripAndFailClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-controlled socket fixture requires root")
	}
	dir, err := os.MkdirTemp("/run", "artex-broker-client-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "broker.sock")
	if _, err := NewUnixClient(path); err == nil {
		t.Fatal("client accepted missing broker socket")
	}
	engine := &fakeEngine{}
	broker, _ := New(engine, testImage)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeUnix(ctx, path, broker) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	client, err := NewUnixClient(path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	handle, err := client.Create(context.Background(), 42)
	if err != nil || len(handle) != 64 {
		t.Fatalf("create: %q %v", handle, err)
	}
	output, err := client.Run(context.Background(), handle, "echo synthetic")
	if err != nil || output != "ran: echo synthetic" {
		t.Fatalf("run: %q %v", output, err)
	}
	input := []byte{'a', 0, 'b'}
	output, err = client.RunInput(context.Background(), handle, "cat", input)
	if err != nil || output != "ran: cat" || string(engine.lastInput) != string(input) {
		t.Fatalf("stdin run: %q %v input=%q", output, err, engine.lastInput)
	}
	upload := []byte("synthetic upload")
	hash := sha256.Sum256(upload)
	if err := client.PutUpload(context.Background(), handle, "análisis final.txt", strings.NewReader(string(upload)), int64(len(upload)), hex.EncodeToString(hash[:])); err != nil {
		t.Fatalf("stream upload: %v", err)
	}
	emptyHash := sha256.Sum256(nil)
	if err := client.PutUpload(context.Background(), handle, "empty.txt", strings.NewReader(""), 0, hex.EncodeToString(emptyHash[:])); err != nil {
		t.Fatalf("empty upload: %v", err)
	}
	if err := client.PutUpload(context.Background(), handle, "invalid-empty.txt", strings.NewReader("unexpected"), 0, hex.EncodeToString(emptyHash[:])); err == nil {
		t.Fatal("accepted nonempty source declared as empty")
	}
	engine.failure = "command-exit"
	output, err = client.Run(context.Background(), handle, "exit 7")
	var exit *CommandExitError
	if output != "diagnostic\n" || !errors.As(err, &exit) || exit.Code != 7 {
		t.Fatalf("nonzero command result: %q %v", output, err)
	}
	output, err = client.RunInput(context.Background(), handle, "exit 7", input)
	if output != "diagnostic\n" || !errors.As(err, &exit) || exit.Code != 7 {
		t.Fatalf("nonzero stdin result: %q %v", output, err)
	}
	engine.failure = ""
	digest, err := client.PutArtifact(context.Background(), handle, "fixture.txt", []byte("synthetic"))
	if err != nil || len(digest) != 64 || engine.delivered != 1 {
		t.Fatalf("artifact delivery: digest=%q delivered=%d err=%v", digest, engine.delivered, err)
	}
	if err := client.Remove(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Run(context.Background(), handle, "echo again"); err == nil {
		t.Fatal("client accepted retired handle")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Create(context.Background(), 43); err == nil {
		t.Fatalf("client accepted weakened broker socket: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if engine.created != 1 {
		t.Fatalf("weakened socket allowed a new sandbox: created=%d", engine.created)
	}
	if _, err := client.Create(context.Background(), 44); err == nil {
		t.Fatal("client accepted unavailable broker")
	}
	if _, err := client.Run(context.Background(), handle, "echo again"); err == nil || strings.Contains(err.Error(), handle) {
		t.Fatalf("unavailable broker exposed handle or allowed execution: %v", err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewUnixClient(path); err == nil {
		t.Fatal("client accepted a forged socket symlink")
	}
}
