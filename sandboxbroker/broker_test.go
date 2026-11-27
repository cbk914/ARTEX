package sandboxbroker

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testImage = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeEngine struct {
	created, started, verified, executed, delivered, removed int
	failure                                                  string
	lastInput                                                []byte
}

type testJournal struct {
	recorded []Spec
	forgot   []Spec
	fail     bool
}

func (j *testJournal) Record(spec Spec) error {
	if j.fail {
		return errors.New("journal unavailable")
	}
	j.recorded = append(j.recorded, spec)
	return nil
}

func (j *testJournal) Forget(spec Spec) error {
	j.forgot = append(j.forgot, spec)
	return nil
}

type journalCheckingEngine struct {
	*fakeEngine
	journal *testJournal
}

func (e *journalCheckingEngine) Create(ctx context.Context, spec Spec) (string, error) {
	if len(e.journal.recorded) != 1 || e.journal.recorded[0] != spec {
		return "", errors.New("Docker create preceded durable intent")
	}
	return e.fakeEngine.Create(ctx, spec)
}

func TestBrokerJournalsBeforeCreateAndForgetsAfterRemove(t *testing.T) {
	j := &testJournal{fail: true}
	e := &journalCheckingEngine{fakeEngine: &fakeEngine{}, journal: j}
	b, err := NewWithJournal(e, testImage, strings.Repeat("f", 32), j)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(context.Background(), 1); err == nil || e.created != 0 {
		t.Fatalf("created without journal: err=%v count=%d", err, e.created)
	}
	j.fail = false
	handle, err := b.Create(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(j.forgot) != 0 {
		t.Fatal("forgot intent before container removal")
	}
	if err := b.Remove(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
	if e.removed != 1 || len(j.forgot) != 1 || j.forgot[0] != j.recorded[0] {
		t.Fatalf("journal lifecycle mismatch: removed=%d, journal=%+v", e.removed, j)
	}
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
	if !ownershipToken.MatchString(s.Token) || !brokerOwner.MatchString(s.Owner) {
		return "", errors.New("missing ownership token")
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
func (f *fakeEngine) Exec(ctx context.Context, _ string, command string) (string, error) {
	f.executed++
	if f.failure == "cancel" {
		<-ctx.Done()
		return "", ctx.Err()
	}
	if f.failure == "output" {
		return "", errDockerOutputLimit
	}
	if f.failure == "status" {
		return "", errDockerStatusInvalid
	}
	if f.failure == "exec" {
		return "failure output", errors.New("command failed")
	}
	if f.failure == "command-exit" {
		return "diagnostic\n", &CommandExitError{Code: 7}
	}
	if f.failure == "command-timeout" {
		return "partial diagnostic", errors.Join(&CommandExitError{Code: 7}, context.DeadlineExceeded)
	}
	return "ran: " + command, nil
}
func (f *fakeEngine) ExecInput(ctx context.Context, _ string, command string, input []byte) (string, error) {
	f.lastInput = append([]byte(nil), input...)
	return f.Exec(ctx, "", command)
}
func (f *fakeEngine) PutArtifact(_ context.Context, _, _ string, _ []byte) error {
	f.delivered++
	if f.failure == "artifact" {
		return errors.New("artifact failure")
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

func TestBrokerRunInputBoundsAndRetiresUnsafeExecution(t *testing.T) {
	engine := &fakeEngine{}
	broker, err := New(engine, testImage)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := broker.Create(context.Background(), 44)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{nil, make([]byte, maxBrokerStdinBytes+1)} {
		if _, err := broker.RunInput(context.Background(), handle, "cat", input); err == nil {
			t.Fatalf("accepted stdin length %d", len(input))
		}
	}
	if engine.executed != 0 {
		t.Fatal("invalid stdin reached executor")
	}
	input := []byte{'a', 0, 'b'}
	if output, err := broker.RunInput(context.Background(), handle, "cat", input); err != nil || output != "ran: cat" || string(engine.lastInput) != string(input) {
		t.Fatalf("stdin execution: %q %v input=%q", output, err, engine.lastInput)
	}
	engine.failure = "output"
	if _, err := broker.RunInput(context.Background(), handle, "cat", []byte("x")); err == nil || engine.removed != 1 {
		t.Fatalf("unsafe stdin execution was not retired: %v removed=%d", err, engine.removed)
	}
}

func TestBrokerArtifactDeliveryRejectsUnsafeInputAndRetiresFailure(t *testing.T) {
	engine := &fakeEngine{}
	broker, err := New(engine, testImage)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := broker.Create(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../escape", ".", "..", "nested/file", "-option"} {
		if err := broker.PutArtifact(context.Background(), handle, name, []byte("data")); err == nil {
			t.Errorf("accepted unsafe artifact name %q", name)
		}
	}
	if engine.delivered != 0 {
		t.Fatal("unsafe name reached container engine")
	}
	if err := broker.PutArtifact(context.Background(), handle, "evidence.txt", []byte("data")); err != nil || engine.delivered != 1 {
		t.Fatalf("valid delivery: delivered=%d err=%v", engine.delivered, err)
	}
	engine.failure = "artifact"
	if err := broker.PutArtifact(context.Background(), handle, "next.txt", []byte("data")); err == nil {
		t.Fatal("accepted failed delivery")
	}
	if engine.removed != 1 {
		t.Fatal("failed delivery did not retire sandbox")
	}
	if _, err := broker.Run(context.Background(), handle, "true"); err == nil {
		t.Fatal("retired handle remained usable")
	}
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

func TestBrokerShutdownRemovesOnlyOwnedSandboxes(t *testing.T) {
	engine := &fakeEngine{}
	broker, _ := New(engine, testImage)
	for _, campaign := range []int64{1, 2} {
		if _, err := broker.Create(context.Background(), campaign); err != nil {
			t.Fatal(err)
		}
	}
	if err := broker.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if engine.removed != 2 || len(broker.byHandle) != 0 || len(broker.byCampaign) != 0 {
		t.Fatalf("shutdown left owned sandboxes: engine=%+v", engine)
	}
	if err := broker.Shutdown(context.Background()); err != nil || engine.removed != 2 {
		t.Fatalf("second shutdown removed anything else: %v %+v", err, engine)
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

func TestBrokerRequiresValidOwner(t *testing.T) {
	for _, owner := range []string{"", "foreign", strings.Repeat("g", 32)} {
		if _, err := NewWithOwner(&fakeEngine{}, testImage, owner); err == nil {
			t.Errorf("accepted invalid owner %q", owner)
		}
	}
	broker, err := NewWithOwner(&fakeEngine{}, testImage, strings.Repeat("a", 32))
	if err != nil || broker.owner != strings.Repeat("a", 32) {
		t.Fatalf("valid owner rejected: %v", err)
	}
}

func TestBrokerRunChecksHandleAndPolicy(t *testing.T) {
	engine := &fakeEngine{}
	broker, _ := New(engine, testImage)
	handle, err := broker.Create(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.Run(context.Background(), "unknown", "echo ok"); err == nil {
		t.Fatal("accepted unknown handle")
	}
	if _, err := broker.Run(context.Background(), handle, "bad\x00command"); err == nil {
		t.Fatal("accepted NUL in command")
	}
	out, err := broker.Run(context.Background(), handle, "echo ok")
	if err != nil || out != "ran: echo ok" || engine.executed != 1 || engine.verified != 2 {
		t.Fatalf("run=%q %v engine=%+v", out, err, engine)
	}
	engine.failure = "exec"
	out, err = broker.Run(context.Background(), handle, "false")
	if err == nil || out != "failure output" || engine.removed != 0 {
		t.Fatalf("ordinary command failure retired sandbox: %q %v %+v", out, err, engine)
	}
	engine.failure = ""
	if err := broker.Remove(context.Background(), handle); err != nil {
		t.Fatal(err)
	}
}

func TestBrokerRunRetiresUnsafeSandbox(t *testing.T) {
	for _, failure := range []string{"verify", "output", "status", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			engine := &fakeEngine{}
			broker, _ := New(engine, testImage)
			handle, err := broker.Create(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			engine.failure = failure
			ctx := context.Background()
			if failure == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			if _, err := broker.Run(ctx, handle, "echo ok"); err == nil {
				t.Fatal("unsafe run succeeded")
			}
			if engine.removed != 1 {
				t.Fatalf("unsafe sandbox not removed: %+v", engine)
			}
			if _, err := broker.Run(context.Background(), handle, "echo again"); err == nil {
				t.Fatal("retired handle remained usable")
			}
		})
	}
}

type blockingEngine struct {
	fakeEngine
	entered chan string
	release chan struct{}
}

func (e *blockingEngine) Verify(context.Context, string, Spec) error { return nil }
func (e *blockingEngine) Exec(_ context.Context, _ string, command string) (string, error) {
	e.entered <- command
	<-e.release
	return command, nil
}

func TestBrokerRunsDifferentCampaignsConcurrently(t *testing.T) {
	engine := &blockingEngine{entered: make(chan string, 2), release: make(chan struct{})}
	broker, _ := New(engine, testImage)
	a, err := broker.Create(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := broker.Create(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	for _, handle := range []string{a, b} {
		go func(h string) { _, err := broker.Run(context.Background(), h, "echo ok"); results <- err }(handle)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-engine.entered:
		case <-time.After(time.Second):
			close(engine.release)
			t.Fatal("campaign commands serialized globally")
		}
	}
	close(engine.release)
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}
