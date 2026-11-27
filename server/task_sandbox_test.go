package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sandboxbroker"
)

type sandboxTaskStore struct {
	mu   sync.Mutex
	rows map[int64]*db.Task
	err  error
}

func (s *sandboxTaskStore) GetTask(id int64) (*db.Task, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	if row := s.rows[id]; row != nil {
		copy := *row
		return &copy, nil
	}
	return nil, nil
}

type sandboxBackendRecorder struct {
	mu          sync.Mutex
	created     map[int64]int
	ran         []string
	put         []string
	lastInput   []byte
	lastCommand string
	exitCode    int
	removed     []string
	removeFail  bool
	onCreate    func()
}

func (b *sandboxBackendRecorder) Create(_ context.Context, id int64) (string, error) {
	b.mu.Lock()
	b.created[id]++
	hook := b.onCreate
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	return fmt.Sprintf("handle-%d", id), nil
}

func (b *sandboxBackendRecorder) Run(_ context.Context, handle, command string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ran = append(b.ran, handle+":"+command)
	if b.exitCode != 0 {
		return "sandbox diagnostic\n", &sandboxbroker.CommandExitError{Code: b.exitCode}
	}
	return handle, nil
}

func (b *sandboxBackendRecorder) RunInput(_ context.Context, handle, command string, input []byte) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ran = append(b.ran, handle+":"+command+":"+string(input))
	b.lastInput = append([]byte(nil), input...)
	b.lastCommand = command
	if b.exitCode != 0 {
		return "sandbox diagnostic\n", &sandboxbroker.CommandExitError{Code: b.exitCode}
	}
	return handle, nil
}

func (b *sandboxBackendRecorder) PutArtifact(_ context.Context, handle, name string, _ []byte) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.put = append(b.put, handle+":"+name)
	return "digest", nil
}

func (b *sandboxBackendRecorder) Remove(ctx context.Context, handle string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.removeFail {
		return errors.New("synthetic removal failure")
	}
	b.removed = append(b.removed, handle)
	return nil
}

func newSandboxTestController(t *testing.T) (*taskSandboxController, *sandboxTaskStore, *sandboxBackendRecorder, *bool) {
	t.Helper()
	store := &sandboxTaskStore{rows: map[int64]*db.Task{7: {ID: 7, ExplorationID: 70}, 8: {ID: 8, ExplorationID: 80}}}
	backend := &sandboxBackendRecorder{created: make(map[int64]int)}
	admit := true
	c, err := newTaskSandboxController(store, backend, func(string) (func(), bool) {
		if !admit {
			return nil, false
		}
		return func() {}, true
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, store, backend, &admit
}

func TestTaskSandboxRejectsUnverifiedIdentityAndLifecycle(t *testing.T) {
	c, store, backend, admit := newSandboxTestController(t)
	ctx := context.Background()
	valid := agent.RunInfo{TaskID: 7, ExplorationID: 70}
	for _, info := range []agent.RunInfo{
		{}, {TaskID: 7}, {ExplorationID: 70},
		{TaskID: 7, ExplorationID: 80}, {TaskID: 9, ExplorationID: 90},
		{TaskID: 7, ExplorationID: 70, SessionID: "chat"},
	} {
		if _, err := c.Run(ctx, info, "true"); err == nil {
			t.Fatalf("accepted unverified identity %+v", info)
		}
	}
	for _, mutate := range []func(*db.Task){
		func(row *db.Task) { row.Paused = true },
		func(row *db.Task) { row.Queued = true },
		func(row *db.Task) { row.Status = "done" },
		func(row *db.Task) { row.ExplorationID = 71 },
	} {
		store.mu.Lock()
		store.rows[7] = &db.Task{ID: 7, ExplorationID: 70}
		mutate(store.rows[7])
		store.mu.Unlock()
		if _, err := c.Run(ctx, valid, "true"); err == nil {
			t.Fatal("accepted task after authority changed")
		}
	}
	store.mu.Lock()
	store.rows[7] = &db.Task{ID: 7, ExplorationID: 70}
	store.err = errors.New("database unavailable")
	store.mu.Unlock()
	if _, err := c.Run(ctx, valid, "true"); err == nil {
		t.Fatal("accepted task while database was unavailable")
	}
	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	*admit = false
	if _, err := c.Run(ctx, valid, "true"); err == nil {
		t.Fatal("accepted task after deletion barrier closed")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.created) != 0 || len(backend.ran) != 0 {
		t.Fatalf("denied task reached broker: creates=%v runs=%v", backend.created, backend.ran)
	}
}

func TestTaskSandboxBindsHandleAndRechecksBeforeReuse(t *testing.T) {
	c, store, backend, _ := newSandboxTestController(t)
	ctx := context.Background()
	info := agent.RunInfo{TaskID: 7, ExplorationID: 70}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if output, err := c.Run(ctx, info, "true"); err != nil || output != "handle-7" {
				t.Errorf("run: %q %v", output, err)
			}
		}()
	}
	wg.Wait()
	if digest, err := c.PutArtifact(ctx, info, "fixture", []byte("synthetic")); err != nil || digest != "digest" {
		t.Fatalf("artifact: %q %v", digest, err)
	}
	if output, err := c.RunInput(ctx, info, "cat", []byte("stdin")); err != nil || output != "handle-7" {
		t.Fatalf("stdin run: %q %v", output, err)
	}
	if output, err := c.Run(ctx, agent.RunInfo{TaskID: 8, ExplorationID: 80}, "true"); err != nil || output != "handle-8" {
		t.Fatalf("other task: %q %v", output, err)
	}
	store.mu.Lock()
	store.rows[7] = &db.Task{ID: 7, ExplorationID: 71}
	store.mu.Unlock()
	if _, err := c.Run(ctx, agent.RunInfo{TaskID: 7, ExplorationID: 71}, "true"); err == nil {
		t.Fatal("reused a handle after task exploration changed")
	}
	store.mu.Lock()
	delete(store.rows, 7)
	store.mu.Unlock()
	if _, err := c.Run(ctx, info, "true"); err == nil {
		t.Fatal("reused a handle after task deletion")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.created[7] != 1 || backend.created[8] != 1 || len(backend.ran) != 14 || len(backend.put) != 1 || backend.put[0] != "handle-7:fixture" {
		t.Fatalf("incorrect campaign binding: creates=%v runs=%v put=%v", backend.created, backend.ran, backend.put)
	}
}

func TestTaskSandboxRemovalRetainsFailedCleanupForRetry(t *testing.T) {
	c, _, backend, _ := newSandboxTestController(t)
	ctx := context.Background()
	if _, err := c.Run(ctx, agent.RunInfo{TaskID: 7, ExplorationID: 70}, "true"); err != nil {
		t.Fatal(err)
	}
	backend.removeFail = true
	if err := c.RemoveTask(ctx, 7); err == nil {
		t.Fatal("failed cleanup was reported as successful")
	}
	backend.removeFail = false
	if err := c.RemoveTask(ctx, 7); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.removed) != 1 || backend.removed[0] != "handle-7" {
		t.Fatalf("unexpected sandbox removal: %v", backend.removed)
	}
}

func TestTaskSandboxRechecksLifecycleAfterCreation(t *testing.T) {
	c, store, backend, _ := newSandboxTestController(t)
	backend.onCreate = func() {
		store.mu.Lock()
		store.rows[7].Paused = true
		store.mu.Unlock()
	}
	if _, err := c.Run(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 70}, "true"); err == nil {
		t.Fatal("ran a command after task paused during sandbox creation")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 0 {
		t.Fatalf("paused task reached broker execution: %v", backend.ran)
	}
	if len(backend.removed) != 1 || backend.removed[0] != "handle-7" {
		t.Fatalf("unadmitted sandbox was retained: %v", backend.removed)
	}
}

func TestTaskSandboxRetriesFailedRetirementBeforeReuse(t *testing.T) {
	c, store, backend, _ := newSandboxTestController(t)
	info := agent.RunInfo{TaskID: 7, ExplorationID: 70}
	backend.removeFail = true
	backend.onCreate = func() {
		store.mu.Lock()
		store.rows[7].Paused = true
		store.mu.Unlock()
	}
	if _, err := c.Run(context.Background(), info, "first"); err == nil {
		t.Fatal("ran a command after task paused during creation")
	}
	store.mu.Lock()
	store.rows[7].Paused = false
	store.mu.Unlock()
	if _, err := c.Run(context.Background(), info, "second"); err == nil {
		t.Fatal("reused a sandbox whose retirement failed")
	}
	backend.mu.Lock()
	if backend.created[7] != 1 || len(backend.ran) != 0 {
		backend.mu.Unlock()
		t.Fatal("failed retirement allowed another create or execution")
	}
	backend.removeFail = false
	backend.onCreate = nil
	backend.mu.Unlock()
	if _, err := c.Run(context.Background(), info, "third"); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.created[7] != 2 || len(backend.removed) != 1 || len(backend.ran) != 1 || backend.ran[0] != "handle-7:third" {
		t.Fatalf("retirement retry did not create a fresh sandbox: creates=%v removed=%v runs=%v", backend.created, backend.removed, backend.ran)
	}
}

func TestTaskSandboxRetiresAfterCreateContextCancellation(t *testing.T) {
	c, _, backend, _ := newSandboxTestController(t)
	ctx, cancel := context.WithCancel(context.Background())
	backend.onCreate = cancel
	_, err := c.Run(ctx, agent.RunInfo{TaskID: 7, ExplorationID: 70}, "never")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled creation: %v", err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 0 || len(backend.removed) != 1 || backend.removed[0] != "handle-7" {
		t.Fatalf("cancelled creation left a sandbox: runs=%v removed=%v", backend.ran, backend.removed)
	}
}

func TestTaskSandboxReleasesTerminalCapacityBeforeNewTask(t *testing.T) {
	c, store, backend, _ := newSandboxTestController(t)
	ctx := context.Background()
	first := agent.RunInfo{TaskID: 7, ExplorationID: 70}
	second := agent.RunInfo{TaskID: 8, ExplorationID: 80}
	if _, err := c.Run(ctx, first, "first"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.rows[7].Status = "done"
	store.mu.Unlock()
	if _, err := c.Run(ctx, second, "second"); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	if len(backend.removed) != 1 || backend.removed[0] != "handle-7" || backend.created[8] != 1 {
		backend.mu.Unlock()
		t.Fatalf("terminal sandbox retained: removed=%v created=%v", backend.removed, backend.created)
	}
	backend.mu.Unlock()
	store.mu.Lock()
	store.rows[7].Status = "running"
	store.mu.Unlock()
	if _, err := c.Run(ctx, first, "revived"); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.created[7] != 2 || len(backend.removed) != 1 {
		t.Fatalf("revived task did not receive a fresh sandbox: created=%v removed=%v", backend.created, backend.removed)
	}
}

func TestTaskSandboxTerminalCleanupFailureBlocksNewCreate(t *testing.T) {
	c, store, backend, _ := newSandboxTestController(t)
	ctx := context.Background()
	if _, err := c.Run(ctx, agent.RunInfo{TaskID: 7, ExplorationID: 70}, "first"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.rows[7].Status = "done"
	store.mu.Unlock()
	backend.mu.Lock()
	backend.removeFail = true
	backend.mu.Unlock()
	second := agent.RunInfo{TaskID: 8, ExplorationID: 80}
	if _, err := c.Run(ctx, second, "blocked"); err == nil {
		t.Fatal("created a sandbox after terminal cleanup failed")
	}
	backend.mu.Lock()
	if backend.created[8] != 0 {
		backend.mu.Unlock()
		t.Fatal("new task reached broker create despite failed retirement")
	}
	backend.removeFail = false
	backend.mu.Unlock()
	if _, err := c.Run(ctx, second, "retry"); err != nil {
		t.Fatal(err)
	}
}

func TestTaskSandboxDelayedTerminalCleanupCannotRetireRevivedRun(t *testing.T) {
	c, store, backend, _ := newSandboxTestController(t)
	info := agent.RunInfo{TaskID: 7, ExplorationID: 70}
	ctx := context.Background()
	if _, err := c.Run(ctx, info, "first"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.rows[7].Status = "done"
	store.mu.Unlock()
	if err := c.RetireTerminalTask(ctx, 7); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.rows[7].Status = "running"
	store.mu.Unlock()
	if _, err := c.Run(ctx, info, "revived"); err != nil {
		t.Fatal(err)
	}
	// Model a terminal callback that was queued for the previous run but only
	// executes after the task has received a fresh sandbox.
	if err := c.RetireTerminalTask(ctx, 7); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.created[7] != 2 || len(backend.removed) != 1 || backend.removed[0] != "handle-7" || len(backend.ran) != 2 {
		t.Fatalf("late terminal cleanup removed a live run: created=%v removed=%v ran=%v", backend.created, backend.removed, backend.ran)
	}
}
