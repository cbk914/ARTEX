package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sandboxbroker"
)

// taskSandboxBackend is the trusted control-plane client, never an agent tool.
// Its opaque handles must not be returned to a model or accepted from a request.
type taskSandboxBackend interface {
	Create(context.Context, int64) (string, error)
	Run(context.Context, string, string) (string, error)
	RunInput(context.Context, string, string, []byte) (string, error)
	PutArtifact(context.Context, string, string, []byte) (string, error)
	Remove(context.Context, string) error
}

var _ taskSandboxBackend = (*sandboxbroker.Client)(nil)

type taskSandboxStore interface {
	GetTask(int64) (*db.Task, error)
}

type taskSandboxEntry struct {
	mu     sync.Mutex
	handle string
	expID  int64
	closed bool
}

// taskSandboxController binds a live task and its exploration to one broker
// handle. It is a control-plane primitive; ARTEX tool paths are not migrated to
// it yet. Admission must use Engine.beginTaskOperation/decInflight so a task
// deletion cannot race a broker operation.
type taskSandboxController struct {
	store   taskSandboxStore
	broker  taskSandboxBackend
	admit   func(string) (func(), bool)
	mu      sync.Mutex
	entries map[int64]*taskSandboxEntry
}

func newTaskSandboxController(store taskSandboxStore, broker taskSandboxBackend, admit func(string) (func(), bool)) (*taskSandboxController, error) {
	if store == nil || broker == nil || admit == nil {
		return nil, errors.New("task sandbox requires a task store, broker and deletion barrier")
	}
	return &taskSandboxController{store: store, broker: broker, admit: admit, entries: make(map[int64]*taskSandboxEntry)}, nil
}

// newTaskSandboxController connects the controller to the real task deletion
// barrier. The caller must supply a client for a verified root-only socket.
func (s *Server) newTaskSandboxController(broker taskSandboxBackend) (*taskSandboxController, error) {
	if s == nil || s.m == nil || s.m.pg == nil || s.engine == nil {
		return nil, errors.New("task sandbox requires an initialized server")
	}
	return newTaskSandboxController(s.m.pg, broker, func(id string) (func(), bool) {
		if !s.engine.beginTaskOperation(id) {
			return nil, false
		}
		return func() { s.engine.decInflight(id) }, true
	})
}

func (c *taskSandboxController) authorizedTask(info agent.RunInfo) (*db.Task, error) {
	if info.TaskID <= 0 || info.ExplorationID <= 0 || info.SessionID != "" {
		return nil, errors.New("task sandbox requires explicit task and exploration identity")
	}
	row, err := c.store.GetTask(info.TaskID)
	if err != nil {
		return nil, fmt.Errorf("verify task sandbox authority: %w", err)
	}
	if row == nil || row.ID != info.TaskID || row.ExplorationID != info.ExplorationID || row.Paused || row.Queued || db.IsTerminal(row.Status) {
		return nil, errors.New("task sandbox authority denied")
	}
	return row, nil
}

func (c *taskSandboxController) operate(ctx context.Context, info agent.RunInfo, fn func(string) (string, error)) (string, error) {
	if c == nil || c.store == nil || c.broker == nil || c.admit == nil {
		return "", errors.New("task sandbox unavailable")
	}
	if info.TaskID <= 0 || info.ExplorationID <= 0 || info.SessionID != "" {
		return "", errors.New("task sandbox requires explicit task and exploration identity")
	}
	id := strconv.FormatInt(info.TaskID, 10)
	release, ok := c.admit(id)
	if !ok || release == nil {
		return "", errors.New("task sandbox operation not admitted")
	}
	defer release()
	if _, err := c.authorizedTask(info); err != nil {
		return "", err
	}
	c.mu.Lock()
	entry := c.entries[info.TaskID]
	if entry == nil {
		entry = &taskSandboxEntry{}
		c.entries[info.TaskID] = entry
	}
	c.mu.Unlock()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.closed {
		return "", errors.New("task sandbox was removed")
	}
	if entry.expID != 0 && entry.expID != info.ExplorationID {
		return "", errors.New("task sandbox exploration changed")
	}
	// Recheck after waiting for an in-flight operation. A pause or task-status
	// transition must not reuse a previously admitted handle.
	if _, err := c.authorizedTask(info); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if entry.handle == "" {
		entry.expID = info.ExplorationID
		handle, err := c.broker.Create(ctx, info.TaskID)
		if err != nil {
			return "", err
		}
		if handle == "" {
			return "", errors.New("broker returned empty sandbox handle")
		}
		entry.handle = handle
	}
	if _, err := c.authorizedTask(info); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return fn(entry.handle)
}

func (c *taskSandboxController) Run(ctx context.Context, info agent.RunInfo, command string) (string, error) {
	return c.operate(ctx, info, func(handle string) (string, error) { return c.broker.Run(ctx, handle, command) })
}

func (c *taskSandboxController) RunInput(ctx context.Context, info agent.RunInfo, command string, input []byte) (string, error) {
	return c.operate(ctx, info, func(handle string) (string, error) { return c.broker.RunInput(ctx, handle, command, input) })
}

func (c *taskSandboxController) PutArtifact(ctx context.Context, info agent.RunInfo, name string, data []byte) (string, error) {
	return c.operate(ctx, info, func(handle string) (string, error) { return c.broker.PutArtifact(ctx, handle, name, data) })
}

// RemoveTask is called after the task deletion barrier has drained operations.
// A failed removal retains the handle so cleanup can be retried explicitly.
func (c *taskSandboxController) RemoveTask(ctx context.Context, taskID int64) error {
	if c == nil || taskID <= 0 {
		return errors.New("invalid task sandbox removal")
	}
	c.mu.Lock()
	entry := c.entries[taskID]
	c.mu.Unlock()
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.closed {
		return nil
	}
	if entry.handle != "" {
		if err := c.broker.Remove(ctx, entry.handle); err != nil {
			return err
		}
	}
	entry.closed = true
	c.mu.Lock()
	if c.entries[taskID] == entry {
		delete(c.entries, taskID)
	}
	c.mu.Unlock()
	return nil
}

// removeTaskSandbox runs only after the task row has been deleted and its
// in-process agents have stopped. A disconnected HTTP client cannot cancel
// this bounded cleanup. A failure is returned as an auditable cleanup warning.
func (s *Server) removeTaskSandbox(taskID string) error {
	if s.taskSandboxes == nil {
		return nil
	}
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return errors.New("invalid task sandbox cleanup identity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.taskSandboxes.RemoveTask(ctx, id); err != nil {
		return fmt.Errorf("remove task sandbox: %w", err)
	}
	return nil
}
