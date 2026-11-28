package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sandboxbroker"
	actool "github.com/Autumn-27/norma/tool"
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
var _ agent.TaskFileRunner = (*taskSandboxController)(nil)
var _ agent.TaskOutputStorer = (*taskSandboxController)(nil)

type taskSandboxStore interface {
	GetTask(int64) (*db.Task, error)
}

type taskSandboxEntry struct {
	mu            sync.Mutex
	handle        string
	expID         int64
	closed        bool
	retirePending bool
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
	// Finished tasks must release broker capacity before a new task creates a
	// sandbox. Do this before locking the current entry so concurrent new tasks
	// cannot wait on one another's entry locks.
	c.mu.Lock()
	current := c.entries[info.TaskID]
	c.mu.Unlock()
	needsCapacity := current == nil
	if current != nil {
		current.mu.Lock()
		needsCapacity = current.handle == ""
		current.mu.Unlock()
	}
	if needsCapacity {
		if err := c.retireTerminal(ctx, info.TaskID); err != nil {
			return "", err
		}
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
	if entry.retirePending {
		if err := c.retireCreated(entry); err != nil {
			return "", err
		}
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
	created := false
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
		created = true
	}
	if _, err := c.authorizedTask(info); err != nil {
		if created {
			return "", errors.Join(err, c.retireCreated(entry))
		}
		return "", err
	}
	if err := ctx.Err(); err != nil {
		if created {
			return "", errors.Join(err, c.retireCreated(entry))
		}
		return "", err
	}
	return fn(entry.handle)
}

// retireTerminal frees capacity held by settled tasks while preserving active
// and paused sandboxes. A failed lookup or removal leaves the handle tracked
// and prevents a new creation with uncertain ownership.
func (c *taskSandboxController) retireTerminal(ctx context.Context, except int64) error {
	c.mu.Lock()
	ids := make([]int64, 0, len(c.entries))
	for id := range c.entries {
		if id != except {
			ids = append(ids, id)
		}
	}
	c.mu.Unlock()
	for _, id := range ids {
		if err := c.RetireTerminalTask(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// RetireTerminalTask removes only the handle observed for a terminal, deleted
// or exploration-changed task. A delayed terminal callback cannot remove a
// freshly created sandbox after the task has been revived.
func (c *taskSandboxController) RetireTerminalTask(ctx context.Context, id int64) error {
	if c == nil || id <= 0 {
		return errors.New("invalid terminal task sandbox retirement")
	}
	c.mu.Lock()
	entry := c.entries[id]
	c.mu.Unlock()
	if entry == nil {
		return nil
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.closed || entry.handle == "" {
		return nil
	}
	row, err := c.store.GetTask(id)
	if err != nil {
		return fmt.Errorf("check task sandbox retirement: %w", err)
	}
	if row != nil && row.ExplorationID == entry.expID && !db.IsTerminal(row.Status) {
		return nil
	}
	if err := c.broker.Remove(ctx, entry.handle); err != nil {
		return fmt.Errorf("retire terminal task sandbox: %w", err)
	}
	entry.closed = true
	c.mu.Lock()
	if c.entries[id] == entry {
		delete(c.entries, id)
	}
	c.mu.Unlock()
	return nil
}

// retireCreated removes a sandbox that was created but never admitted to run.
// Cleanup uses its own deadline because the caller's context may already be
// cancelled. A failed removal blocks reuse until it can be retried.
func (c *taskSandboxController) retireCreated(entry *taskSandboxEntry) error {
	if entry.handle == "" {
		entry.retirePending = false
		return nil
	}
	entry.retirePending = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.broker.Remove(ctx, entry.handle); err != nil {
		return fmt.Errorf("retire unadmitted task sandbox: %w", err)
	}
	entry.handle = ""
	entry.retirePending = false
	return nil
}

func (c *taskSandboxController) Run(ctx context.Context, info agent.RunInfo, command string) (string, error) {
	wrapped, err := taskSandboxCommand(info, command)
	if err != nil {
		return "", err
	}
	return c.operate(ctx, info, func(handle string) (string, error) { return c.broker.Run(ctx, handle, wrapped) })
}

func (c *taskSandboxController) RunInput(ctx context.Context, info agent.RunInfo, command string, input []byte) (string, error) {
	wrapped, err := taskSandboxCommand(info, command)
	if err != nil {
		return "", err
	}
	return c.operate(ctx, info, func(handle string) (string, error) { return c.broker.RunInput(ctx, handle, wrapped, input) })
}

func taskSandboxRunDir(info agent.RunInfo) (string, error) {
	if info.IntentID < 0 {
		return "", errors.New("invalid task sandbox intent")
	}
	if info.IntentID == 0 {
		return "main", nil
	}
	return "i" + strconv.FormatInt(info.IntentID, 10), nil
}

func taskSandboxCommand(info agent.RunInfo, command string) (string, error) {
	if command == "" {
		return "", errors.New("empty task sandbox command")
	}
	dir, err := taskSandboxRunDir(info)
	if err != nil {
		return "", err
	}
	path := "/campaign/" + dir
	// Keep the caller's shell operators inside a child shell. Otherwise a
	// command containing "||" could run from /campaign after mkdir/cd fails.
	return "mkdir -p " + path + " && cd " + path + " && /bin/sh -c " + shellQuote(command), nil
}

func (c *taskSandboxController) PutArtifact(ctx context.Context, info agent.RunInfo, name string, data []byte) (string, error) {
	return c.operate(ctx, info, func(handle string) (string, error) { return c.broker.PutArtifact(ctx, handle, name, data) })
}

// StoreOutput keeps long shell output in a random, immutable file on the
// campaign-private artifact tmpfs. A model cannot choose its name or handle.
func (c *taskSandboxController) StoreOutput(ctx context.Context, info agent.RunInfo, data []byte) (string, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return "", errors.New("invalid task sandbox output size")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	name := "output-" + hex.EncodeToString(nonce[:]) + ".txt"
	if _, err := c.PutArtifact(ctx, info, name, data); err != nil {
		return "", err
	}
	return "/artifacts/" + name, nil
}

func (c *taskSandboxController) RunFileTool(ctx context.Context, info agent.RunInfo, req agent.SandboxFileToolRequest) (actool.Result, error) {
	if req.Name == "" || len(req.Input) == 0 || req.WorkingDir == "" || req.MaxOutputChars < 1 {
		return actool.Result{}, errors.New("invalid task sandbox file request")
	}
	dir, err := taskSandboxRunDir(info)
	if err != nil {
		return actool.Result{}, err
	}
	req.SandboxDir = dir
	if req.MaxOutputChars > 512<<10 {
		req.MaxOutputChars = 512 << 10
	}
	body, err := json.Marshal(req)
	if err != nil || len(body) > 1<<20 {
		return actool.Result{}, errors.New("task sandbox file request exceeds stdin limit")
	}
	output, err := c.RunInput(ctx, info, agent.SandboxFileToolCommand, body)
	if err != nil {
		return actool.Result{}, err
	}
	var result agent.SandboxFileToolResponse
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		return actool.Result{}, errors.New("invalid task sandbox file response")
	}
	if result.IsError {
		return actool.Errorf(result.Text), nil
	}
	return actool.Text(result.Text), nil
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
