package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestTaskDeleteRemovesBoundSandboxAfterCommit(t *testing.T) {
	for _, failRemove := range []bool{false, true} {
		name := "successful removal"
		if failRemove {
			name = "cleanup warning and retry"
		}
		t.Run(name, func(t *testing.T) {
			m, err := NewManager(t.TempDir(), "")
			if err != nil {
				db.SkipPGUnavailable(t, err)
			}
			defer m.Close()
			task, err := m.CreateTask("sandbox delete fixture", "verify teardown", nil, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
			s := &Server{m: m, engine: NewEngine(m)}
			backend := &sandboxBackendRecorder{created: make(map[int64]int), removeFail: failRemove}
			controller, err := s.newTaskSandboxController(backend)
			if err != nil {
				t.Fatal(err)
			}
			s.taskSandboxes = controller
			if _, err := controller.Run(context.Background(), agent.RunInfo{TaskID: mustTaskID(t, task.ID), ExplorationID: task.ExpID}, "true"); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodDelete, "/api/tasks/"+task.ID, strings.NewReader("{}"))
			req.SetPathValue("id", task.ID)
			response := httptest.NewRecorder()
			s.pgDeleteTask(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("delete status=%d body=%s", response.Code, response.Body.String())
			}
			var result DeleteTaskResult
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Deleted != task.ID || (result.CleanupWarning != "") != failRemove {
				t.Fatalf("unexpected deletion result: %+v", result)
			}
			if row, err := m.pg.GetTask(mustTaskID(t, task.ID)); err != nil || row != nil {
				t.Fatalf("task row survived committed delete: %+v %v", row, err)
			}
			if failRemove {
				backend.removeFail = false
				if err := controller.RemoveTask(context.Background(), mustTaskID(t, task.ID)); err != nil {
					t.Fatalf("retry sandbox cleanup: %v", err)
				}
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			if len(backend.removed) != 1 {
				t.Fatalf("sandbox cleanup count=%d, want 1", len(backend.removed))
			}
		})
	}
}

func TestTerminalTaskRevivalRetiresPreviousSandbox(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	defer restoreConcurrencySetting(t, m)()
	if err := m.SetConcurrency(false, defaultConcurrencyLimit); err != nil {
		t.Fatal(err)
	}
	task, err := m.CreateTask("sandbox revival fixture", "fresh private state", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) }()
	s := newAdmissionTestServer(m, nil)
	backend := &sandboxBackendRecorder{created: make(map[int64]int)}
	controller, err := s.newTaskSandboxController(backend)
	if err != nil {
		t.Fatal(err)
	}
	s.taskSandboxes = controller
	info := agent.RunInfo{TaskID: mustTaskID(t, task.ID), ExplorationID: task.ExpID}
	if _, err := controller.Run(context.Background(), info, "first run"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetTaskStatus(task.ID, "done"); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	backend.removeFail = true
	backend.mu.Unlock()
	if _, err := s.admitTask(task, "resume"); err == nil {
		t.Fatal("revived a terminal task whose previous sandbox could not be removed")
	}
	if state := task.lifecycleSnapshot(); state.Status != "done" {
		t.Fatalf("failed cleanup changed task status: %+v", state)
	}
	backend.mu.Lock()
	backend.removeFail = false
	backend.mu.Unlock()
	if _, err := s.admitTask(task, "resume"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Run(context.Background(), info, "second run"); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.created[info.TaskID] != 2 || len(backend.removed) != 1 {
		t.Fatalf("revival reused old sandbox: created=%v removed=%v", backend.created, backend.removed)
	}
}
