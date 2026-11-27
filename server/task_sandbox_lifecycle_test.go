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
