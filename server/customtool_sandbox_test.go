package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestCommandToolUsesAuthorizedTaskSandbox(t *testing.T) {
	controller, _, backend, _ := newSandboxTestController(t)
	s := &Server{taskSandboxes: controller}
	input := json.RawMessage(`{"command":"printf sandbox"}`)
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 70})
	result, err := s.runCommandTool(ctx, "fixture", input, nil, nil)
	if err != nil || !strings.Contains(result.Flatten(), "handle-7") {
		t.Fatalf("sandbox command result = %q, %v", result.Flatten(), err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 1 || backend.ran[0] != "handle-7:printf sandbox" {
		t.Fatalf("command reached wrong executor: %v", backend.ran)
	}
}

func TestCommandToolSandboxDoesNotFallBackToHost(t *testing.T) {
	controller, _, backend, _ := newSandboxTestController(t)
	s := &Server{taskSandboxes: controller}
	for _, tc := range []struct {
		name string
		ctx  context.Context
		spec string
	}{
		{"missing identity", context.Background(), `{"command":"printf host"}`},
		{"wrong exploration", agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 80}), `{"command":"printf host"}`},
		{"unsupported timeout", agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 70}), `{"command":"printf host","timeout_ms":30001}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := s.runCommandTool(tc.ctx, "fixture", json.RawMessage(tc.spec), nil, nil)
			if err != nil || !strings.Contains(result.Flatten(), "sandbox") || strings.Contains(result.Flatten(), "host") {
				t.Fatalf("denied sandbox command = %q, %v", result.Flatten(), err)
			}
		})
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 0 {
		t.Fatalf("denied command reached broker: %v", backend.ran)
	}
}

func TestCommandToolKeepsConversationPath(t *testing.T) {
	controller, _, backend, _ := newSandboxTestController(t)
	s := &Server{taskSandboxes: controller}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: "synthetic-chat"})
	result, err := s.runCommandTool(ctx, "fixture", json.RawMessage(`{"command":"echo CHAT_OK"}`), nil, nil)
	if err != nil || !strings.Contains(result.Flatten(), "CHAT_OK") {
		t.Fatalf("conversation command result = %q, %v", result.Flatten(), err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 0 {
		t.Fatalf("conversation command used task broker: %v", backend.ran)
	}
}

func TestCommandToolPreservesSandboxExitOutput(t *testing.T) {
	controller, _, backend, _ := newSandboxTestController(t)
	backend.exitCode = 7
	s := &Server{taskSandboxes: controller}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 70})
	result, err := s.runCommandTool(ctx, "fixture", json.RawMessage(`{"command":"exit 7"}`), nil, nil)
	if err != nil || !strings.Contains(result.Flatten(), "sandbox diagnostic") || !strings.Contains(result.Flatten(), "[exit code 7]") {
		t.Fatalf("nonzero sandbox command = %q, %v", result.Flatten(), err)
	}
}
