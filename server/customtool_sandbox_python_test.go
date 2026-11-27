package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
)

func TestScriptToolUsesTaskSandboxWithParameters(t *testing.T) {
	controller, _, backend, _ := newSandboxTestController(t)
	s := &Server{taskSandboxes: controller}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 70})
	spec := scriptExec{Code: "print('sandbox')"}
	params := map[string]any{"target": "example.test", "port": float64(8080)}
	result, err := s.runScriptToolWithInterpreter(ctx, "fixture", spec, params, nil, "python3")
	if err != nil || !strings.Contains(result.Flatten(), "handle-7") {
		t.Fatalf("script result = %q, %v", result.Flatten(), err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 1 || !strings.Contains(backend.lastCommand, "python3") || !strings.Contains(backend.lastCommand, "runpy.run_path") {
		t.Fatalf("script did not reach sandbox: %v", backend.ran)
	}
	var payload struct {
		Code   string            `json:"code"`
		Params map[string]any    `json:"params"`
		Env    map[string]string `json:"env"`
	}
	if err := json.Unmarshal(backend.lastInput, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != spec.Code || payload.Env["TOOL_TARGET"] != "example.test" || payload.Env["TOOL_PORT"] != "8080" {
		t.Fatalf("sandbox script envelope = %+v", payload)
	}
}

func TestScriptToolSandboxRejectsUnverifiedRun(t *testing.T) {
	controller, _, backend, _ := newSandboxTestController(t)
	s := &Server{taskSandboxes: controller}
	for _, tc := range []struct {
		ctx  context.Context
		spec scriptExec
	}{
		{context.Background(), scriptExec{Code: "print('host')"}},
		{agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 80}), scriptExec{Code: "print('host')"}},
		{agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 70}), scriptExec{Code: "print('host')", TimeoutMs: 30001}},
	} {
		result, err := s.runScriptToolWithInterpreter(tc.ctx, "fixture", tc.spec, nil, nil, "python3")
		if err != nil || !strings.Contains(result.Flatten(), "sandbox") {
			t.Fatalf("denied script result = %q, %v", result.Flatten(), err)
		}
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 0 {
		t.Fatalf("denied script reached broker: %v", backend.ran)
	}
}

func TestScriptToolPreservesSandboxExitOutput(t *testing.T) {
	controller, _, backend, _ := newSandboxTestController(t)
	backend.exitCode = 7
	s := &Server{taskSandboxes: controller}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 7, ExplorationID: 70})
	result, err := s.runScriptToolWithInterpreter(ctx, "fixture", scriptExec{Code: "raise SystemExit(7)"}, nil, nil, "python3")
	if err != nil || !strings.Contains(result.Flatten(), "sandbox diagnostic") || !strings.Contains(result.Flatten(), "[exit code 7]") {
		t.Fatalf("nonzero sandbox script = %q, %v", result.Flatten(), err)
	}
}

type localPythonRunner struct{ dir string }

func (r localPythonRunner) RunInput(ctx context.Context, _ agent.RunInfo, command string, input []byte) (string, error) {
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	cmd.Dir = r.dir
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestSandboxPythonBootstrapPreservesStdinAndEnvironment(t *testing.T) {
	interp, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	dir := t.TempDir()
	code := `import json, os, sys
params = json.load(sys.stdin)
print(params["target"])
print(os.environ["TOOL_TARGET"])
print(os.path.isfile(__file__))
os.chdir("/")
`
	out, err := execPythonSandbox(context.Background(), localPythonRunner{dir: dir}, agent.RunInfo{TaskID: 7, ExplorationID: 70}, interp, code, map[string]any{"target": "example.test"}, 5*time.Second)
	if err != nil || !strings.Contains(out, "example.test\nexample.test\nTrue") {
		t.Fatalf("sandbox Python output = %q, %v", out, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("sandbox script was not removed: %v, %v", entries, err)
	}
}

func TestScriptToolKeepsConversationPath(t *testing.T) {
	interp, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	controller, _, backend, _ := newSandboxTestController(t)
	s := &Server{m: &Manager{dir: t.TempDir()}, taskSandboxes: controller}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionID: "synthetic-chat"})
	result, err := s.runScriptToolWithInterpreter(ctx, "fixture", scriptExec{Code: "print('CHAT_SCRIPT_OK')"}, nil, nil, interp)
	if err != nil || !strings.Contains(result.Flatten(), "CHAT_SCRIPT_OK") {
		t.Fatalf("conversation script result = %q, %v", result.Flatten(), err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.ran) != 0 {
		t.Fatalf("conversation script used task broker: %v", backend.ran)
	}
}

func TestSandboxPythonEnvelopeRejectsOversize(t *testing.T) {
	if _, err := sandboxPythonEnvelope(strings.Repeat("x", maxSandboxScriptEnvelope), nil); err == nil {
		t.Fatal("oversized sandbox script was accepted")
	}
}
