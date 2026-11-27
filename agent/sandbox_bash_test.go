package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

type recordingTaskShell struct {
	calls int
	info  RunInfo
	cmd   string
}

func (r *recordingTaskShell) Run(ctx context.Context, info RunInfo, command string) (string, error) {
	r.calls++
	r.info = info
	r.cmd = command
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 31*time.Second {
		return "", context.DeadlineExceeded
	}
	return "sandbox output", nil
}

func TestTaskBashRoutesWithExplicitIdentity(t *testing.T) {
	runner := &recordingTaskShell{}
	var bash actool.CoreTool
	for _, candidate := range defaultToolsWithTaskShell(t.TempDir(), runner) {
		if candidate.Name() == "Bash" {
			bash = candidate
			break
		}
	}
	if bash == nil {
		t.Fatal("Bash tool missing")
	}
	if _, exposed := bash.InputSchema()["properties"].(map[string]any)["run_in_background"]; exposed {
		t.Fatal("sandbox Bash advertised unsupported background execution")
	}
	info := RunInfo{TaskID: 41, ExplorationID: 73, IntentID: 11}
	ctx := WithRunInfo(context.Background(), info)
	result, err := bash.Call(ctx, json.RawMessage(`{"command":"printf hello"}`), &actool.ToolContext{})
	if err != nil || !strings.Contains(result.Flatten(), "sandbox output") {
		t.Fatalf("Bash result = %q, %v", result.Flatten(), err)
	}
	if runner.calls != 1 || runner.info != info || runner.cmd != "printf hello" {
		t.Fatalf("runner calls=%d info=%+v command=%q", runner.calls, runner.info, runner.cmd)
	}
}

func TestTaskBashFailsClosedWithoutIdentityOrUnsupportedMode(t *testing.T) {
	runner := &recordingTaskShell{}
	bash := &sandboxBashTool{runner: runner}
	cases := []struct {
		name  string
		ctx   context.Context
		input string
	}{
		{"missing task", context.Background(), `{"command":"true"}`},
		{"session", WithRunInfo(context.Background(), RunInfo{TaskID: 41, ExplorationID: 73, SessionID: "chat"}), `{"command":"true"}`},
		{"background", WithRunInfo(context.Background(), RunInfo{TaskID: 41, ExplorationID: 73}), `{"command":"true","run_in_background":true}`},
		{"long timeout", WithRunInfo(context.Background(), RunInfo{TaskID: 41, ExplorationID: 73}), `{"command":"true","timeout_ms":30001}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := bash.Call(tc.ctx, json.RawMessage(tc.input), nil)
			if err != nil || !strings.Contains(result.Flatten(), "Error:") {
				t.Fatalf("Bash result = %q, %v", result.Flatten(), err)
			}
		})
	}
	if runner.calls != 0 {
		t.Fatalf("rejected Bash calls reached runner: %d", runner.calls)
	}
}
