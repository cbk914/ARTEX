package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/sandboxbroker"
	actool "github.com/Autumn-27/norma/tool"
)

type recordingTaskShell struct {
	calls    int
	info     RunInfo
	cmd      string
	exitCode int
	output   string
	stored   []byte
}

func (r *recordingTaskShell) Run(ctx context.Context, info RunInfo, command string) (string, error) {
	r.calls++
	r.info = info
	r.cmd = command
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 31*time.Second {
		return "", context.DeadlineExceeded
	}
	if r.exitCode != 0 {
		return "sandbox diagnostic\n", &sandboxbroker.CommandExitError{Code: r.exitCode}
	}
	if r.output != "" {
		return r.output, nil
	}
	return "sandbox output", nil
}

func (r *recordingTaskShell) StoreOutput(_ context.Context, _ RunInfo, data []byte) (string, error) {
	r.stored = append([]byte(nil), data...)
	return "/artifacts/private-output.txt", nil
}

type shellWithoutOutputStore struct{}

func (shellWithoutOutputStore) Run(_ context.Context, _ RunInfo, _ string) (string, error) {
	return strings.Repeat("s", 100), nil
}

func TestTaskBashLongOutputStaysInCampaignSandbox(t *testing.T) {
	runner := &recordingTaskShell{output: strings.Repeat("private", 20)}
	bash := &sandboxBashTool{runner: runner}
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 41, ExplorationID: 73})
	result, err := bash.Call(ctx, json.RawMessage(`{"command":"printf private"}`), &actool.ToolContext{MaxOutputChars: 20, OutputDir: t.TempDir()})
	if err != nil || result.IsError || !strings.Contains(result.Flatten(), "/artifacts/private-output.txt") || string(runner.stored) != runner.output {
		t.Fatalf("private output result=%q stored=%d err=%v", result.Flatten(), len(runner.stored), err)
	}
	missing := &sandboxBashTool{runner: shellWithoutOutputStore{}}
	result, err = missing.Call(ctx, json.RawMessage(`{"command":"printf private"}`), &actool.ToolContext{MaxOutputChars: 20, OutputDir: t.TempDir()})
	if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "private output storage is unavailable") {
		t.Fatalf("missing private store: %q, %v", result.Flatten(), err)
	}
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

func TestTaskBashPreservesNonzeroOutput(t *testing.T) {
	runner := &recordingTaskShell{exitCode: 7}
	bash := &sandboxBashTool{runner: runner}
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 41, ExplorationID: 73})
	result, err := bash.Call(ctx, json.RawMessage(`{"command":"exit 7"}`), nil)
	if err != nil || !strings.Contains(result.Flatten(), "sandbox diagnostic") || !strings.Contains(result.Flatten(), "[exit code 7]") {
		t.Fatalf("nonzero Bash result = %q, %v", result.Flatten(), err)
	}
}
