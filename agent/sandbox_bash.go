package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/sandboxbroker"
	actool "github.com/Autumn-27/norma/tool"
)

// TaskShellRunner is supplied by the trusted server control plane. The tool
// never accepts a sandbox handle or task selector from model input.
type TaskShellRunner interface {
	Run(context.Context, RunInfo, string) (string, error)
}

// sandboxBashTool keeps the SDK's permission check while replacing its host
// subprocess path for task runs. The advertised contract matches the broker's
// synchronous, 30-second execution limit.
type sandboxBashTool struct {
	actool.CoreTool
	runner TaskShellRunner
}

func (t *sandboxBashTool) Description() string {
	return "Executes a shell command in this task's isolated sandbox and returns combined stdout and stderr. Commands are synchronous and limited to 30 seconds."
}

func (t *sandboxBashTool) Prompt() string {
	return "Run one shell command in the task sandbox. The command may use shell syntax, but it cannot run in the background. The sandbox has no access to host paths or other tasks."
}

func (t *sandboxBashTool) InputSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"command":    map[string]any{"type": "string", "description": "The shell command to execute."},
			"timeout_ms": map[string]any{"type": "integer", "minimum": 1, "maximum": 30000, "description": "Timeout in milliseconds (default and maximum 30000)."},
		},
		"required": []any{"command"},
	}
}

func (t *sandboxBashTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	var in struct {
		Command         string `json:"command"`
		TimeoutMS       int    `json:"timeout_ms"`
		RunInBackground bool   `json:"run_in_background"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return actool.Result{}, err
	}
	if strings.TrimSpace(in.Command) == "" {
		return actool.Errorf("Error: command is required"), nil
	}
	if in.RunInBackground {
		return actool.Errorf("Error: background execution is unavailable in the task sandbox"), nil
	}
	if in.TimeoutMS < 0 || in.TimeoutMS > 30000 {
		return actool.Errorf("Error: task sandbox timeout must be between 1 and 30000 ms"), nil
	}
	info := RunInfoFrom(ctx)
	if info.TaskID <= 0 || info.ExplorationID <= 0 || info.SessionID != "" || t.runner == nil {
		return actool.Errorf("Error: task sandbox identity is unavailable"), nil
	}
	timeout := 30 * time.Second
	if in.TimeoutMS > 0 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := t.runner.Run(runCtx, info, in.Command)
	if err != nil {
		var exit *sandboxbroker.CommandExitError
		if errors.As(err, &exit) {
			if strings.TrimSpace(output) == "" {
				output = "(no output)"
			}
			return actool.Errorf(fmt.Sprintf("%s\n\n[exit code %d]", actool.Capture(tc, output), exit.Code)), nil
		}
		return actool.Errorf(fmt.Sprintf("Error: task sandbox command failed: %v", err)), nil
	}
	if strings.TrimSpace(output) == "" {
		output = "(command produced no output)"
	}
	return actool.Text(actool.Capture(tc, output)), nil
}
