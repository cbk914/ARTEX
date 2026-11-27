package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	actool "github.com/Autumn-27/norma/tool"
)

// SandboxFileToolCommand is fixed control-plane code, never assembled from a
// model-supplied tool name or path.
const SandboxFileToolCommand = "/app/artex __artex-sandbox-filetool"

const maxSandboxFileToolRequest = 1 << 20

type SandboxFileToolRequest struct {
	Name           string          `json:"name"`
	Input          json.RawMessage `json:"input"`
	WorkingDir     string          `json:"working_dir"`
	MaxOutputChars int             `json:"max_output_chars"`
}

type SandboxFileToolResponse struct {
	Text    string `json:"text"`
	IsError bool   `json:"is_error"`
}

// TaskFileRunner is the trusted host-side route into a campaign sandbox.
// The model never selects a handle or a working directory for this interface.
type TaskFileRunner interface {
	RunFileTool(context.Context, RunInfo, SandboxFileToolRequest) (actool.Result, error)
}

type sandboxFileTool struct {
	actool.CoreTool
	runner TaskFileRunner
}

func (t *sandboxFileTool) Call(ctx context.Context, input json.RawMessage, tc *actool.ToolContext) (actool.Result, error) {
	info := RunInfoFrom(ctx)
	if t.runner == nil || info.TaskID <= 0 || info.ExplorationID <= 0 || info.SessionID != "" || tc == nil || tc.WorkingDir == "" {
		return actool.Errorf("Error: task sandbox file authority is unavailable"), nil
	}
	req := SandboxFileToolRequest{Name: t.Name(), Input: input, WorkingDir: tc.WorkingDir, MaxOutputChars: actool.MaxOutput(tc)}
	result, err := t.runner.RunFileTool(ctx, info, req)
	if err != nil {
		return actool.Errorf(fmt.Sprintf("Error: task sandbox file operation failed: %v", err)), nil
	}
	return result, nil
}

// RunSandboxFileTool executes one of the existing confined file tools inside
// the campaign container. Its root is fixed to the private /campaign tmpfs;
// WorkingDir only translates the host-facing absolute paths already shown to
// the model and cannot widen the root.
func RunSandboxFileTool(ctx context.Context, input io.Reader, output io.Writer) error {
	return runSandboxFileToolAtRoot(ctx, "/campaign", input, output)
}

func runSandboxFileToolAtRoot(ctx context.Context, rootPath string, input io.Reader, output io.Writer) error {
	body, err := io.ReadAll(io.LimitReader(input, maxSandboxFileToolRequest+1))
	if err != nil || len(body) > maxSandboxFileToolRequest {
		return errors.New("sandbox file request exceeds its limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var req SandboxFileToolRequest
	if err := decoder.Decode(&req); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("sandbox file request has trailing data")
	}
	if !filepath.IsAbs(req.WorkingDir) || req.MaxOutputChars < 1 || req.MaxOutputChars > 512<<10 {
		return errors.New("invalid sandbox file context")
	}
	run := confinedFileToolNames[req.Name]
	if run == nil {
		return errors.New("unknown sandbox file tool")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Mkdir(".artex-output", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	spillDir, err := root.Lstat(".artex-output")
	if err != nil || !spillDir.IsDir() || spillDir.Mode()&os.ModeSymlink != 0 {
		return errors.New("private sandbox output directory is unsafe")
	}
	w := &workRoot{Root: root, dir: req.WorkingDir, sandboxAlias: rootPath}
	tc := &actool.ToolContext{WorkingDir: req.WorkingDir, MaxOutputChars: req.MaxOutputChars, OutputDir: filepath.Join(rootPath, ".artex-output")}
	result, err := run(w, req.Input, tc)
	if err != nil {
		return err
	}
	if w.captured {
		result = actool.Text(actool.Capture(tc, result.Flatten()))
	}
	return json.NewEncoder(output).Encode(SandboxFileToolResponse{Text: result.Flatten(), IsError: result.IsError})
}
