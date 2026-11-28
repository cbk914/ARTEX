package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"
)

func callSandboxFileHelper(t *testing.T, root string, req SandboxFileToolRequest) SandboxFileToolResponse {
	t.Helper()
	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runSandboxFileToolAtRoot(context.Background(), root, bytes.NewReader(encoded), &output); err != nil {
		t.Fatal(err)
	}
	var response SandboxFileToolResponse
	if err := json.Unmarshal(output.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestSandboxFileHelperConfinesExistingToolSemantics(t *testing.T) {
	root := t.TempDir()
	hostDir := filepath.Join(t.TempDir(), "tasks", "7", "main")
	outside := filepath.Join(filepath.Dir(hostDir), "other.txt")
	if err := os.MkdirAll(filepath.Dir(outside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, []byte("outside sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeInput, _ := json.Marshal(map[string]any{"file_path": filepath.Join(hostDir, "report.txt"), "content": "campaign-private"})
	got := callSandboxFileHelper(t, root, SandboxFileToolRequest{Name: "Write", Input: writeInput, WorkingDir: hostDir, SandboxDir: "main", MaxOutputChars: 30000})
	if got.IsError || !strings.Contains(got.Text, "Created") {
		t.Fatalf("write: %+v", got)
	}
	if data, err := os.ReadFile(filepath.Join(root, "main", "report.txt")); err != nil || string(data) != "campaign-private" {
		t.Fatalf("private file: %q, %v", data, err)
	}
	readInput, _ := json.Marshal(map[string]any{"file_path": filepath.Join(hostDir, "report.txt")})
	got = callSandboxFileHelper(t, root, SandboxFileToolRequest{Name: "Read", Input: readInput, WorkingDir: hostDir, SandboxDir: "main", MaxOutputChars: 30000})
	if got.IsError || !strings.Contains(got.Text, "campaign-private") {
		t.Fatalf("read: %+v", got)
	}
	aliasInput, _ := json.Marshal(map[string]any{"file_path": filepath.Join(root, "main", "report.txt")})
	got = callSandboxFileHelper(t, root, SandboxFileToolRequest{Name: "Read", Input: aliasInput, WorkingDir: hostDir, SandboxDir: "main", MaxOutputChars: 30000})
	if got.IsError || !strings.Contains(got.Text, "campaign-private") {
		t.Fatalf("sandbox path alias: %+v", got)
	}
	outsideInput, _ := json.Marshal(map[string]any{"file_path": outside})
	got = callSandboxFileHelper(t, root, SandboxFileToolRequest{Name: "Read", Input: outsideInput, WorkingDir: hostDir, SandboxDir: "main", MaxOutputChars: 30000})
	if !got.IsError || !strings.Contains(got.Text, "outside") {
		t.Fatalf("outside read was admitted: %+v", got)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "outside sentinel" {
		t.Fatalf("outside sentinel changed: %q, %v", data, err)
	}
	for i := 0; i < 12; i++ {
		name := filepath.Join(root, "main", fmt.Sprintf("private-%02d.txt", i))
		if err := os.WriteFile(name, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	listInput, _ := json.Marshal(map[string]any{"path": hostDir})
	got = callSandboxFileHelper(t, root, SandboxFileToolRequest{Name: "LS", Input: listInput, WorkingDir: hostDir, SandboxDir: "main", MaxOutputChars: 50})
	if got.IsError || !strings.Contains(got.Text, "<persisted-output>") {
		t.Fatalf("private output did not spill: %+v", got)
	}
	spills, err := os.ReadDir(filepath.Join(root, "main", ".artex-output"))
	if err != nil || len(spills) != 1 {
		t.Fatalf("private output spill missing: %v, %v", spills, err)
	}
}

func TestSandboxFileHelperKeepsRunDirectoriesDistinct(t *testing.T) {
	root := t.TempDir()
	mainDir := filepath.Join(t.TempDir(), "tasks", "7", "main")
	workerDir := filepath.Join(filepath.Dir(mainDir), "i3")
	for _, item := range []struct {
		hostDir, sandboxDir, content string
	}{{mainDir, "main", "main-private"}, {workerDir, "i3", "worker-private"}} {
		input, _ := json.Marshal(map[string]any{"file_path": filepath.Join(item.hostDir, "same.txt"), "content": item.content})
		got := callSandboxFileHelper(t, root, SandboxFileToolRequest{Name: "Write", Input: input, WorkingDir: item.hostDir, SandboxDir: item.sandboxDir, MaxOutputChars: 30000})
		if got.IsError {
			t.Fatalf("%s write: %+v", item.sandboxDir, got)
		}
		if data, err := os.ReadFile(filepath.Join(root, item.sandboxDir, "same.txt")); err != nil || string(data) != item.content {
			t.Fatalf("%s file: %q, %v", item.sandboxDir, data, err)
		}
	}
	input, _ := json.Marshal(map[string]any{"file_path": filepath.Join(root, "main", "same.txt")})
	got := callSandboxFileHelper(t, root, SandboxFileToolRequest{Name: "Read", Input: input, WorkingDir: workerDir, SandboxDir: "i3", MaxOutputChars: 30000})
	if !got.IsError {
		t.Fatalf("worker file tool crossed its run directory: %+v", got)
	}
	for _, unsafe := range []string{"", "..", "i0", "i-1", "main/other", "/campaign/main"} {
		var out bytes.Buffer
		request, _ := json.Marshal(SandboxFileToolRequest{Name: "Read", Input: json.RawMessage(`{"file_path":"same.txt"}`), WorkingDir: mainDir, SandboxDir: unsafe, MaxOutputChars: 30000})
		if err := runSandboxFileToolAtRoot(context.Background(), root, bytes.NewReader(request), &out); err == nil {
			t.Fatalf("accepted unsafe sandbox directory %q", unsafe)
		}
	}
}

type syntheticSandboxFileRunner struct{ calls int }

func (*syntheticSandboxFileRunner) Run(context.Context, RunInfo, string) (string, error) {
	return "", nil
}

func (r *syntheticSandboxFileRunner) RunFileTool(_ context.Context, _ RunInfo, req SandboxFileToolRequest) (actool.Result, error) {
	r.calls++
	if req.Name != "Read" || req.WorkingDir == "" {
		return actool.Errorf("wrong request"), nil
	}
	return actool.Text("from campaign sandbox"), nil
}

func TestTaskFileToolUsesSandboxAndRequiresTaskIdentity(t *testing.T) {
	runner := &syntheticSandboxFileRunner{}
	var selected actool.CoreTool
	for _, tool := range defaultToolsWithTaskShell(t.TempDir(), runner) {
		if tool.Name() == "Read" {
			selected = tool
		}
	}
	if selected == nil {
		t.Fatal("Read tool unavailable")
	}
	hostDir := t.TempDir()
	input, _ := json.Marshal(map[string]any{"file_path": filepath.Join(hostDir, "report.txt")})
	ctx := WithRunInfo(context.Background(), RunInfo{TaskID: 7, ExplorationID: 70})
	result, err := selected.Call(ctx, input, &actool.ToolContext{WorkingDir: hostDir})
	if err != nil || result.IsError || result.Flatten() != "from campaign sandbox" || runner.calls != 1 {
		t.Fatalf("sandbox routing: %+v, %v, calls=%d", result, err, runner.calls)
	}
	result, err = selected.Call(context.Background(), input, &actool.ToolContext{WorkingDir: hostDir})
	if err != nil || !result.IsError || runner.calls != 1 {
		t.Fatalf("unattributed tool reached sandbox: %+v, %v, calls=%d", result, err, runner.calls)
	}
}
