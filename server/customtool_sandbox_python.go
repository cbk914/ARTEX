package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
)

// The command is fixed server code; the script and parameters arrive only on
// stdin. DockerEngine.ExecInput starts it in the campaign-private working dir.
const sandboxPythonBootstrap = `import io, json, os, runpy, sys, tempfile
payload = json.load(sys.stdin)
params = payload["params"]
for name, value in payload["env"].items():
    os.environ[name] = value
with tempfile.NamedTemporaryFile(mode="w", prefix="artex-tool-", suffix=".py", dir=".", delete=False) as script:
    script.write(payload["code"])
    path = os.path.abspath(script.name)
try:
    sys.stdin = io.StringIO(json.dumps(params, separators=(",", ":")))
    runpy.run_path(path, run_name="__main__")
finally:
    os.unlink(path)
`

const maxSandboxScriptEnvelope = 1 << 20 // broker RunInput limit

type sandboxPythonRunner interface {
	RunInput(context.Context, agent.RunInfo, string, []byte) (string, error)
}

func sandboxPythonEnvelope(code string, params map[string]any) ([]byte, error) {
	if code == "" {
		return nil, errors.New("empty sandbox script")
	}
	env := make(map[string]string)
	for key, value := range params {
		if strings.IndexByte(key, 0) >= 0 || strings.Contains(key, "=") {
			return nil, fmt.Errorf("invalid script parameter name %q", key)
		}
		if scalar, ok := scalarStr(value); ok {
			if strings.IndexByte(scalar, 0) >= 0 {
				return nil, errors.New("script parameter contains a NUL byte")
			}
			env["TOOL_"+strings.ToUpper(key)] = scalar
		}
	}
	payload, err := json.Marshal(struct {
		Code   string            `json:"code"`
		Params map[string]any    `json:"params"`
		Env    map[string]string `json:"env"`
	}{Code: code, Params: params, Env: env})
	if err != nil {
		return nil, err
	}
	if len(payload) > maxSandboxScriptEnvelope {
		return nil, errors.New("sandbox script and parameters exceed the 1 MiB stdin limit")
	}
	return payload, nil
}

func execPythonSandbox(ctx context.Context, runner sandboxPythonRunner, info agent.RunInfo, interp, code string, params map[string]any, timeout time.Duration) (string, error) {
	if runner == nil || strings.TrimSpace(interp) == "" || strings.IndexByte(interp, 0) >= 0 {
		return "", errors.New("sandbox Python execution unavailable")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return "", errors.New("invalid sandbox Python timeout")
	}
	payload, err := sandboxPythonEnvelope(code, params)
	if err != nil {
		return "", err
	}
	command := shellQuote(interp) + " -c " + shellQuote(sandboxPythonBootstrap)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runner.RunInput(runCtx, info, command, payload)
}
