# Process and secret boundary inventory

Source snapshot: `b9b2a7f`. This is a source map for Phase 0, not a claim that every route is isolated or every secret is redacted.

## Process launch paths

| Path | Implementation | Boundary to validate |
| --- | --- | --- |
| Norma Bash | `agent/chat.go`, `agent/mainagent.go`, `agent/planner.go`, `agent/worker.go` set `BashEnv`; `server/execpriv_unix.go` installs the executable shim | Norma starts Bash itself; the shim must drop credentials before execution. Proxy environment is guidance, not an arbitrary-process network boundary. |
| Interactive shell | Agent tool binding in `server/assembly.go` and the Norma runtime | Its process, child processes, environment and lifetime need campaign-scoped isolation. |
| Command custom tools | `server/customtool.go:442-464` calls Norma's `NewBash().Call` | The same Bash and approval boundary must apply to rendered command tools. |
| Python custom tools | `server/customtool.go:475-527` uses `exec.CommandContext` | `applyExecCredential`, script storage and inherited environment must be reviewed together. |
| Stdio MCP | `server/mcpdiscover.go:37` calls `mcp.NewStdioClient`; `server/execpriv.go` wraps the command | MCP children inherit the executor identity and may use network/process capabilities. |
| HTTP MCP | `mcphttp/`, `server/mcpdiscover.go` | No child process is required, but the configured service and tool descriptions cross an external trust boundary. |
| Isolation probe | `server/isolation_unix.go:273` starts Bash; `server/execpriv_unix.go:785` execs the target from a shim | Probe success must represent the real executor configuration. |
| Server re-exec | `server/envseal_linux.go:36` uses `syscall.Exec` | Privileged server environment is sealed before normal operation; it is not an agent tool. |

The direct Go process-launch search found no other production `exec.Command`, `os.StartProcess`, `syscall.Exec`, `unix.Exec` or `NewStdioClient` calls. This does not enumerate subprocesses launched inside Norma, third-party libraries, scripts or command-line tools invoked through Bash.

## Credential storage and retrieval

`db/secrets.go` defines AES-GCM sealing for selected columns and secret settings. `server/manager.go:453` initializes the key before normal database use. The key comes from `ARTEX_SECRET_KEY` or the protected key directory; initialization refuses to create a replacement key over existing encrypted data. `db/settings.go` seals and opens configured secret settings. `db/config.go` covers LLM API keys, proxies, custom headers and MCP environment. `db/task_credentials.go` seals task passwords. Notification, custom-tool, traffic evidence, rewrite-rule and tamper-hook fields have separate sealed-column mappings in `db/secrets.go`.

Agent task credentials are exposed through `agent/tools_creds.go` (`save_task_credential`, `list_task_credentials`) and task context in `agent/tools.go`. The console uses `server/task_credentials.go` routes. These are model-facing or operator-facing retrieval paths and require per-campaign authorization and log-redaction review. `llmrec/` and error/log paths also need a value-flow audit; encrypted storage alone does not prevent plaintext exposure after retrieval.

No credential values or operational secret files were read for this inventory.
