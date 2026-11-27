# ADR 0002: Campaign execution boundary

Status: proposed, with a host-side lifecycle prototype. No runtime migration or deployment has occurred.

## Decision context

`PrepareExecPrivilege` shares every task and session run directory with one executor GID and configures one executor UID/GID for Bash shims, custom tools and file tools. `prepareExecHome` creates one `<data>/exec-home` and `execHomeEnv` supplies that path to every executor. Spill directories are readable by the same group. A process running under this identity can therefore read or modify another run directory through ordinary filesystem permissions. The existing privilege drop protects the root-owned control plane, but it does not isolate campaigns from each other. An opt-in synthetic root-capable Linux probe on 2026-11-27 observed cross-campaign file read/write, HOME reuse and process signaling under this identity. The probe confirms exposure; it does not implement or verify isolation.

The custom-tool launcher formerly used `SysProcAttr.Credential` without setting `no_new_privs`. A root-capable regression observed `NoNewPrivs: 0` in the Python child. It now uses the same drop shim as MCP, with an explicit keep list for its session and scalar parameter variables. The regression observes `NoNewPrivs: 1`; focused normal/race tests, environment allowlist tests, `go vet`, Windows cross-compilation and the full PostgreSQL-backed server suite passed in disposable containers. This strengthens the process privilege boundary, but every campaign still shares the same executor identity and HOME.

The supported-platform check now rejects the privilege drop on non-Linux Unix hosts before setup; those hosts cannot provide the Linux `no_new_privs` guarantee. A macOS server test binary cross-compiled after this change. No macOS runtime acceptance is claimed.

## Docker Desktop feasibility probe

On 2026-11-27, a disposable `artex:local` container with no network or operational mounts could not create user, PID, network or mount namespaces with `unshare`; each attempt returned `Operation not permitted`. This is a runtime constraint of the tested Docker configuration, not a universal Linux result. An in-process broker that requires these namespace operations cannot be enabled in the current container.

Two separate disposable sibling containers were then started with `--network none`, a read-only image, private tmpfs at `/campaign`, no capabilities, `no-new-privileges`, and CPU, memory and PID limits. Their PID, mount and network namespace identifiers differed. A marker written in A's private tmpfs was absent in B; B could neither see nor signal A's host PID. The probe used synthetic data and did not mount any operational ARTEX volume. The existing `artex:local` image declares `/app/data` and `/app/keys` volumes, so Docker created distinct empty anonymous volumes for these probes; they were inspected and removed with the probe containers. A production execution image must avoid or explicitly override those image-declared volumes.

This proves only that Docker Desktop can supply separate local container boundaries under the tested options. It does not prove ARTEX routes any executor through them, that approved network traffic works, that a compromised process cannot exploit a kernel flaw, or that lifecycle and artifact exchange are correct. The implementation path is a dedicated trusted broker outside the ARTEX server and agent containers. It must own container creation and lifecycle, accept only opaque campaign handles and fixed reviewed image/policy choices, and expose no Docker daemon socket to the server or agents. Engine access in a broker is host-powerful and requires a separate credential and API review before deployment.

## Host-side lifecycle prototype

`sandboxbroker` now provides an in-memory campaign-to-handle registry and a Docker CLI engine for a trusted host-side process. The broker accepts a pinned image digest, allocates a random opaque handle and container name, creates one container per campaign, starts it, checks the effective Docker policy, and removes it by handle. A failed start or policy check triggers removal. Docker creation uses no bind mount, no network, a read-only root, dropped capabilities, `no-new-privileges`, a fixed non-root user, CPU/memory/PID limits, and private tmpfs paths. The `/app/data` and `/app/keys` tmpfs overrides prevent the current image's declared volumes from becoming anonymous volumes or exposing an operational mount. A local disposable container probe confirmed these paths were tmpfs and `docker inspect` reported no `Mounts` entries. Unit tests exercise handle lifecycle and reject an unexpected image volume, bind mount, or bridge network; `go test -race` and `go vet` passed for the package.

This is deliberately not wired into the server or agents. It cannot run campaign tools, mediate network egress, exchange artifacts, authorize operators, persist handles across a broker crash, or prove teardown after host failure. The prototype's Docker Engine access remains host-powerful. `Create` failure cleanup and Docker policy verification need further adversarial review before production use. The current ARTEX deployment still uses the shared executor. The prototype is not a security acceptance gate and must not be reported as remediating ARTEX-001, ARTEX-004, or ARTEX-005.

The opt-in `TestDockerBrokerSmoke` was cross-compiled with Go 1.26.11 and passed natively on Windows against the local image digest. It created, verified and removed one disposable Docker container; no sandbox container remained afterward.

## Execution handoff inventory

| Path | Current entry point | Migration requirement |
| --- | --- | --- |
| Planner, worker and main agent Bash | `agent/planner.go`, `agent/worker.go`, `agent/mainagent.go` compose Norma default tools; `server/execpriv_unix.go` places the Bash drop shim on `PATH` | Replace the SDK process launch with a broker-backed tool for every task run, including background jobs and cancellation. A task ID alone is not a verified campaign grant. |
| Chat Bash | `agent/chat.go` composes the same default tools but records a session ID with task ID zero | Assign an explicit chat trust domain and sandbox lifecycle; do not silently attach a chat session to a campaign. |
| Interactive shell | `server/assembly.go` exposes Norma `ShellSessionTools` to enabled agents; the same Bash shim currently supplies its identity | Keep stdin, terminal state, process groups, close and cancellation semantics inside one authorized sandbox. |
| Custom command and Python tools | `server/customtool.go` sends command tools through Norma Bash, while `execPython` starts the interpreter directly after writing a script | Route both launch paths and script/parameter transfer through the broker. The server must not execute arbitrary campaign code directly. |
| Stdio MCP | `server/assembly.go` and `server/mcpdiscover.go` start configured commands, including global discovery and agents' per-run clients | Decide whether discovery is non-executing metadata or runs in an isolated scope; carry stdio streams and approved credentials through a scoped broker channel. |
| File tools | `agent/filetools.go` runs Read/Write/Edit/MultiEdit/LS/Glob/Grep inside the server under a temporary filesystem identity | Move campaign file access to a sandbox-facing file API or a separately authorized artifact store; a host `os.Root` over a shared run tree is not campaign isolation. |
| HTTP MCP, WebFetch and custom HTTP | `server/mcpdiscover.go` creates HTTP/SSE clients; `agent/chat.go` and `server/customtool.go` provide additional direct network paths | Enforce the same per-campaign target grant in a network gateway, including redirect and DNS decisions. Process isolation alone cannot enforce ARTEX-004. |

`agent/runinfo.go` carries task, exploration, intent or chat-session attribution to tool assembly. It is optional context, not an authorization token. The broker cannot infer campaign scope from it without a server-side operator grant and a verified task-to-campaign mapping. Startup MCP discovery and chat have no task scope, so both need explicit handling before an isolated mode can be enabled.

## Proposed boundary

Introduce a trusted campaign execution broker that owns a `SandboxHandle` for each campaign. The handle carries an opaque ID, the authorized campaign and operator scope, private filesystem and process namespace references, network policy reference, resource limits and lifecycle state. The server must use that handle for every Bash, interactive shell, background task, Python, custom-tool and stdio MCP launch, and for file-tool operations. No tool receives a raw identity, host path or namespace selector from an LLM or imported document.

The broker creates a separate Linux execution sandbox for each campaign with a distinct writable filesystem, private HOME, XDG directories, TMPDIR and browser profile, independent process namespace and limits. It mounts approved binaries and read-only resources explicitly. Credential injection is per operation and scoped to the handle; it is never inherited from the server's full environment. Network access follows ADR's future campaign policy design and fails closed when enforcement is unavailable. The broker mediates controlled artifact exchange; the shared workspace is not a private campaign store.

The control plane retains keys, database credentials, archive staging and evidence staging outside every executor mount. Run output and spills are bound to a campaign identity and cannot be opened through another handle. Sandbox teardown revokes the handle, stops remaining processes and removes only its ephemeral state. Persistent campaign artifacts survive through a separately controlled store. Reuse requires a new handle and a clean ephemeral filesystem.

## Migration and validation gates

1. Inventory all launch paths and filesystem consumers, including third-party Norma background tasks, MCP servers and restored campaigns. Route them through the broker or refuse their use when isolated execution is required.
2. Prototype the broker against disposable local sandboxes and synthetic campaigns. Verify concurrent and sequential read, write and process-interference denials, plus permitted artifact exchange. Exercise cancellation, crash recovery and teardown.
3. Add network default-deny enforcement and per-campaign policy before enabling arbitrary processes in the new sandbox. Verify DNS, redirect, IPv4, IPv6, proxy and infrastructure cases with mock services.
4. Migrate existing data without changing its ownership in place until a backed-up copy passes integrity and access checks. Preserve the current Docker Desktop deployment and signing keys. Provide a reversible switch and a documented rollback that does not delete volumes.
5. Enable the new boundary only after Bash, planner/worker, chat, custom tools, file tools, MCP and browser tests pass. Unsupported hosts and missing isolation features must fail closed, with an explicit operator-visible readiness error.

Changing only the global UID/GID, working directory or environment variables cannot satisfy this boundary. Until the broker is implemented and validated, ARTEX-001 and ARTEX-005 remain open and cross-campaign confidentiality and integrity must not be claimed.
