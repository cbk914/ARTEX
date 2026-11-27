# ADR 0002: Campaign execution boundary

Status: proposed. No runtime migration or deployment has occurred.

## Decision context

`PrepareExecPrivilege` shares every task and session run directory with one executor GID and configures one executor UID/GID for Bash shims, custom tools and file tools. `prepareExecHome` creates one `<data>/exec-home` and `execHomeEnv` supplies that path to every executor. Spill directories are readable by the same group. A process running under this identity can therefore read or modify another run directory through ordinary filesystem permissions. The existing privilege drop protects the root-owned control plane, but it does not isolate campaigns from each other. `no_new_privs` is set by Bash and stdio shims; the custom-tool path uses `SysProcAttr.Credential` without that flag. An opt-in synthetic root-capable Linux probe on 2026-11-27 observed cross-campaign file read/write, HOME reuse and process signaling under this identity. The probe confirms exposure; it does not implement or verify isolation.

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
