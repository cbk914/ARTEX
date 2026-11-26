# ARTEX-Galactus whitebox audit baseline

Date: 2026-11-26. Baseline: `3cb06383fd99ffe7686abe1d375de11da7cfad54`, matching the fork's `main` when inspected. This is source evidence, not dynamic confirmation.

## Architecture and boundaries

`cmd/artex` starts the `server` HTTP API and task engine. `agent` supplies planner, worker and tools. `db` persists campaigns and secrets in PostgreSQL. `traffic` is the recording proxy; `guard` binds `intercept` target checks and approvals to tool hooks. `mcphttp`, stdio MCP, Bash, custom tools and Python cross from model-directed activity to process or network access. `web` is the browser console. `docs/ARCHITECTURE.md` gives the existing package map.

The boundaries to verify are browser/API, server/PostgreSQL and keys, untrusted content/model, model/server tools, server/executor, campaign/campaign, and executor/network.

Detailed inventories: [HTTP routes](HTTP-ROUTES.md), [direct server filesystem sites](FILESYSTEM-SITES.md), [process and secret boundaries](PROCESS-AND-SECRETS.md), and [CI and deployment](CI-AND-DEPLOYMENT.md).

## Initial inventory

| Surface | Source | Initial observation |
| --- | --- | --- |
| HTTP and auth | `server/server.go`, `server/auth.go` | 278 `mux.HandleFunc` registrations were counted in `server/server.go`; `requireAuth` exempts `/api/auth/*`, health and readiness. Cookie state changes require a same-origin signal. Full route and middleware analysis remains open. |
| Sessions | `server/auth.go`, `web/src/lib/auth.ts`, `web/src/lib/api.ts` | Browser token storage uses `localStorage`; `extractToken` accepts a `token` query parameter. |
| Filesystem | `server/pathconfine.go`, `server/workspace.go`, `server/chatupload.go`, `server/ask_operator.go`, `server/task_archive_package.go` | Workspace validation precedes path-based operations; denied internal prefixes are used. Uploads enter agent-visible directories. |
| Execution | `server/execpriv*.go`, `server/customtool.go`, `agent/filetools.go` | The executor UID/GID and `exec-home` are shared. Full subprocess caller inventory remains open. |
| Network | `guard/guard.go`, `intercept/target_*.go`, `egress/`, `traffic/` | Target checks depend on an enabled scoped gate. Application dial checks do not establish policy for arbitrary child processes. |
| Scope and secrets | `agent/tools_insert.go`, `db/`, `config/`, `llmrec/` | Asset authorization, secret retrieval and telemetry need caller-by-caller tracing. |
| Deployment | `Dockerfile`, `start.sh`, `docker-compose*.yml`, `.github/workflows/` | Checked-in default Compose uses host binds. The running project mounts named Linux volumes for data, keys, skills and PostgreSQL data. Effective configuration remains to be reviewed. |

## Baseline checks

`go.mod` requires Go 1.26.11; installed Go is 1.20.2. `GOTOOLCHAIN=local go test ./...` failed parsing `go.mod` before tests ran. With permitted read-only Docker access, the application and PostgreSQL containers were running, PostgreSQL reported healthy, and named volumes `artex_artex_data`, `artex_artex_keys`, `artex_artex_skills` and `artex_pgdata` were listed. No container or volume was changed. Git requires a temporary mapped drive for work-tree commands on this UNC checkout. Status then showed three previously deleted PoC scripts under `scripts/poc/php2shell/poc/`; they were left untouched. No frontend, PostgreSQL-backed or race tests have run.

ARTEX-001 through ARTEX-013 were **PENDING VALIDATION** at the initial baseline. ARTEX-012 was subsequently reproduced and fixed locally; see `REGRESSION-MATRIX.md`. The other findings remain pending. `SECURITY.md` already acknowledges shared executor and path-based privileged operation limitations; its statements must be reconciled with each completed remediation batch.
