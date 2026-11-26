# ARTEX-Galactus remediation state

Updated: 2026-11-26. Local branch: `codex/security-remediation`. Baseline: `3cb06383fd99ffe7686abe1d375de11da7cfad54`.

## Completed

- Matched local HEAD to the referenced fork's `main` at inspection time and created the local remediation branch.
- Added Phase 0 source observations, threat model, plan and regression matrix.
- Applied the ARTEX-Galactus display name to the README and frontend metadata. Runtime `ARTEX_*` settings, Compose service names and Go imports remain compatible.

## Current state

Batch A is in progress. ARTEX-001 through ARTEX-013 are pending validation; no finding is marked fixed. Full HTTP route, subprocess, credential, CI and Docker-volume inventories remain open.

## Checks and blockers

- Go 1.20.2 is installed, while `go.mod` requires 1.26.11. `GOTOOLCHAIN=local go test ./...` failed at module parsing; no tests ran.
- Initial sandboxed Docker access was denied. With permitted read-only access, the application and PostgreSQL containers were running, PostgreSQL reported healthy, and named volumes `artex_artex_data`, `artex_artex_keys`, `artex_artex_skills` and `artex_pgdata` were listed. Effective configuration, data contents and integration behavior were not inspected. No volume was changed.
- Git work-tree commands fail directly on the UNC path. Using a temporary drive mapping, `git status` showed three previously deleted PoC scripts under `scripts/poc/php2shell/poc/`; they were left untouched and are outside this remediation commit.
- Frontend, integration, race, dependency and Docker tests have not run.

## Next steps and rollback

Restore the required Go toolchain. Use the temporary mapped-drive workaround for Git status and diff. Complete Batch A and a dedicated PostgreSQL baseline using disposable data, not the running project's database. Begin Batch B with synthetic path-race and upload regressions. Review and reverse only this branch's targeted edits if rollback is needed; do not reset the repository or remove volumes. Runtime migration needs a separately tested procedure before deployment.
