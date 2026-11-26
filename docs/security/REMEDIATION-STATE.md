# ARTEX-Galactus remediation state

Updated: 2026-11-26. Local branch: `codex/security-remediation`. Baseline: `3cb06383fd99ffe7686abe1d375de11da7cfad54`. Phase 0 commit: `882555b`.

## Completed

- Matched local HEAD to the referenced fork's `main` at inspection time and created the local remediation branch.
- Added Phase 0 source observations, threat model, plan and regression matrix.
- Applied the ARTEX-Galactus display name to the README and frontend metadata. Runtime `ARTEX_*` settings, Compose service names and Go imports remain compatible.

## Current state

Batch A is in progress. ARTEX-012 is confirmed and fixed locally with a failing pre-fix regression and passing focused tests. ARTEX-001 through ARTEX-011 and ARTEX-013 remain pending validation. Full HTTP route, subprocess, credential and CI inventories remain open.

## Checks and blockers

- Go 1.20.2 is installed on the host, while `go.mod` requires 1.26.11. Host `GOTOOLCHAIN=local go test ./...` failed at module parsing. A disposable container with the Dockerfile-pinned Go 1.26.11 ran the suite without network after downloading pinned modules. The unskipped baseline failed six root isolation tests because the restricted UID could not execute Go's temporary test binary. After the JWT patch, `go test -p 1 ./...` passed with those six tests skipped; the focused JWT and password-version tests passed.
- Initial sandboxed Docker access was denied. With permitted read-only access, the application and PostgreSQL containers were running, PostgreSQL reported healthy, and named volumes `artex_artex_data`, `artex_artex_keys`, `artex_artex_skills` and `artex_pgdata` were listed. Effective configuration, data contents and integration behavior were not inspected. No volume was changed.
- Git work-tree commands fail directly on the UNC path. Using a temporary drive mapping, `git status` showed three previously deleted PoC scripts under `scripts/poc/php2shell/poc/`; they were left untouched and are outside this remediation commit.
- Frontend, PostgreSQL-backed integration, dependency and Docker build tests have not run. `go vet ./server` and focused JWT `go test -race` passed. The `server` package passed when skipping exactly the six baseline container failures; the earlier all-package run used a broader skip expression.

## Next steps and rollback

Restore the required Go toolchain. Use the temporary mapped-drive workaround for Git status and diff. Complete Batch A and a dedicated PostgreSQL baseline using disposable data, not the running project's database. Begin Batch B with synthetic path-race and upload regressions. Review and reverse only this branch's targeted edits if rollback is needed; do not reset the repository or remove volumes. Runtime migration needs a separately tested procedure before deployment.
