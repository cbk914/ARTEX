# ARTEX-Galactus remediation state

Updated: 2026-11-26. Local branch: `codex/security-remediation`. Baseline: `3cb06383fd99ffe7686abe1d375de11da7cfad54`. Phase 0 commit: `882555b`.

## Completed

- Matched local HEAD to the referenced fork's `main` at inspection time and created the local remediation branch.
- Added Phase 0 source observations, threat model, plan and regression matrix.
- Applied the ARTEX-Galactus display name to the README and frontend metadata. Runtime `ARTEX_*` settings, Compose service names and Go imports remain compatible.
- Fixed strict session JWT validation in commit `089299b`, with a pre-fix reproducer and post-fix normal and race checks.
- Confirmed ARTEX-011 with a failing barrier-controlled pre-fix test. Implemented an atomic hash/version read and monotonic post-commit version updates in commit `deece11`; focused PostgreSQL-backed normal and race tests and the full post-fix Go suite pass.

## Current state

Batch A is in progress. ARTEX-011 and ARTEX-012 are confirmed and fixed locally with failing pre-fix regressions and passing focused tests. ARTEX-001 through ARTEX-010 and ARTEX-013 remain pending validation. HTTP route registrations, direct server filesystem calls, primary process and secret paths, and CI/deployment configuration have been inventoried. Handler-level authorization, transitive filesystem calls, third-party subprocesses and credential value flow remain open.

## Checks and blockers

- Go 1.20.2 is installed on the host, while `go.mod` requires 1.26.11. Host `GOTOOLCHAIN=local go test ./...` failed at module parsing. The first Go 1.26.11 container had six isolation failures because the restricted UID could not execute Go's temporary test binary. A later disposable Go container with a test-only wrapper and dedicated PostgreSQL 16 tmpfs database passed `go test -exec /tmp/artex-test-exec.sh -p 1 ./...` without command-line skips. The non-verbose run did not enumerate test-level skips. Focused JWT and password-version tests passed.
- Initial sandboxed Docker access was denied. With permitted read-only access, the application and PostgreSQL containers were running, PostgreSQL reported healthy, and named volumes `artex_artex_data`, `artex_artex_keys`, `artex_artex_skills` and `artex_pgdata` were listed. Effective configuration, data contents and integration behavior were not inspected. No volume was changed.
- Git work-tree commands fail directly on the UNC path. Using a temporary drive mapping, `git status` showed three previously deleted PoC scripts under `scripts/poc/php2shell/poc/`; they were left untouched and are outside this remediation commit.
- Frontend, dependency and Docker build tests have not run. `go vet ./...`, focused JWT `go test -race`, and the CI-selected race suite passed against disposable databases before the ARTEX-011 edit. Focused post-fix auth tests passed normally and under `-race`; the full post-fix Go suite passed. An intermediate full run failed on an existing test expectation for login with a deliberately corrupt version; after the fixture was changed to expect fail-closed 503 and verify recovery, the suite passed.
- The two disposable test containers and their internal Docker network were removed after results were recorded. They had no operational volume mounts; operational ARTEX containers and volumes were not changed.

## Next steps and rollback

Use the Dockerfile-pinned Go 1.26.11 container for further Go checks and the temporary mapped-drive workaround for Git status and diff. Complete Batch A authorization and secret value-flow review, then begin Batch B with synthetic path-race and upload regressions. Review and reverse only this branch's targeted edits if rollback is needed; do not reset the repository or remove volumes. Runtime migration needs a separately tested procedure before deployment.
