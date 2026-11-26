# ARTEX-Galactus remediation state

Updated: 2026-11-26. Local branch: `codex/security-remediation`. Baseline: `3cb06383fd99ffe7686abe1d375de11da7cfad54`. Phase 0 commit: `882555b`.

## Completed

- Matched local HEAD to the referenced fork's `main` at inspection time and created the local remediation branch.
- Added Phase 0 source observations, threat model, plan and regression matrix.
- Applied the ARTEX-Galactus display name to the README and frontend metadata. Runtime `ARTEX_*` settings, Compose service names and Go imports remain compatible.
- Fixed strict session JWT validation in commit `089299b`, with a pre-fix reproducer and post-fix normal and race checks.
- Confirmed ARTEX-011 with a failing barrier-controlled pre-fix test. Implemented an atomic hash/version read and monotonic post-commit version updates in commit `deece11`; focused PostgreSQL-backed normal and race tests and the full post-fix Go suite pass.
- Confirmed the ARTEX-003 duplicate-name race with a failing pre-fix regression. Partial mitigation commit `22bf3f2` uses a run-directory `os.Root`, exclusive file creation, bounded copying, cancellation checks and incomplete-file cleanup; focused normal/race, 512 MiB boundary and full PostgreSQL-backed Go tests pass. Protected staging and immutable metadata remain open.
- Confirmed ARTEX-002's check/open race with a failing deterministic parent-swap read regression. Partial mitigation commit `ba9f398` confines list, read and download through `os.Root`; focused normal/race, FIFO, HTTP range, vet, Windows compile and full PostgreSQL-backed Go checks pass. Write, mkdir, upload, delete and explicit allowed roots remain open.

## Current state

Batch B is in progress. ARTEX-011 and ARTEX-012 are confirmed and fixed locally; ARTEX-002 and ARTEX-003 are confirmed with partial mitigations. ARTEX-001, ARTEX-004 through ARTEX-010 and ARTEX-013 remain pending validation. HTTP route registrations, direct server filesystem calls, primary process and secret paths, and CI/deployment configuration have been inventoried. Handler-level authorization, transitive filesystem calls, third-party subprocesses and credential value flow remain open.

## Checks and blockers

- Go 1.20.2 is installed on the host, while `go.mod` requires 1.26.11. Host `GOTOOLCHAIN=local go test ./...` failed at module parsing. The first Go 1.26.11 container had six isolation failures because the restricted UID could not execute Go's temporary test binary. A later disposable Go container with a test-only wrapper and dedicated PostgreSQL 16 tmpfs database passed `go test -exec /tmp/artex-test-exec.sh -p 1 ./...` without command-line skips. The non-verbose run did not enumerate test-level skips. Focused JWT and password-version tests passed.
- Initial sandboxed Docker access was denied. With permitted read-only access, the application and PostgreSQL containers were running, PostgreSQL reported healthy, and named volumes `artex_artex_data`, `artex_artex_keys`, `artex_artex_skills` and `artex_pgdata` were listed. Effective configuration, data contents and integration behavior were not inspected. No volume was changed.
- Git work-tree commands fail directly on the UNC path. Using a temporary drive mapping, `git status` showed three previously deleted PoC scripts under `scripts/poc/php2shell/poc/`; they were left untouched and are outside this remediation commit.
- Frontend, dependency and Docker build tests have not run. `go vet ./...`, focused JWT `go test -race`, and the CI-selected race suite passed against disposable databases before the ARTEX-011 edit. Focused post-fix auth tests passed normally and under `-race`; the full post-fix Go suite passed. An intermediate full run failed on an existing test expectation for login with a deliberately corrupt version; after the fixture was changed to expect fail-closed 503 and verify recovery, the suite passed.
- The two disposable test containers and their internal Docker network were removed after results were recorded. They had no operational volume mounts; operational ARTEX containers and volumes were not changed.
- A separate network-disconnected, disposable Go 1.26.11 container reproduced the ARTEX-003 name collision before the change and passed focused normal, race and 512 MiB upload boundary tests afterward. After connecting it only to a disposable internal PostgreSQL 16 database, the full Go suite passed. An initial full attempt failed before executing tests because the disposable launcher contained a PowerShell carriage return; the corrected launcher and same suite passed.
- The phase-B Go and PostgreSQL test containers and their internal network were removed after the full run; Docker inspection showed no operational volume mounts.
- A new isolated Go 1.26.11 container reproduced the ARTEX-002 parent-swap read before the fix. Focused post-fix read/list/download, FIFO, HTTP range and race tests passed; `go vet ./server`, Windows cross-compilation and the full PostgreSQL-backed Go suite passed.
- The workspace Go and PostgreSQL test containers and their internal network were removed after the full run; inspection showed no operational volume mounts.

## Next steps and rollback

Use the Dockerfile-pinned Go 1.26.11 container for further Go checks and the temporary mapped-drive workaround for Git status and diff. Continue Batch B with a deterministic `wsWrite` parent-swap reproducer and a shared confined filesystem layer for write, mkdir, upload and delete. The current `wsResolveConfined` check is still followed by path-based mutations and its deny-list does not replace an explicit allowed-root policy. Protected upload staging and immutable attachment references remain open; `docs/security/adr/0001-protected-artifact-storage.md` records the proposed design and migration dependencies. The agent can still modify completed files in its run directory; `os.Root` only prevents traversal outside that directory. `wsUpload` intentionally overwrites existing names, so preserve that behavior through a separately reviewed atomic replacement design. Complete Batch A authorization and secret value-flow review in parallel with later work. Review and reverse only this branch's targeted edits if rollback is needed; do not reset the repository or remove volumes. Runtime migration needs a separately tested procedure before deployment.
