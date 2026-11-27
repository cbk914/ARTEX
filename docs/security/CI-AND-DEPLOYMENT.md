# CI and deployment baseline

Source snapshot: `b9b2a7f`. The running Docker Desktop project was inspected read-only; no compose action, container replacement or volume migration was performed.

## CI inventory

`.github/workflows/ci.yml` has a pinned-Go job with PostgreSQL 16, `gofmt`, build, vet, serial `go test -p 1 ./...`, SQL script apply/rollback and a selected `go test -race` package list including `server`. A separate advisory job tests the latest stable Go. The workflow also has `govulncheck`, shellcheck and script tests, frontend TypeScript/test/static-build checks, and Python tests. The Go job uses suffixed test databases; two tests are documented as skipped in code pending issue #9. This describes CI configuration, not a verified result for this branch.

## Image and Compose inventory

`Dockerfile` pins the Node, Go, Debian, Python and PostgreSQL-related build inputs by image digest where shown, and pins Go 1.26.11. The runtime image declares volumes for `/app/data` and `/app/keys`; `start.sh` verifies the binary and execs it. The base `docker-compose.yml` binds `./data`, `./keys` and `./skills`, while PostgreSQL uses `pgdata`. The default published ports bind the API and proxy to loopback unless the operator changes `ARTEX_BIND_ADDR`. At the baseline snapshot neither checked-in Compose file defined an ARTEX container healthcheck. `server/ready.go` reports PostgreSQL ping status with a short cache. Isolation status is exposed through the authenticated health response, but readiness does not currently require a successful isolation self-test.

On the local remediation branch, both checked-in Compose files now have an ARTEX healthcheck that calls `curl --fail --silent --show-error http://127.0.0.1:8787/api/ready`. `docker compose ... config --quiet` passed for each file, and this exact curl command returned `{"ready":true}` inside the existing running application container. This validates the command and configuration, not a newly built image or a deployment. The endpoint still checks PostgreSQL reachability only; it does not gate on isolation or migrations beyond startup behavior.

The running Docker Desktop project uses the named Linux volumes `artex_artex_data`, `artex_artex_keys`, `artex_artex_skills` and `artex_pgdata`. This differs from the base file's bind mounts. Its exact original Compose inputs and skill-volume update procedure remain to be verified.

`docker-compose.docker-desktop.yml` is a local overlay for the existing named-volume layout. With `docker compose -p artex -f docker-compose.yml -f docker-compose.docker-desktop.yml config --format json`, its four resolved volume names and destinations matched the running containers' read-only mount inventory. The project name matters: another name would create different volumes. This overlay does not copy data from the bind-mount profile and was not used to start or replace the running services. Before a future deployment, compare the effective Compose configuration and volume IDs again, back up the four volumes, and test the image and rollback on disposable volumes.

## Baseline test limits

The host Go 1.20.2 cannot parse the repository's Go 1.26.11 directive. The first disposable Go 1.26.11 container lacked PostgreSQL and had six root isolation test failures because the restricted UID could not execute Go's temporary test binary. A second disposable Go container and a PostgreSQL 16 container on an internal Docker network used a dedicated tmpfs database and a wrapper that made Go's temporary test binary traversable by that UID. `go test -exec /tmp/artex-test-exec.sh -p 1 ./...`, `go vet ./...`, and the CI-selected `go test -race` package list passed on the pre-ARTEX-011 code. Focused post-fix auth tests passed normally and under `-race`, and the full post-fix normal suite passed. The non-verbose runs did not enumerate test-level skips. Frontend, Docker build, Compose validation and dependency scans remain pending.
