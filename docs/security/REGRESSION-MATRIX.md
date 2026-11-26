# ARTEX-Galactus security regression matrix

The initial baseline had no passing dynamic security regression. ARTEX-011 and ARTEX-012 now have failing pre-fix reproducers and passing post-fix checks. Other findings remain **PENDING VALIDATION**.

| ID | Priority | Status | Primary invariant | Required evidence |
| --- | --- | --- | --- | --- |
| ARTEX-001 | P0 | PENDING VALIDATION | Cross-campaign process and file isolation | Concurrent and sequential campaigns |
| ARTEX-002 | P0 | PENDING VALIDATION | Privileged filesystem confinement | Parent replacement, link and special-file fixtures |
| ARTEX-003 | P0 | PENDING VALIDATION | Atomic confined uploads | Duplicate, concurrent, cancelled and quota cases |
| ARTEX-004 | P0 | PENDING VALIDATION | Independent default-deny network authorization | Mock authorized, denied and infrastructure destinations through each executor |
| ARTEX-005 | P0 | PENDING VALIDATION | Private HOME, cache, temp and browser state | Cross-campaign state and reuse tests |
| ARTEX-006 | P1 | PENDING VALIDATION | Secure browser sessions | Login, logout, CSRF, stream reconnect, bearer compatibility |
| ARTEX-007 | P1 | PENDING VALIDATION | Consistent, bounded archive and restore | Concurrent mutation, malformed archive, cancellation, rollback |
| ARTEX-008 | P1 | PENDING VALIDATION | Immutable, attributed operator evidence | Stage, hash, concurrent modification, display |
| ARTEX-009 | P1 | PENDING VALIDATION | Discovery cannot grant execution scope | Scanner import, denial precedence, revocation, inheritance |
| ARTEX-010 | P2 | PENDING VALIDATION | Bounded resource use | Exhaustion, cleanup, evidence preservation |
| ARTEX-011 | P1 | CONFIRMED; FIXED LOCALLY | Consistent password version | `TestLoginCannotSignOldPasswordAtNewVersion` failed before and passed after; focused PostgreSQL and race tests passed. See details below. |
| ARTEX-012 | P2 | CONFIRMED; FIXED LOCALLY | Strict HS256, expiration, subject and explicit password version | `TestSessionJWTRejectsUnsupportedClaimsAndAlgorithms` failed before and passed after; `TestPasswordVersionClaim` passed. See details below. |
| ARTEX-013 | P2 | PENDING VALIDATION | Safe Docker Desktop deployment and readiness | Config, build, readiness, migration tests |

For each validated finding add root cause, affected files, remediation, test command and result, residual risk and commit. A skipped check remains skipped.

## ARTEX-012 validation and remediation

Root cause: `verifyJWT` accepted any HMAC signing method and did not require expiration, the ARTEX subject or an explicit `pwd` claim when the current version was zero. `jwtSubject` separately parsed the token with similarly broad rules. The pre-fix regression accepted all five malicious synthetic tokens (HS384, missing expiration, wrong subject, missing subject and missing password version). The current patch uses one parser with the JWT library's valid-method, expiration and subject options, and requires an explicit `pwd` equal to the current version. It preserves normal `signJWTVersion` tokens and the existing password-version test. Modified files: `server/auth.go`, `server/auth_jwt_strict_test.go`. Fix commit: `089299b`. Issuer and audience are not minted by this existing single-operator protocol and remain a future protocol decision. The browser still stores tokens in `localStorage` and accepts URL tokens; ARTEX-006 remains open.

Observed checks: focused regression and `TestPasswordVersionClaim` passed; `go vet ./server` and focused `go test -race` passed. The first container run passed with skips after six root isolation tests failed because the restricted UID could not execute Go's temporary test binary. A subsequent isolated Go 1.26.11 run against disposable PostgreSQL 16 passed `go test -exec /tmp/artex-test-exec.sh -p 1 ./...` with no command-line skips; the wrapper only made that temporary test binary accessible to the restricted UID. `go vet ./...` and the CI-selected `go test -race` package list passed on the pre-ARTEX-011 code. The non-verbose suites did not list test-level skips; CI documents two self-skipped tests. No deployment validation was performed.

## ARTEX-011 validation and remediation

Root cause: login validated the password against a database hash, then signed a token with the mutable in-memory password version. A barrier-controlled test forced a rotation between these steps and observed an old password mint a token at the new version. `db.GetAuthSnapshot` now reads hash and version in one PostgreSQL statement, so login signs only the version paired with the validated hash. In-memory version updates no longer regress when concurrent rotations finish their post-commit work out of order. Modified files: `db/settings.go`, `server/auth.go`, `db/settings_insert_test.go`, `server/auth_concurrency_test.go`, `server/login_limit_test.go`.

The focused normal and race-enabled tests for the login barrier, out-of-order version updates, database snapshot and existing auth/version cases passed against the disposable PostgreSQL database. The full post-fix `go test -exec /tmp/artex-test-exec.sh -p 1 ./...` suite passed after updating an existing test fixture to expect a 503 login response while its password-version row is deliberately corrupt, and successful login after repair. A concurrent rotation can still make a just-issued old-version token unusable; that is safe, but may require retrying login. Cross-process session revocation and the broader browser session design remain open under ARTEX-006. Commit reference is pending.
