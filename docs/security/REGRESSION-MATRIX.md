# ARTEX-Galactus security regression matrix

The initial baseline had no passing dynamic security regression. ARTEX-012 is now confirmed by a failing pre-fix test and passing post-fix checks. Other findings remain **PENDING VALIDATION**.

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
| ARTEX-011 | P1 | PENDING VALIDATION | Consistent password version | Barrier-controlled rotation/login and race tests |
| ARTEX-012 | P2 | CONFIRMED; FIXED LOCALLY | Strict HS256, expiration, subject and explicit password version | `TestSessionJWTRejectsUnsupportedClaimsAndAlgorithms` failed before and passed after; `TestPasswordVersionClaim` passed. See details below. |
| ARTEX-013 | P2 | PENDING VALIDATION | Safe Docker Desktop deployment and readiness | Config, build, readiness, migration tests |

For each validated finding add root cause, affected files, remediation, test command and result, residual risk and commit. A skipped check remains skipped.

## ARTEX-012 validation and remediation

Root cause: `verifyJWT` accepted any HMAC signing method and did not require expiration, the ARTEX subject or an explicit `pwd` claim when the current version was zero. `jwtSubject` separately parsed the token with similarly broad rules. The pre-fix regression accepted all five malicious synthetic tokens (HS384, missing expiration, wrong subject, missing subject and missing password version). The current patch uses one parser with the JWT library's valid-method, expiration and subject options, and requires an explicit `pwd` equal to the current version. It preserves normal `signJWTVersion` tokens and the existing password-version test. Modified files: `server/auth.go`, `server/auth_jwt_strict_test.go`. Fix commit: `089299b`. Issuer and audience are not minted by this existing single-operator protocol and remain a future protocol decision. The browser still stores tokens in `localStorage` and accepts URL tokens; ARTEX-006 remains open.

Observed checks: focused regression and `TestPasswordVersionClaim` passed; `go vet ./server` and focused `go test -race` passed. `go test -p 1 ./...` passed with a broad skip expression, followed by `go test ./server -count=1` with a skip expression matching exactly the six root isolation tests that failed in the baseline container; that server run also passed. The full unskipped baseline failed in those six tests because the restricted UID could not execute Go's temporary test binary. PostgreSQL-backed tests were not exercised; the test database was not configured. No deployment validation was performed.
