# ARTEX-Galactus security regression matrix

No dynamic security regression has passed at this baseline. Every status is **PENDING VALIDATION**.

| ID | Priority | Primary invariant | Required evidence |
| --- | --- | --- | --- |
| ARTEX-001 | P0 | Cross-campaign process and file isolation | Concurrent and sequential campaigns |
| ARTEX-002 | P0 | Privileged filesystem confinement | Parent replacement, link and special-file fixtures |
| ARTEX-003 | P0 | Atomic confined uploads | Duplicate, concurrent, cancelled and quota cases |
| ARTEX-004 | P0 | Independent default-deny network authorization | Mock authorized, denied and infrastructure destinations through each executor |
| ARTEX-005 | P0 | Private HOME, cache, temp and browser state | Cross-campaign state and reuse tests |
| ARTEX-006 | P1 | Secure browser sessions | Login, logout, CSRF, stream reconnect, bearer compatibility |
| ARTEX-007 | P1 | Consistent, bounded archive and restore | Concurrent mutation, malformed archive, cancellation, rollback |
| ARTEX-008 | P1 | Immutable, attributed operator evidence | Stage, hash, concurrent modification, display |
| ARTEX-009 | P1 | Discovery cannot grant execution scope | Scanner import, denial precedence, revocation, inheritance |
| ARTEX-010 | P2 | Bounded resource use | Exhaustion, cleanup, evidence preservation |
| ARTEX-011 | P1 | Consistent password version | Barrier-controlled rotation/login and race tests |
| ARTEX-012 | P2 | Strict JWT algorithm and claims | Unsupported algorithm, missing claims, malformed token |
| ARTEX-013 | P2 | Safe Docker Desktop deployment and readiness | Config, build, readiness, migration tests |

For each validated finding add root cause, affected files, remediation, test command and result, residual risk and commit. A skipped check remains skipped.
