# ADR 0003: Campaign network authorization boundary

Status: proposed, with a staged decision ledger. No network enforcement change or deployment has occurred.

## Evidence and constraint

The task API describes `target_gate` as opt-in. The existing target gate, dial checks and egress governor protect platform-owned paths when they are used; they do not intercept arbitrary sockets opened by Bash, Python, custom tools or stdio MCP processes. An opt-in root-capable Linux probe on 2026-11-27 used the actual custom-tool executor path and connected to a loopback-only mock TCP service with no target authorization configured. The disposable container had no external network. This confirms at least one bypass of a campaign-wide network policy. The probe is diagnostic, not a passing enforcement test.

## Proposed decision

The campaign execution broker from ADR 0002 must create each executor in a private network namespace or equivalent isolated sandbox with no default route. Only the trusted broker may configure its network edge. Agent processes must not receive Docker daemon access, network-administration capabilities or a path to the host network namespace. All outbound connections, including raw sockets and HTTP proxies, must traverse a broker-owned egress gateway that binds the connection to an opaque campaign handle and a current operator-approved policy revision. The target gate remains a complementary early check and operator workflow.

The authorization model separates discovered and candidate assets from operator-authorized destinations (ARTEX-009). Deny and revocation rules take precedence. A rule identifies allowed destination identity, protocol and port range; hostnames are resolved by a broker-controlled resolver and checked at resolution and dial time against the current policy. The gateway records DNS answers and the actual IPv4 or IPv6 peer. HTTP redirects, SOCKS and CONNECT cannot create a second path around the gateway. New connections after revocation are denied against the new policy revision. The system records a bounded, redacted audit event for every denied connection.

Control-plane LLM provider calls and configured MCP infrastructure must use separately named service identities and narrowly scoped exemptions. An exemption for `host.docker.internal` or a proxy must not become general executor access to the Docker host, PostgreSQL, management APIs or private networks. A missing broker, stale policy, resolver failure or unsupported sandbox feature is an operator-visible readiness failure and denies autonomous execution. Authorized local mock targets and approved self-hosted LLM endpoints need distinct test cases.

## Migration and acceptance gates

1. Inventory every process and network-capable tool path. Route Bash, interactive shell, background tasks, custom/Python tools, browser processes and stdio MCP through the broker handle. Keep platform-owned HTTP calls under their existing target checks and classify them by identity.
2. Build a disposable prototype with local authorized, denied and infrastructure mock endpoints. Test direct TCP, UDP, DNS, HTTP redirects, IPv4, IPv6, proxy and raw-socket attempts through each executor path. Include policy revocation between two connection attempts and a broker outage.
3. Confirm planner, worker, chat and MCP functionality against approved destinations. Verify campaign isolation and HOME separation from ADR 0002 in the same sandbox, including concurrent campaigns and sequential reuse.
4. Migrate configuration and operator approvals with versioned policy data. Do not infer execution authorization from discovered assets, scanner output or historical allow-less tasks. Keep the current Docker Desktop deployment unchanged until backup, rollback, readiness and compatibility checks pass.

Changing the default `target_gate` flag or parsing shell commands cannot alone enforce this boundary. ARTEX-004 remains open until the independent gateway and full path matrix are implemented and observed to deny unauthorized connections.
