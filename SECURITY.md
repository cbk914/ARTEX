# Security Policy

## Supported Versions

ARTEX is an autonomous penetration-testing tool. Security fixes are provided only for the latest official release line. The `main` branch is not considered a stable release and may change at any time.

Only the latest release line receives security fixes. Older releases do not receive fixes; please upgrade to the latest release.

Notes:
- Please upgrade to the latest release before reporting a vulnerability.
- Forks, custom builds from arbitrary commits, and modified versions are not covered by official support.

## Reporting a Vulnerability

**Do not open a public issue for a security vulnerability.**

Sign in to GitHub and use the [private vulnerability report form](https://github.com/BaaRai/ARTEX/security/advisories/new). You can also reach it from the repository's **Security and quality** tab under **Advisories** → **Report a vulnerability**. This is the only reporting channel.

Please include:
- A description of the vulnerability and its expected impact.
- The ARTEX version and/or commit hash.
- Runtime environment (OS, Docker/local, PostgreSQL, LLM provider, etc.).
- Minimal reproduction steps (PoC).
- Logs, screenshots, or sample traffic with **sensitive data removed**.
- Suggested remediation, if available.

**Do not send** real third-party data, credentials, tokens, customer data, or unredacted sensitive content.

## Scope and Authorized Testing

ARTEX is an offensive-security tool. Test only against:
- Your own ARTEX deployment in a lab or local environment;
- Systems you own;
- Targets explicitly authorized in writing (bug bounty, pentest contract, etc.).

Testing, scanning, or exploiting third-party systems without explicit authorization is strictly prohibited. Reports that violate this principle may be closed without action.

## Trusted Inputs and Scope Enforcement

ARTEX treats the `scope_distance` field in `ingest_bbot` output (`output.json`) as the scanner's own classification. An asset event marked `0` is passed to `insert_assets`; that classification is not operator authorization to execute against the target.

The asset-insertion boundary is `insert_assets`, which runs every candidate through `EvaluateAssetGate`: block rules always apply, and a task allow-list is enforced when one is configured. A rejected candidate is returned as an `insertion forbidden` error for that asset and is not inserted. Asset insertion is separate from execution authorization; rejection here does not establish that every executor route is blocked from contacting the target. `in_scope_not_asset` in the `ingest_bbot` result is a different count: scanner-classified in-scope events that are not asset types (findings and the like).

When a task has no allow-list, any scanner-classified in-scope asset that is not blocked can enter the graph and create an automatic coverage row. The target gate is opt-in and its allow decision does not use these insertion rules. There is no independent default-deny campaign network boundary. Operators should treat scanner and agent scope as discovery and coverage data only. [ADR 0004](docs/security/adr/0004-discovery-and-execution-authorization.md) records the required operator grant model and migration; ARTEX-009 remains open.

## Outbound Model Listing (`POST /api/llm/models`)

`POST /api/llm/models` fetches model lists from the provider endpoint and optional HTTP proxy supplied in the request. By default, ARTEX allows only `http` and `https` URLs whose hosts resolve exclusively to public IP addresses (blocking loopback, RFC1918 private networks, IPv6 unique-local `fc00::/7`, link-local/cloud metadata such as `169.254.169.254`, unspecified, and multicast addresses, carrier-grade NAT `100.64.0.0/10`, the benchmarking range `198.18.0.0/15`, `192.0.0.0/24` and the reserved block `240.0.0.0/4`; a NAT64 `64:ff9b::/96` or 6to4 `2002::/16` address is judged by the IPv4 address it embeds), and enforces the same checks on redirects and at dial time. A non-200 answer from the endpoint is reported by its status only; its body is not returned. The built-in local Ollama default (`http://127.0.0.1:11434/v1`) is permitted only when the request leaves `base_url` empty for the `ollama` provider.

Operators running self-hosted LLM gateways or Ollama on a LAN or Docker bridge can allow specific endpoints with `ARTEX_LLM_PRIVATE_ENDPOINTS`, a comma-separated list of exact `host:port` entries (for example, `127.0.0.1:11434,host.docker.internal:11434,192.168.1.10:11434`). A URL whose `host:port` matches an entry may resolve to a loopback or private address, or to an address in `100.64.0.0/10` or `198.18.0.0/15` (an overlay network, a fake-IP resolver), while scheme restrictions, link-local/cloud-metadata blocks, the other reserved ranges above, and redirect validation still apply; everything else stays refused. Leaving `ARTEX_LLM_PRIVATE_ENDPOINTS` unset or empty keeps the strict public-only policy.

## Agent Process Isolation

The server uses a privileged control plane and drops Bash, interactive shell, custom-tool and stdio MCP child processes to an executor UID/GID when execution privilege is enabled. File tools use `os.Root` confinement to their run directory. Key files and configuration are kept outside the executor's writable paths. These controls reduce exposure to the control plane, but **they do not isolate campaigns**: all campaigns currently share one executor UID/GID, one `<data>/exec-home` and cache, and a group that can read run directories and spill files from other campaigns. A disposable synthetic Linux probe confirmed cross-campaign file read/write, shared HOME state and process signaling. No campaign-specific process or network sandbox is implemented. A separate loopback-only mock probe confirmed an unapproved custom-tool executor connection. The target gate is not a substitute for a network boundary around arbitrary child processes. See [ADR 0002](docs/security/adr/0002-campaign-execution-boundary.md) for the proposed broker and [ADR 0003](docs/security/adr/0003-campaign-network-authorization.md) for network policy gates.

On the local ARTEX-Galactus remediation branch, workspace list, read, download, write, mkdir, upload and delete operations open through `os.Root`, with deterministic parent-swap regressions. This limits escapes outside the data root. The workspace still uses denied internal prefixes rather than an explicit allow-list; an in-root link can reach a denied subtree after validation. Existing-file writes and workspace uploads can leave partial content after cancellation or I/O failure. Hardlinks, mount boundaries and restricted filesystem identity need further review. Archive packaging and other privileged file paths remain under review.

New `ask_operator` screenshots on this local branch are staged under a server-owned `operator-evidence` directory outside the executor tree, with bounded copying, content-format checks, task/intent metadata and SHA-256 verification on authenticated delivery. This does not retroactively authenticate historical evidence under `tasks/<id>/uploads`. The new store requires a private data root; native Windows staging fails closed until ACL verification is implemented. The current Docker Desktop deployment uses a Linux volume with `/app/data` owned by root and mode 0755, as observed without changing it.

## ARTEX-Galactus local remediation branch

The local `codex/security-remediation` branch also includes strict JWT claim validation (ARTEX-012), a consistent password-hash/version snapshot for login (ARTEX-011), and exclusive confined chat-upload creation (partial ARTEX-003). Chat uploads remain in agent-writable run directories and can be changed after acknowledgement. The password-change endpoint now rejects foreign-origin requests authenticated by browser cookie. Browser login and setup use server-owned HttpOnly cookies, the UI migrates legacy tokens, and JWT query parameters no longer authenticate streams. Logout records a token digest in PostgreSQL so the same JWT is rejected if copied as a bearer. ARTEX-006 remains partially open pending browser and deployment acceptance. Campaign-specific execution, HOME/cache and network authorization remain architectural work. These changes have **not** been deployed or published.

The [remediation matrix](docs/security/REGRESSION-MATRIX.md) records test evidence and open work. [ADR 0001](docs/security/adr/0001-protected-artifact-storage.md) proposes the broader protected artifact exchange needed for chat uploads and campaign isolation; the `ask_operator` store is a narrower local mitigation.

## What to Expect

This is an open-source project maintained on a best-effort basis. We aim to acknowledge a report within about a week and keep you updated, but we cannot guarantee specific response or fix timeframes.

## If a Report Is Accepted

- We will open a private **GitHub Security Advisory** for coordination.
- We will identify the release containing the fix when it is published.
- We may request a **CVE** if the vulnerability qualifies.
- We will credit you or your organization in the advisory if you wish.
- Default disclosure timing: **90 days** after a fix is available, or earlier by mutual agreement. If the vulnerability is being exploited in the wild, we may disclose earlier.

## If a Report Is Declined

We will explain the reason, for example:
- It is not a security vulnerability but intended behavior.
- It is outside ARTEX’s scope (e.g., an issue in an LLM provider, PostgreSQL, Docker, or a browser).
- There is insufficient information to reproduce it.
- The report only states that “the tool can be misused” without identifying a specific technical flaw in ARTEX.

Where appropriate, we may convert the report into a public hardening issue or feature request.

## Out of Scope

The following are generally **not** considered ARTEX security vulnerabilities:
- Attacks or scans against systems you do not own or are not authorized to test.
- Self-XSS, spam, or brute-force without real impact.
- Large-scale DoS/DDoS or resource-exhaustion attacks.
- Social engineering targeting maintainers or users.
- Issues that exist only in third-party dependencies and do not affect ARTEX.
- Reports that “ARTEX can be used to attack systems” when the user has valid authorization — this is the nature of a penetration-testing tool, not a vulnerability.
- Missing headers or hardening configuration without a concrete security impact.

## Safe Harbor

We welcome ethical security research. If you follow this policy and test only within authorized scope, we will not pursue legal action against you for good-faith research. This does not exempt you from applicable laws in your jurisdiction.

## Disclosure Policy

- Do not publicly disclose vulnerability details before a fix is available or before the coordinated disclosure period ends.
- Do not publish a public PoC without maintainer consent.
- If you do not receive a response within a reasonable time, please ping the contact channel above before disclosing.

Thank you for helping make ARTEX safer.
