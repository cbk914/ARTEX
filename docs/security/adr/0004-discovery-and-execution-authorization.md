# ADR 0004: Keep discovery separate from execution authorization

Status: a separate decision ledger, policy evaluator and authenticated operator API are staged locally; no execution authorization boundary is active.

## Observed behavior

`ingest_bbot` treats a scanner-supplied `scope_distance: 0` asset event as an
asset to pass to `insert_assets`. `ingest_scan_output` also passes parsed assets
to that handler. `insert_assets` checks global and task block rules, then task
allow rules, before storing an asset. If no task allow rule is enabled,
`EvaluateAssetGate` permits the insert. It subsequently calls `AddAutoScope`,
which writes a `task_scope` row with source `auto`. The `add_task_scope` agent
tool writes source `agent` rows. These rows drive coverage and asset filtering;
the tool itself says that they do not block execution.

The per-task target gate defaults off (`db.CreateTaskWithOptions`). Even when
enabled, its `BlockRules` path reads global and task block rules, not the
asset-insertion allow rules. Its pins and exemptions are separate from
`task_scope`. A source task can contribute inherited assets to a new task's
context (`IntentAssets`), but that relation is not an execution grant.

Consequently, neither scanner `scope_distance`, an asset row, an auto or agent
coverage row, nor an inherited asset establishes operator permission to send
traffic. Existing execution paths lack an independent default-deny campaign
network boundary (ADR 0003). The current labels and gate behavior must not be
represented as such a boundary.

## Staged decision ledger

Local commit `2a79fb7` adds migration `0016_campaign_network_rules.sql` with
campaign network decisions and a separate revocation table. Application writes
insert decisions and revocations as separate rows. No historical `task_scope`, asset,
target pin or interception row is copied into it. `db.RecordCampaignNetworkRule`
requires an existing live task, an actor, a reason, an allow or deny effect,
an exact hostname, IP or CIDR target, TCP or UDP port bounds and an expiry.
`db.ActiveCampaignNetworkRules` excludes expired and revoked rows and rows for
deleted tasks; revocation is visible through a fresh database read while the
original decision remains for audit. The tests check that agent coverage and
source-task inheritance produce no decision, that a cross-task revocation is
rejected, and that a version-15 database gains the table without altering its
coverage row.

Migration 17 adds `allow_direct` with a false default. The independent gate
consumes fresh rows through `db.LoadCampaignNetworkRules`; a peer-range rule
used to approve a hostname cannot by itself approve direct access to that IP.
The gate has no bound broker handle, agent tool or executor path. Authenticated
`/api/tasks/{id}/network-decisions` routes now list active decisions, create a
new decision and revoke one for the same task. The global auth middleware
rejects missing sessions and cross-origin cookie writes; the route records the
JWT session identifier as actor. Its JSON body is bounded and checked for
unknown fields. Responses explicitly state `enforced:false` while no executor
uses the gate. The route is an approval workflow staging step, not evidence
that traffic obeys the decisions.
Their presence does not authorize or block a network connection in the current
server. A future authenticated operator route must supply the actor and prove
the task grant, and the broker must query current decisions on every new
connection. A database read error, absent approval or missing gateway must
remain a denial; no UI should describe these staged rows as effective scope.

## Required authorization model

Use distinct records for observed assets, candidate targets, coverage scope,
and operator-authorized execution scope. The last record must have a campaign
owner, target pattern and protocol/port restrictions, source approval, creation
time, expiry or revocation state, and immutable audit provenance. Only an
authenticated operator action can create or expand an execution grant. Agent
tools, scanner imports, target content, company attribution, inherited assets,
and coverage rows can create candidates but cannot create grants.

The campaign broker from ADR 0002/0003 must evaluate every connection against
current grants and denials. Explicit deny and revocation take precedence over
grants; absent or unreadable policy fails closed. DNS names and every resolved
address must be checked at the time of use, including redirects, proxies,
IPv6, and direct IP connections. A new campaign starts with no inherited
execution grants. If an operator wants to copy a source campaign's permission,
that must be a new, attributable approval for the destination campaign.

Do not reuse `task_scope` or `task_intercept_rules` as the grant store. Existing
rows were written for coverage or asset insertion and do not prove approval.
Migration may preserve them as context while requiring explicit operator
review before any execution grant is active. Preserve the asset graph,
deduplication, and coverage data during this migration.

## Acceptance tests

1. Import a scanner event claiming `scope_distance: 0` for an unauthorized
   host; preserve it as an observed candidate but deny a connection to it.
2. Have an agent add a root domain to coverage and insert a discovered host;
   neither action changes the broker's execution decision.
3. Approve a narrow host/port grant, then show permitted traffic and denial
   for a sibling host, another port, DNS rebind, and direct IP bypass.
4. Add a block rule or revoke the grant while a campaign is running; all new
   connections are denied, including through custom tools and subprocesses.
5. Create a task from a source task with assets and grants; inherited assets
   remain visible while no source grant is effective in the new task.
6. Fail the policy store and exercise both an empty policy and an expired
   approval; every connection fails closed without erasing discovered data.

Run these against a disposable broker and synthetic local services. Passing
asset-insertion or target-gate unit tests alone cannot satisfy this ADR.
