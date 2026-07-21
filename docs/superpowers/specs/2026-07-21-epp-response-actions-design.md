# EPP Response Actions — Design

**Status:** Approved (pending final user sign-off on this written doc)

## Problem

Every integration this platform has today is read-only: `detectverify` queries EDR/SIEM alerts, `internal/ioc` enriches indicators, `internal/connector` pulls threat intel. None of it can act on the environment it's validating. `integrations.txt` calls out "verify → remediate → verify again" as the most valuable integration pattern a BAS platform can offer, and today this platform stops at "verify." This closes that gap for the highest-value case: isolating a compromised host, killing a malicious process, and quarantining a dropped file via the EPP vendors already wired into `detectverify` — CrowdStrike Falcon and Microsoft Defender for Endpoint (via Defender XDR).

## Scope

- **Vendors:** CrowdStrike Falcon, Microsoft Defender for Endpoint. Both already have working OAuth + API plumbing in `detectverify` to build on; no new vendor integration from zero.
- **Actions:** Isolate host (network containment), release from isolation, kill process, quarantine file.
- **Trigger:** Manual only, operator-initiated per action. No auto-remediation, no approval queue, no policy engine — see "Deferred" below.
- **Authorization:** A single new Admin-only permission gates execution. No separate approver role exists yet (today's roles are Admin/Analyst/Viewer), so "different approval process" for v1 means "a higher permission bar than any read-only action in the platform," not a request/approve workflow.

## Architecture

```
internal/
    detectverify/          existing — becomes a consumer, not an owner, of vendor auth/API code
    actions/                new — Action model, execution, audit
    vendors/
        crowdstrike/        new — auth, device resolution (+cache), alerts, response actions
        defender/           new — same shape, Microsoft Graph/Defender API
```

**Why move vendor code out of `detectverify`:** today `crowdstrike.go`/`crowdstrike_auth.go` and `defenderxdr.go`/`entra_auth.go` live inside `detectverify`, which the package's own doc comment promises is read-only. Adding write-capable methods to those same connector types would erase that guarantee for every future reviewer. Splitting vendor API/auth code into `internal/vendors/<vendor>` and having both `detectverify` (reads) and `actions` (writes) consume it as a library keeps "can this touch a live endpoint" answerable by which package you're reading, not by which method you're calling. This is a real refactor of shipped code — `detectverify`'s existing tests must still pass unchanged, since only the code's *location* changes, not its behavior.

**Vendor adapter shape** (same shape for both `vendors/crowdstrike` and `vendors/defender`):
```go
package crowdstrike

type Client struct { /* cfg, http.Client, token source, device-ID cache */ }

func New(cfg Config) *Client

// Consumed by detectverify (moved from detectverify/crowdstrike.go as-is).
func (c *Client) QueryAlerts(ctx context.Context, req AlertQuery) ([]Alert, error)

// Consumed by actions (new).
func (c *Client) ResolveDevice(ctx context.Context, hostname string) (deviceID string, err error)
func (c *Client) Isolate(ctx context.Context, deviceID string) (vendorRequestID string, err error)
func (c *Client) Release(ctx context.Context, deviceID string) (vendorRequestID string, err error)
func (c *Client) KillProcess(ctx context.Context, deviceID string, pid int) (vendorRequestID string, err error)
func (c *Client) QuarantineFile(ctx context.Context, deviceID string, filePath string) (vendorRequestID string, err error)
```
`ResolveDevice` is the hostname→device-ID lookup CrowdStrike's and Defender's action APIs require (unlike `detectverify`'s alert queries, which filter by hostname directly). It is a prerequisite for mutation, not verification, so it lives entirely inside `vendors/`, TTL-cached (15 minutes, same pattern as the existing `ioc_enrichment` cache) so a large fleet doesn't hammer a rate-limited device-lookup endpoint on every action. Callers of `actions/` never see a device ID — only a hostname goes in.

**`actions` package — the `Action` model:**
```go
package actions

type Target struct {
    Type       string // "hostname" — the only value implemented in v1
    Identifier string
}

type Request struct {
    Type        string         // "endpoint.isolate" | "endpoint.release" | "endpoint.kill_process" | "endpoint.quarantine_file"
    Target      Target
    Parameters  map[string]any // {"pid": 4821} or {"filePath": "...", "sha256": "..."} — empty for isolate/release
    ConnectorID string         // which configured action_connectors row (vendor + credentials) to use
    RequestedBy string         // user ID
    Reason      string         // required, freeform — audit requirement
    TicketRef   string         // optional freeform reference (e.g. "INC0012345") — not a live ITSM integration in v1
    RunID       string         // optional — links back to the BAS run/finding that prompted this action
}

type Action struct {
    ID, Type          string
    Target             Target
    Parameters         map[string]any
    ConnectorID        string
    Status             string // requested | dispatched | vendor_accepted | vendor_rejected | completed | failed
    ResolvedDeviceID   string
    VendorRequestID    string
    Error              string
    RequestedBy, Reason, TicketRef, RunID string
    RequestedAt, DispatchedAt, CompletedAt time.Time
}

func Execute(ctx context.Context, req Request) (Action, error)
```
`Target.Type` is a string, not a closed enum, so identity/cloud/firewall targets (a real future need per the doc — Entra user, AWS instance, K8s node) can be added later without an API break. Only `"hostname"` is implemented in v1.

`Execute` does, in order: validate `Target.Identifier` is a currently-enrolled agent's hostname (see Safety below) → resolve the connector's vendor client → `ResolveDevice` (cached) → a no-op `checkPolicy(ctx, req) error` hook (so a future policy/approval engine plugs in here without restructuring this function) → dispatch to the vendor method matching `req.Type` → persist the `Action` row at each status transition → write an audit log entry. No `dispatcher/` package — the type→vendor-method routing is a single `switch` inside `Execute`; if a third vendor or a fifth action type makes that unwieldy, extracting a dispatcher is a mechanical, low-risk follow-up, not a decision to make speculatively now.

## Safety

- **Admin-only.** New permission `actions:execute` gates `Execute` — no Analyst-level access, unlike every other "run" permission in this platform (`scenarios:run`, `detectverify:run` are Analyst+Admin).
- **Target must be a known agent.** `Execute` rejects any `Target.Identifier` that isn't the current hostname of an enrolled agent in this platform's `agents` table. An operator cannot type an arbitrary hostname and isolate a host outside the BAS fleet — this mirrors how the multi-agent dispatch work earlier this session only ever lets an operator pick from enrolled agents, never free-type a target.
- **Reason is required.** `Request.Reason` cannot be empty — enforced at the API layer, not just a UI nicety.
- **No retries.** A failed vendor call marks the action `failed` with the error recorded; the operator re-submits explicitly. Matches the existing no-retry convention in `detectverify`'s connectors.

## Configuration

New table `action_connectors`, deliberately separate from `detection_connectors` (mirrors the existing `ioc_enrichment` vs `detection_connectors` separation — different write/read blast radius, different config surface):
```
id, name, provider ('crowdstrike' | 'microsoft_defender'), enabled,
tenant_id, client_id, client_secret, base_url, created_at, updated_at
```
A customer can enable CrowdStrike detection verification without enabling CrowdStrike response actions — expected in regulated environments per the earlier design discussion.

## Data model

New table `action_requests`, persisting every field of the `Action` struct above (`requested_at`, `dispatched_at`, and `completed_at` as separate timestamp columns — no stored `duration_ms`; the API computes duration from those timestamps at read time so it can never drift from them).

This table **is** the audit trail — every field the earlier design discussion called out (timestamp, operator, hostname, resolved device ID, action, reason, ticket, success, vendor request ID) is a column, and duration is one subtraction away from columns that are. No separate "audit log" table for this feature; `internal/api/audit.go`'s existing general audit log additionally gets one entry per action for cross-feature audit search consistency with the rest of the platform.

## Permissions

New, following the existing `domain:action` / Admin-only-connector-config convention exactly:
```go
CanExecuteResponseAction   Permission = "actions:execute"           // Admin-only
CanViewResponseActions     Permission = "actions:view"              // Analyst+Admin — read the audit trail
CanListResponseConnectors  Permission = "actions:connectors:list"   // Admin-only
CanCreateResponseConnector Permission = "actions:connectors:create" // Admin-only
CanUpdateResponseConnector Permission = "actions:connectors:update" // Admin-only
CanDeleteResponseConnector Permission = "actions:connectors:delete" // Admin-only
CanTestResponseConnector   Permission = "actions:connectors:test"   // Admin-only
```

## API routes

Mirrors `detectverify`'s existing route shape exactly:
```
POST   /api/actions/run                    CanExecuteResponseAction
GET    /api/actions?runId=&agentId=        CanViewResponseActions
GET    /api/actions/configs                CanListResponseConnectors
POST   /api/actions/configs                CanCreateResponseConnector
PUT    /api/actions/configs/{id}           CanUpdateResponseConnector
DELETE /api/actions/configs/{id}           CanDeleteResponseConnector
POST   /api/actions/configs/{id}/test      CanTestResponseConnector
```

## UI

Response Actions surface on the existing **Findings** view (`internal/findings`, already the page where `CanPushToITSM` lives) rather than a new page — a finding already carries `AgentID`, which resolves to the agent's current hostname exactly like the Run modal does today. A "Respond" action menu appears per finding row (Admin only — hidden entirely for Analyst/Viewer, not just disabled) with:
- **Isolate host** — no extra input; hostname comes from the finding's agent.
- **Release from isolation** — same.
- **Kill process** — prompts for a PID. There is no run-result field capturing a technique's spawned PID today (confirmed: `scenario/outcome.go` has no process/artifact tracking), so this is operator-entered, informed by their own EDR console.
- **Quarantine file** — prompts for a file path (and optional SHA256). Same reasoning — no dropped-file tracking exists in run results today.

Every action requires the **Reason** field before the confirm button enables, and shows a native `confirm()` with the action, target hostname, and reason echoed back — matching this codebase's existing high-stakes-action pattern (telemetry/lab mode confirms, the multi-agent dispatch confirms from earlier this session).

A **Response Connectors** admin config screen (CrowdStrike / Defender credentials, enable/disable, test connection) lives alongside the existing Detection Verification connector config screen — same visual pattern, separate config.

## Deferred (explicitly out of scope for this plan)

- **Policy/approval engine** (`internal/policy/`) — auto-isolate rules, maintenance windows, per-scenario policies, manager-approval workflows. `Execute`'s `checkPolicy` hook exists so this plugs in without restructuring `actions/`, but no rule language, authoring UI, or approval queue is designed or built here.
- **Pluggable `Approver` backends** (auto/manual/ServiceNow/Jira/webhook) — depends on the policy engine above existing first.
- **`internal/dispatcher/` as its own package** — v1's routing is a `switch` inside `actions.Execute`; extracted later only if warranted by real complexity.
- **`approved` / `rolled_back` status values** — not added until there's an approval engine or a rollback mechanism to put behind them.
- **Identity, Cloud, Firewall action types** (disable Entra user, block IP, disable AWS key, etc.) — `Target.Type` stays open-ended for this, but v1 implements only `"hostname"` for CrowdStrike/Defender.
- **Close-the-loop auto-reverification** (rerun the attack after remediation to confirm it worked) — a strong, explicitly-flagged future sub-project spanning `execution` + `actions` + `detectverify`, not part of this plan.
- **SentinelOne** — third EPP vendor from `integrations.txt`'s list; no existing connector to extend, so it's a from-zero vendor integration, not part of this first cut.
