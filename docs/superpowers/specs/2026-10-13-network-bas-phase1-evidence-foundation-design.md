# Network BAS Phase 1: Evidence Foundation & Discovery — Implementation Specification

**Parent spec:** `docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md` (master architecture, §4 Phase 1). This document implements that phase's roadmap-level definition at file/interface level. It does not re-derive architecture already locked there — see that document for the three-evidence-domain model, the reuse boundaries, and the vantage-point decision this spec implements.

**Locked decisions carried in from brainstorming (binding, not re-litigated here):**
- Probes originate only from the orchestrator server process. No agent-based vantage points in this phase.
- Probe method is bounded TCP reachability via `net.DialTimeout`. No host enumeration, no ping sweeps.
- Targets are explicitly authorized — never discovered via scanning.
- Evidence records target, port, vantage-point identity, timestamp, result, timeout/configuration, provenance. Reachable/unreachable/unknown are distinct; a timeout is never reported as a firewall block.
- `cloudgraph.PathState`'s six values are reused verbatim, unchanged semantics.
- The vantage point's declared network position is fixed by server configuration, never caller-supplied per request.
- Orchestration follows the cloud_run precedent (dedicated HTTP API + Postgres), not `scenario.Engine`, because this phase has no agent-side execution to dispatch.

## Scope Refinement Since the Master Spec

The master spec listed "network asset, network zone" among Phase 1's core types. Implementing this phase concretely surfaces a YAGNI problem: Phase 1 has no asset-inventory-import mechanism (explicitly deferred) and no zone/segmentation model (that is Phase 2's job). Building `NetworkAsset`/`NetworkZone` types now would mean types with no code that populates or consumes them.

**Refinement:** Phase 1 ships `Target` (a bare host/port/protocol triple, optionally carrying a caller-supplied label), not `NetworkAsset`. `NetworkAsset`/`NetworkZone` are introduced in Phase 2, when there is an actual consumer (zone-boundary test-matrix generation) and, ideally, the inventory-import mechanism to populate them meaningfully. This is a scope narrowing, not a reversal of the architecture — `Target` still carries `cloudgraph.Provenance` and resolves to `cloudgraph.PathState`-classified observations exactly as the master spec intends. Flagging this explicitly for your review rather than silently departing from the parent spec's wording.

## 1. Package Layout

New package: `orchestrator/internal/networkgraph/`

| File | Responsibility |
|---|---|
| `types.go` | `Target`, `VantagePoint`, `NetworkObservation`, `NetworkFinding`, `NetworkEvidence` — pure types, no I/O. Imports `cloudgraph.PathState` and `cloudgraph.Provenance` directly (the one deliberate cross-package dependency, per the master spec). |
| `vantagepoint.go` | `VantagePoint` resolution from server configuration (env vars), fail-closed if unset. No per-request override path exists anywhere in this file. |
| `probe.go` | `TCPReachabilityProbe` interface + `DialerProbe` (real `net.DialTimeout`-backed implementation). Maps raw dial outcomes to `cloudgraph.PathState`. |
| `discovery.go` | `RunDiscovery(ctx, vp VantagePoint, targets []Target, opts DiscoveryOptions) (*DiscoveryResult, error)` — bounded-concurrency orchestration, caps enforcement, builds observations/findings/evidence. |

New files in existing packages, mirroring the `cloud_run` precedent exactly:

| File | Responsibility |
|---|---|
| `orchestrator/internal/db/networkdiscovery_store.go` | `EnsureNetworkDiscoverySchema`, `NetworkDiscoveryRun` type, `InsertNetworkDiscoveryRun`, `GetNetworkDiscoveryRun`, `ListNetworkDiscoveryRuns`, `InsertNetworkObservations` (batch). |
| `orchestrator/internal/api/networkdiscovery_handlers.go` | `TriggerNetworkDiscoveryRun` (POST), `ListNetworkDiscoveryRuns` (GET), `GetNetworkDiscoveryRun` (GET). |

Modified files: `orchestrator/internal/api/routes.go` (register 3 routes), `orchestrator/internal/api/rbac_matrix_test.go` (3 matching rows), `orchestrator/cmd/server/main.go` and `orchestrator/internal/testutil/testdb.go` (wire `EnsureNetworkDiscoverySchema`, same call-site pattern as `EnsureCloudRunSchema`), and `orchestrator/cmd/server/main.go` again for vantage-point config loading at startup.

## 2. Core Types (`networkgraph/types.go`)

```go
package networkgraph

import (
    "time"
    "github.com/audspect/bas/internal/cloudgraph"
)

// Target is a single, explicitly authorized probe destination. There is no
// discovery-of-targets in this phase -- every Target is supplied by an
// authenticated, permissioned caller, never derived from scanning.
type Target struct {
    Host     string `json:"host"`
    Port     int    `json:"port"`
    Protocol string `json:"protocol"` // "tcp" only in this phase; field exists for forward compatibility
    Label    string `json:"label,omitempty"`
}

// VantagePoint identifies where probes actually originate. Populated once,
// at server startup, from operator configuration -- never from a request
// body. See vantagepoint.go.
type VantagePoint struct {
    ID             string `json:"id"`
    NetworkPosition string `json:"networkPosition"` // operator-supplied free text, e.g. "customer-dc1-mgmt-vlan"
}

// NetworkObservation is one probe's result against one Target, from one
// VantagePoint, at one point in time.
type NetworkObservation struct {
    ID             string              `json:"id"`
    RunID          string              `json:"runId"`
    Target         Target              `json:"target"`
    VantagePointID string              `json:"vantagePointId"`
    State          cloudgraph.PathState `json:"state"`     // Observed | Blocked | Unknown in this phase (see probe.go)
    ErrorDetail    string              `json:"errorDetail,omitempty"`
    Provenance     cloudgraph.Provenance `json:"provenance"`
}

// NetworkFinding is the reporting-layer unit: one Target's final classification
// for a run, derived from its NetworkObservation, never invented.
type NetworkFinding struct {
    Target      Target               `json:"target"`
    State       cloudgraph.PathState `json:"state"`
    Limitations string               `json:"limitations,omitempty"` // e.g. "timeout is not proof of a firewall block"
}
```

`NetworkEvidence` is not a fourth type — `NetworkObservation.Provenance` (reusing `cloudgraph.Provenance{Source, ObservedAt, CollectionAge, Confidence, ErrorDetail}` verbatim) *is* the evidence record. Introducing a separate `NetworkEvidence` type with the same fields would duplicate `Provenance` for no reason; flagging this as another scope narrowing from the master spec's phrasing ("network evidence record" as its own type) for your review.

## 3. Vantage Point Resolution (`networkgraph/vantagepoint.go`)

```go
// LoadVantagePoint reads NETWORK_VANTAGE_POINT_ID and
// NETWORK_VANTAGE_POINT_POSITION from the environment. Returns an error if
// either is unset or empty -- there is no default, because a default would
// be exactly the "declare a position we don't actually occupy" failure mode
// the locked decision rules out. Called once at server startup (main.go);
// the resolved VantagePoint is held by the Handler, never re-read per request.
func LoadVantagePoint() (VantagePoint, error)
```

If unset, `main.go` logs a clear startup warning and the discovery API returns `503 Service Unavailable` with `"network discovery vantage point not configured"` rather than silently using an empty or fabricated value — this is a deliberate fail-closed choice protecting evidence integrity, flagged for your review since the master spec didn't specify the unset-config behavior explicitly.

## 4. Probe Implementation (`networkgraph/probe.go`)

```go
type TCPReachabilityProbe interface {
    Probe(ctx context.Context, target Target, timeout time.Duration) (cloudgraph.PathState, error)
}

// DialerProbe is the only real implementation. It calls net.DialTimeout
// and classifies the outcome:
//   - connection succeeds                  -> Observed   (closes the connection immediately; sends/reads nothing)
//   - connection actively refused           -> Blocked
//   - timeout, or any other dial error      -> Unknown    (NEVER Blocked -- a timeout proves nothing about why)
type DialerProbe struct{}
func (DialerProbe) Probe(ctx context.Context, target Target, timeout time.Duration) (cloudgraph.PathState, error)
```

No data is written to or read from the connection beyond the TCP handshake itself — this is a pure reachability check, not a service/banner probe, keeping it unambiguously non-disruptive per the locked decision.

## 5. Discovery Orchestration (`networkgraph/discovery.go`)

```go
type DiscoveryOptions struct {
    TimeoutPerTarget time.Duration // caller-requested, server-clamped (see caps below)
    MaxConcurrency   int           // server-fixed, not caller-configurable in this phase
}

type DiscoveryResult struct {
    Observations []NetworkObservation
    Findings     []NetworkFinding
}

// RunDiscovery probes every target with bounded concurrency (a worker pool,
// not sequential -- sequential would make a 50-target request take up to
// 50x the per-target timeout). Each target's probe failure is isolated:
// one target's error never aborts the others' probes, matching the same
// per-account isolation principle already proven in cloud_campaign's
// CreateCloudCampaign.
func RunDiscovery(ctx context.Context, vp VantagePoint, targets []Target, opts DiscoveryOptions) (*DiscoveryResult, error)
```

**Safety caps (constants in `discovery.go`, mirroring `cloud_campaign`'s `maxCloudCampaignAccounts`/`maxEdgesPerAccount` precedent):**
- `maxTargetsPerRun = 50` — bounds blast radius; a request exceeding this is rejected before any probing starts (whole-request rejection, same pattern as `cloud_campaign`'s account cap).
- `defaultProbeTimeout = 2 * time.Second`, `maxProbeTimeout = 5 * time.Second` — a caller-requested timeout above the max is rejected, not silently clamped, so a caller can't quietly tie up a worker slot longer than intended.
- `maxConcurrency = 10` — fixed, not caller-configurable.
- `maxRunDuration = 30 * time.Second` — a `context.WithTimeout` wrapping the whole `RunDiscovery` call; a run that would exceed this is capped, with any still-outstanding targets recorded as `Unknown` with an explicit "run deadline exceeded" provenance note, never silently dropped from the response.

## 6. Database Schema (`db/networkdiscovery_store.go`)

```sql
CREATE TABLE IF NOT EXISTS network_discovery_runs (
    id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    vantage_point_id text       NOT NULL,
    requested_by    text,
    target_count    int         NOT NULL,
    status          text        NOT NULL,  -- 'completed' (every target probed within the run deadline, regardless of each target's own PathState), 'partial' (the 30s run deadline hit before every target was probed -- the remainder are recorded as Unknown with an explicit deadline-exceeded note, never dropped), or 'failed' (the run itself never persisted any observations, e.g. a DB write failure -- mirrors cloud_run's "nothing persisted" edge case)
    started_at      timestamptz NOT NULL DEFAULT NOW(),
    completed_at    timestamptz
);

CREATE TABLE IF NOT EXISTS network_observations (
    id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
    run_id          text        NOT NULL REFERENCES network_discovery_runs(id),
    target_host     text        NOT NULL,
    target_port     int         NOT NULL,
    target_label    text,
    vantage_point_id text       NOT NULL,
    path_state      text        NOT NULL,  -- one of cloudgraph.PathState's six values, stored as text
    error_detail    text,
    observed_at     timestamptz NOT NULL,
    confidence      text
);
CREATE INDEX IF NOT EXISTS idx_network_observations_run ON network_observations (run_id);
```

Functions mirror `cloudrun_store.go`'s exact shape: `InsertNetworkDiscoveryRun`, `GetNetworkDiscoveryRun` (404 via `errors.Is(err, pgx.ErrNoRows)`), `ListNetworkDiscoveryRuns(ctx, pool, limit)`, `InsertNetworkObservations(ctx, pool, runID string, obs []networkgraph.NetworkObservation) error` (batch insert, one transaction).

## 7. HTTP API (`api/networkdiscovery_handlers.go`)

| Method | Path | Permission | Behavior |
|---|---|---|---|
| POST | `/api/network-discovery-runs` | `auth.CanRunScenario` (reused, matching `cloud_run`/`cloud_campaign`'s own reasoning: no role grants network-discovery execution separately from scenario execution today) | Decodes `{targets: [{host, port, protocol, label}], timeoutPerTargetMs?}`. Validates: `targets` non-empty, `len(targets) <= maxTargetsPerRun`, each target's host non-empty and port in `[1,65535]`, `timeoutPerTargetMs` (if supplied) `<= maxProbeTimeout`. Body size bounded via `http.MaxBytesReader`, same lesson learned from `cloud_campaign`'s final-review fix. Returns 503 if the vantage point isn't configured. Runs `networkgraph.RunDiscovery`, persists the run + observations, responds `201` with the run ID, vantage point, and per-target findings. |
| GET | `/api/network-discovery-runs` | baseline-auth-only | Same limit-clamp convention as `ListCloudRuns` (default 20, max 100, malformed falls back silently). |
| GET | `/api/network-discovery-runs/{id}` | baseline-auth-only | 404 via `errors.Is(err, pgx.ErrNoRows)`, includes the run's full observation list. |

`RequestedBy` is server-controlled from `auth.ClaimsFrom(r.Context())`, never trusted from the request body — identical discipline to `cloud_run`'s `InitiatedBy`.

## 8. Acceptance Criteria (Implementation-Level)

- A request with zero targets is rejected (400), nothing persisted.
- A request with 51 targets is rejected (400) before any probe runs, nothing persisted.
- A request with a `timeoutPerTargetMs` above 5000 is rejected (400).
- An oversized request body is rejected before full JSON decode (`http.MaxBytesReader`).
- A successful TCP connect to a real listener (test fixture: an `httptest`-style raw TCP listener spun up in the test) is recorded as `Observed`.
- A connection actively refused (test fixture: dial a closed port) is recorded as `Blocked`.
- A connection that times out (test fixture: a listener that accepts but never completes the handshake, or a non-routable test address) is recorded as `Unknown`, and the finding's `Limitations` field states a timeout is not proof of a block.
- One target's probe error never prevents other targets in the same run from completing and being recorded correctly (isolation test, mirroring `cloud_campaign`'s per-account isolation test).
- A run that exceeds the 30-second deadline before every target is probed is recorded as `partial`, with each un-probed target recorded as `Unknown` and an explicit deadline-exceeded note — never silently dropped from the response or the persisted observation set. This is the one status branch unlikely to be reachable through an ordinary fast-fixture integration test, so it gets a direct unit test against `RunDiscovery` with an artificially short deadline, the same "prove the hard-to-reach branch directly" pattern used for `bucketCloudRunStatus`'s non-terminal-status branches.
- `RequestedBy` is always the authenticated caller, never a client-supplied value, even when the request body includes one.
- Discovery is refused with `503` when the vantage point is not configured (test fixture: construct a `Handler` without calling `LoadVantagePoint`).
- `GET /api/network-discovery-runs/{id}` round-trips a triggered run including all its observations.
- `GET /api/network-discovery-runs/{id}` on a nonexistent ID returns 404.
- RBAC matrix rows exist for all three routes and `TestRBACMatrix_NoDrift` passes.

## 9. Safety Constraints Carried Into Tests

- No test may perform a real probe against any host outside test-local fixtures (loopback/test listeners only) — consistent with "no production network traffic from the test suite" conventions already established in this repo (e.g., `testcontainers-go`-backed DB tests never touch a real external service).
- The 50-target, 5-second-timeout, 10-way-concurrency, 30-second-run-deadline caps are each covered by at least one test proving the cap is enforced, not merely documented.

## 10. Explicitly Out of Scope for Phase 1

- Asset-inventory import/comparison (needs its own design once a real inventory source is identified).
- `NetworkAsset`/`NetworkZone` types (deferred to Phase 2, per the Scope Refinement above).
- Any vantage point other than the orchestrator server process itself.
- Any probe type beyond bounded TCP connect (no UDP, no ICMP, no service/banner identification).

## 11. Testing Strategy Summary

Pure-logic unit tests for `networkgraph` (probe classification, cap enforcement, concurrency isolation) requiring no database — mirroring the `TestBucketCloudRunStatus_EveryBranch` direct-unit-test pattern for branches integration can't reach (e.g., the run-deadline-exceeded path). Integration tests for the DB store and HTTP handlers follow the exact `cloudrun_store_test.go`/`cloudrun_handlers_test.go` pattern already established this session (`sharedDB.RunWithPool`, `seedUser`, `authedRequest`, `callAuthed`).
