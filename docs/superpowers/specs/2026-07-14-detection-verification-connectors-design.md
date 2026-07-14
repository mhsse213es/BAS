# Detection Verification Connectors (SP1 first slice) — Design

**Status:** Approved by user 2026-07-14, pending final spec review.
**Supersedes:** the "SP3" naming used in earlier roadmap notes — this is now the platform's SP1 strategic feature ([[project_platform_roadmap_2026h2]]). The old Detection Validation "SP1/SP2" (schema+engine / verification store) are complete and unrelated to this SP1.
**First slice scope:** connector framework + Microsoft Sentinel + Microsoft Defender XDR. QRadar, Splunk, CrowdStrike, Trellix follow in later slices using the same framework.

## Why

Today, off-host detections (SIEM/XDR/identity) sit at `workflow_state=Pending` until an analyst manually attests them in the Detection Validation UI (SP2, shipped). This makes the platform's flagship gap-analysis feature only as fast as an analyst's queue. This slice replaces that manual step for two vendors with an automatic query-and-attest pipeline:

```
... → Verification Store → Manual Review   (today)
... → Connector → Verification Store → Automatic Gap Analysis   (this slice)
```

~80% of the plumbing already exists and needs no changes: the Provider Registry (`internal/scenario/providers.go`), the `ExpectedDetection`/`ExpectedEvidence` schema, `verification.Store.Attest(Source=api)`, and the reporting overlay (`Engine.WithVerifications`). The gap is per-vendor query logic and per-run/per-expectation orchestration.

## Architecture

New package **`internal/detectverify`**, deliberately separate from `internal/siem`:

- `internal/siem` stays untouched. It does bulk per-run correlation by agent IP across a time window and is a shipped, working feature (`AutoCorrelateSIEM`, `siem_configs`, `siem_correlations`). Reusing it here would mean bolting per-expectation, technique-aware verification onto a type built for a different job.
- `internal/detectverify` is verification-first: given one `ExpectedDetection` + the run/step context, answer "did this specific provider raise a matching alert for this specific expectation" and write the answer into the SP2 store. It does not touch `siem_configs`/`siem_correlations`.
- When QRadar's turn comes in a later slice, its Ariel client in `internal/siem/qradar.go` can be extracted into a `detectverify` connector rather than rewritten — the framework doesn't preclude reuse of vendor HTTP clients, only the config/orchestration layer.

### Components

```
internal/detectverify/
  connector.go       // Connector interface, Registry, VerifyRequest/VerifyResult
  entra_auth.go       // shared Entra client-credentials token fetch + cache (Sentinel + Defender XDR both need it)
  sentinel.go         // Log Analytics KQL connector
  defenderxdr.go      // Graph security incidents/alerts connector
  match.go            // host+window+technique matching, confidence scoring
  orchestrate.go       // VerifyRun(ctx, runID) — resolves expectations, calls connectors, attests

internal/api/
  detectverify_handlers.go   // config CRUD + on-demand trigger endpoint (mirrors siem_handlers.go pattern)
  detectverify_handlers_test.go
internal/detectverify/*_test.go
```

```go
// connector.go
type VerifyRequest struct {
    RunID         string
    ExpectationID string
    TechniqueID   string
    HostName      string
    HostIP        string
    WindowStart   time.Time
    WindowEnd     time.Time
}

type VerifyResult struct {
    Verdict          string // "Detected" | "NotDetected"
    Confidence       string // "high" | "medium"
    MatchedAlerts    []MatchedAlert
    DetectionLatency time.Duration // 0 if NotDetected
    InvestigationURL string
}

type MatchedAlert struct {
    AlertID   string
    RuleName  string
    Timestamp time.Time
    Severity  string
    RawJSON   json.RawMessage
}

type Connector interface {
    Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
    TestConnection(ctx context.Context) error
}
```

`Registry` maps a config row's `provider` field (`microsoft_sentinel`, `microsoft_defender` for XDR — reusing the existing Provider Registry keys from `providers.go`) to a constructed `Connector`.

## Data model

New table **`detection_connectors`** (parallel to `siem_configs`, not a reuse of it — Defender XDR is not a SIEM):

```sql
CREATE TABLE detection_connectors (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    provider               TEXT NOT NULL,           -- 'microsoft_sentinel' | 'microsoft_defender'
    enabled                BOOLEAN NOT NULL DEFAULT true,
    auto_verify            BOOLEAN NOT NULL DEFAULT false,
    tenant_id              TEXT NOT NULL,
    client_id              TEXT NOT NULL,
    client_secret          TEXT NOT NULL,            -- encrypted at rest, same handling as siem_configs.token
    workspace_id           TEXT,                     -- Sentinel Log Analytics workspace; empty for Defender XDR
    verify_delay_seconds   INTEGER NOT NULL DEFAULT 120,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Admin CRUD (`internal/api/detectverify_handlers.go`) follows the exact pattern already established by `siem_handlers.go`: secret fields write-only (masked as `"••••••••"` on read), `TestConnection` endpoint does an auth round-trip + a cheap no-op query.

## Data flow

1. **Trigger** (on-demand or auto — see below) calls `detectverify.VerifyRun(ctx, runID)`.
2. Load the run's steps + results (`models.SimulationResult`, same struct the SIEM correlator already consumes) and the run's agent host/IP (same query `SubmitScenarioResult` already runs for `AutoCorrelateSIEM`).
3. For each step's resolved expectations (`scenario.Engine.ResolveStepExpectations`, already exists) whose `Provider` resolves to an **enabled** `detection_connectors` row:
   - Skip if `Verification` (resolved via `scenario.ResolveVerification`) is not `api`, or if the step's BAS verdict is `Pass`/`Blocked` (nothing to alert on — same rule the SIEM correlator uses today) or `Skipped`/`Error`.
   - Build a `VerifyRequest`: window = `[step.ExecutedAt − preWindow, step.ExecutedAt + duration + postWindow]` using the **same `preWindow`/`postWindow` constants `internal/siem/correlator.go` already defines** (2min/5min) — no need to invent new tuning.
   - Call `connector.Verify(...)`.
   - On success, call `verification.Store.Attest(...)` (see gating below).
   - On error, write nothing (see Error Handling).
4. Reporting needs no changes — `Engine.WithVerifications` already overlays whatever the store holds.

## Matching logic

Expectations today have no vendor rule/query field — only `Provider`, `Confidence`, and (via the step) `TechniqueID`. Both Sentinel (via `Microsoft-Sentinel-Analytics-Rule` alerts, which carry ATT&CK tags) and Defender XDR (Graph `alerts.techniques[]`) natively tag alerts with technique IDs, so first-slice matching is:

- **High confidence**: an alert exists in the host+window whose technique tags include the step's `TechniqueID`.
- **Medium confidence**: an alert exists in the host+window with no technique tag (older/custom rules often don't tag) — counted as a match but flagged lower-confidence.
- **No match**: `Verdict = NotDetected`.

`DetectionLatency` = matched alert's earliest timestamp − `step.ExecutedAt`. `InvestigationURL` is built from the config's tenant/workspace + alert ID (Sentinel incident URL / Defender XDR `securitycenter` deep link).

**Future-compatible, not built now:** `ExpectedEvidence` gets no new field in this slice. If a later slice needs an author-pinned rule name, add `ExpectedEvidence.RuleName` then — nothing here blocks it.

## Verdict gating (resolved decision)

- `Verdict=Detected` (any confidence) → `Attest(Result=Detected, WorkflowState=Approved, Source=api)`. Auto-approved: it lands in Coverage immediately, no analyst step.
- `Verdict=NotDetected` → `Attest(Result=NotDetected, WorkflowState=NeedsReview, Source=api)`. A human confirms a real gap before it becomes a scored False Silence finding — avoids a flaky/misconfigured connector silently tanking a customer's score.

This matches the store's existing default: `Attest` treats an empty `WorkflowState` as `Approved`, so the orchestrator sets it explicitly either way rather than relying on that default.

## Trigger model

- **On-demand:** `POST /api/detectverify/run/{runId}` (existing RBAC — same permission tier as `POST /api/siem/correlate/{runId}`).
- **Auto:** fire-and-forget goroutine added at the same call site as `AutoCorrelateSIEM` in `SubmitScenarioResult` (`internal/api/handlers.go:~1795`), gated per-connector by `auto_verify=true`. Each connector's goroutine sleeps `verify_delay_seconds` (default 120s) before verifying, to absorb SIEM/XDR ingestion lag — a real gap in an instant query would otherwise misfire as `NotDetected`.
- **Idempotent:** re-running verification for a run supersedes prior `Source=api` attestations through the store's existing supersede chain — no special-casing needed.

## Error handling

A connector auth failure, timeout, or query error must never produce a false `NotDetected` — that would silently tank a customer's score on a vendor outage. Behavior:

- Any error from `connector.Verify` → log it, write **no** attestation for that expectation, move to the next. The expectation stays whatever it was before (`Pending` if never verified).
- Applies per-expectation, not per-run — one failing expectation doesn't stop the rest of the run's verification pass.
- `TestConnection` in the admin CRUD is how an operator diagnoses a misconfigured connector before it silently no-ops on every run.

## Testing

- **`internal/detectverify/entra_auth_test.go`, `sentinel_test.go`, `defenderxdr_test.go`**: `httptest`-mocked token endpoint + Log Analytics query API + Graph incidents API, same style as the just-shipped `internal/ticketing/jira_test.go`/`servicenow_test.go`. Cover: token fetch + cache reuse, high/medium-confidence matching, no-match → NotDetected, latency computation, investigation-URL construction, HTTP error → `Verify` returns error (not a fabricated NotDetected).
- **`internal/detectverify/orchestrate_test.go`**: container-backed (`sharedDB.RunWithPool`), seeds a run + expectations + a fake `Connector` (no real HTTP), asserts `VerifyRun` writes the right `(Result, WorkflowState, Source=api)` rows via the real `verification.Store`, and that a connector error leaves the row untouched.
- **`internal/api/detectverify_handlers_test.go`**: CRUD (secret masking on read, same assertions the SIEM config tests already make) + on-demand trigger endpoint permission/dispatch test.

## Out of scope for this slice

- QRadar/Splunk/Elastic/CrowdStrike/Trellix connectors (future slices, same `detectverify` framework).
- `ExpectedEvidence.RuleName` author-pinning.
- Any change to `internal/siem` or its bulk correlation feature.
