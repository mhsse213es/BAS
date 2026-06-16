# Detections Loop — Design (v1)

**Date:** 2026-06-16
**Status:** Approved (design review in `detection.txt` — all 10 additions incorporated; revised to **extend the existing detection pipeline in place** after discovering a coarse v0 already ships).
**Branch:** `feat/detections-loop`

## Existing subsystem this extends (discovered during planning)

A coarse detection pipeline already exists and **must be extended, not duplicated**:

- **Agent** — `collectRecentEvents(ctx, since) []string` (`agent/executor_windows.go:161`, posix no-op stub at `agent/executor_posix.go:33`) collects Defender Operational / Sysmon / Security events as `"eventId:log"` tokens, called per step at `agent/executor.go:104,229`, carried on `ExecResult.Events []string` (`agent/types.go:176`) → `models.SimulationResult.Events` (`internal/models/schema.go:48`) through the existing durable result path. **Weakness:** it sleeps only 300 ms, so it misses the 30–120 s late Defender/EDR alerts.
- **Server** — `internal/reporting/engine.go` already has `type Detection{Detected,Status,Source,Detail}`, `classifyDetection(events []string)` returning **Detected / Logged / None** with a source, `defenderDetectIDs` + `asrBlockIDs` maps, `attributeControl()`, `splitEventToken()`, and `buildDetectionCategories(results)` feeding the report's "Detection coverage by tactic" section (used by both `Build` and `BuildFromRun`).

**Consequence:** the **Logged** tier is already implemented (Change #7 is partly done — keep it, don't "reserve" it). v1 enriches collection (rich records + 90 s grace sweep), extends `classifyDetection` (confidence, `matchedBy`, EDR provider regex), and adds the headline metrics + per-technique badges + retention. It reuses `defenderDetectIDs`/`asrBlockIDs`/`attributeControl`/`buildDetectionCategories` rather than adding a parallel classifier.

## Goal

After a scenario run, determine for each executed technique whether a defensive
**alert** fired on the endpoint, and surface **Prevention / Detection / Undetected
rates + MTTD + per-technique verdicts** in run results and reports. The headline
value is exposing the **"succeeded but undetected"** blind spot — a technique that
the control allowed *and* no defensive tool alerted on.

This closes the purple-team loop the platform is missing: today it proves a
technique executed and whether a control blocked it (prevention), but never asks
whether the EDR/AV *saw* it.

## Decisions (anchored with the user)

1. **Signal source: agent-local collection.** The agent reads the endpoint's own
   defensive signals; no SIEM/EDR API credentials, no extra orchestrator egress,
   works fully air-gapped. Fits on-prem BFSI and the existing agent.
2. **Correlation: windowed presence + raw capture**, upgraded with opportunistic
   corroboration for confidence (see Verdict model). Raw alerts are stored so
   precise technique-mapping can be added later without re-collecting.
3. **Collection scope: Windows alert sources** (Defender Operational, AppLocker/
   WDAC, Defender Firewall, and EDR provider events by regex allowlist). Linux/
   macOS collection deferred (stubs return empty).
4. **Output: Prevention / Detection / Undetected rates + MTTD + per-technique
   badges**, alongside the existing prevention/exposure scores. Fleet-wide
   Detections dashboard deferred.
5. **Collection timing: end-of-run sweep + server-side correlation** (approach A).
   One collection pass after a grace wait; the server owns all correlation and
   verdict logic (honors the "agent is a dumb executor, server interprets"
   architecture).
6. **Extend in place, not parallel.** v1 enriches the existing collector and
   `classifyDetection`/`buildDetectionCategories` rather than building a second
   detection system. The grace-swept rich alerts are delivered on a new
   post-result route (plumbing only — the result is already submitted before the
   90 s grace elapses, so detections must arrive separately and idempotently); the
   server's classification/scoring/report logic stays **unified** in
   `internal/reporting` (+ a small pure `internal/detect` scoring unit). The coarse
   per-step `ExecResult.Events []string` is retained as an immediate, backward-
   compatible fallback when no rich sweep arrives — a graceful fallback, not a
   parallel system.

## Agent architecture boundary (non-negotiable)

The agent **collects raw events** and ships them verbatim. It does **not** decide
what counts as a detection, does not compute confidence, does not assign verdicts.
All correlation/scoring is server-side. The only agent-side "rules" are the
collection filter (which channels/event IDs / provider allowlist to read), which
is server-controllable config with a sane compiled default — collection
configuration, not interpretation.

---

## Components

### Agent (`agent/`, Windows)

New file `agent/detect_windows.go` (with `agent/detect_other.go` no-op stubs for
linux/darwin build tags):

```go
// AlertRecord is one raw defensive event collected from the endpoint. The agent
// fills every field it can extract; the server interprets them. Never the agent.
type AlertRecord struct {
    Channel     string    `json:"channel"`     // e.g. "Microsoft-Windows-Windows Defender/Operational"
    Provider    string    `json:"provider"`    // event provider name (used against the EDR allowlist)
    EventID     int       `json:"eventId"`     // e.g. 1116
    Level       string    `json:"level"`       // Critical|Error|Warning|Information
    Timestamp   time.Time `json:"timestamp"`   // event TimeCreated (UTC)
    ThreatName  string    `json:"threatName"`  // Defender ThreatName / EDR rule name when present
    ProcessName string    `json:"processName"` // when present in event data
    ProcessPath string    `json:"processPath"`
    CommandLine string    `json:"commandLine"`
    User        string    `json:"user"`
    Message     string    `json:"message"`     // rendered event message (truncated)
}

// CollectAlerts reads alert-tier events on this host in [from,to] and returns
// the raw records (capped). Best-effort: any error returns (nil, err) and the
// caller treats detection as unavailable — it never affects the run result.
func CollectAlerts(from, to time.Time, cfg DetectConfig) ([]AlertRecord, error)
```

- Reuses the agent's existing Windows event-log reading mechanism.
- **Caps:** ≤ 500 events and ≤ 512 KB per submission (oldest-first truncation with
  a `truncated:true` flag), so a noisy host can't ship a massive blob.
- Extracts process/path/commandLine/user from event data XML where the event
  exposes them (Defender 1116/1117 and many EDR events do).

### Wire

New endpoint, separate from result submission so detection collection never
delays or risks the result write:

```
POST /api/scenarios/runs/{runId}/detections   (agent auth)
  body: { "alerts": [AlertRecord...], "collectedAt": ts, "windowFrom": ts,
          "windowTo": ts, "truncated": bool }
```

Agent flow: after the final step completes and the result is submitted, the agent
waits `grace_wait` (default **90s**), calls `CollectAlerts(run_start,
run_end + correlation_window)`, and POSTs. Failure is logged and dropped.

### Server (`orchestrator/internal/detect/`)

Pure, independently testable units:

```go
// Verdict per executed technique. Logged already exists in classifyDetection
// (telemetry present, no alert) — v1 keeps it. Aligns with the report's existing
// Detection.Status values ("Detected"/"Logged"/"None").
type Verdict string
const (
    VerdictPrevented  Verdict = "prevented"  // control blocked it (maps to existing PASS)
    VerdictDetected   Verdict = "detected"   // a defensive alert fired in-window
    VerdictLogged     Verdict = "logged"     // telemetry present, no alert (existing tier)
    VerdictUndetected Verdict = "undetected" // executed, not prevented, no alert (blind spot)
)

type TechniqueDetection struct {
    TaskID      string   `json:"taskId"`
    TechniqueID string   `json:"techniqueId"`
    Verdict     Verdict  `json:"verdict"`
    Confidence  string   `json:"confidence,omitempty"` // "high"|"low" when detected
    MatchedBy   []string `json:"matchedBy,omitempty"`  // e.g. ["timestamp","process","commandLine"]
    Alert       *AlertRecord `json:"alert,omitempty"`  // the corroborating alert
    TimeToDetectMs int64 `json:"timeToDetectMs,omitempty"` // alert.ts - step.ts
}

// correlate maps alerts to executed steps. A step matches an alert when the alert
// timestamp is within [step.ts, step.ts + window] (host is implicit — agent reads
// only its own box). matchedBy always includes "timestamp"; "hostname" is implicit.
// When the alert's processName/commandLine/threatName corroborates the step's
// executor/command/technique, the match adds those tags and confidence="high";
// timestamp-only matches are confidence="low". Prevented steps (PASS) are never
// marked detected.
func correlate(steps []StepMeta, alerts []AlertRecord, window time.Duration) []TechniqueDetection

// score computes the three rates + MTTD. Prevented techniques are excluded from
// the detection denominator.
func score(dets []TechniqueDetection) DetectionSummary
```

```go
type DetectionSummary struct {
    PreventionRate int   `json:"preventionRate"` // prevented / executed   (%)
    DetectionRate  int   `json:"detectionRate"`  // detected / (executed - prevented)  (%)
    UndetectedRate int   `json:"undetectedRate"` // undetected / (executed - prevented) (%)  ← key BAS metric
    MTTDMs         int64 `json:"mttdMs"`         // mean time-to-detect over detected techniques
    Executed       int   `json:"executed"`
    Prevented      int   `json:"prevented"`
    Detected       int   `json:"detected"`
    Undetected     int   `json:"undetected"`
}
```

### Reporting / UI (`orchestrator/wwwroot/index.html` + report renderers)

- Run summary gains **Detection Rate**, **Undetected Rate**, and **MTTD** next to
  the existing Prevention/Exposure scores.
- Each technique row in run results and the PDF/HTML report gets a
  **Prevented / Detected (High|Low) / Undetected** badge; detected rows show the
  corroborating alert (provider, event id, threat name, time-to-detect);
  undetected-and-not-prevented rows are flagged as **blind spots**.

---

## Data flow

```
run executes
  └─ run_events already stamp each technique's execution ts (existing)
  └─ result submitted (existing, unchanged)
agent grace-wait (90s)
  └─ CollectAlerts(run_start, run_end + 5m)  → raw AlertRecords
  └─ POST /api/scenarios/runs/{runId}/detections
server
  └─ correlate(step_meta + run_events ts, alerts, window=5m)
        alert.ts ∈ [step.ts, step.ts+window]  ⇒ candidate match
        + process/commandLine/threatName corroboration ⇒ confidence high, matchedBy
        prevented (PASS) ⇒ verdict=prevented (never detected)
  └─ score(...) → PreventionRate / DetectionRate / UndetectedRate / MTTD
  └─ persist (REPLACE — idempotent, like existing result reconciliation)
report / UI read detection_summary
```

**Verdict precedence:** Prevented > Detected > Undetected. Detection Rate and
Undetected Rate are computed over **executed-and-not-prevented** techniques only
(prevented techniques never enter the denominator):

```
100 executed, 20 prevented, 40 detected, 40 undetected
DetectionRate  = 40 / (100-20) = 50%
UndetectedRate = 40 / (100-20) = 50%
PreventionRate = 20 / 100      = 20%
```

## Storage

New columns on `scenario_runs` (`ADD COLUMN IF NOT EXISTS`, matching the existing
migration pattern):

- `detections_raw jsonb NOT NULL DEFAULT '[]'` — raw AlertRecords. **Retention: 30
  days** (pruned by a daily job; see below).
- `detection_summary jsonb` — `{ summary: DetectionSummary, techniques:
  []TechniqueDetection }`. **Retained forever** (small, the audit/trend record).
- `detection_rate int`, `undetected_rate int`, `mttd_ms bigint` — denormalized for
  cheap listing/trend queries.

**Raw retention job:** a daily prune (mirroring `internal/connector/scheduler.go`)
runs `UPDATE scenario_runs SET detections_raw='[]' WHERE completed_at < NOW() -
INTERVAL '30 days' AND detections_raw <> '[]'`. Summaries are never pruned.

## Config (server-side, sane compiled defaults)

```
detect.enabled              = true        # collect on live runs (telemetry/lab)
detect.grace_wait_seconds   = 90
detect.window_seconds       = 300         # 5-minute correlation window
detect.max_events           = 500
detect.max_bytes            = 524288
detect.provider_allowlist   = [regex...]  # see below
```

Posture runs **do not** collect (no attack executed → only noise). Collection is
on by default for live (telemetry/lab) runs and can be disabled globally.

**Provider allowlist — regex, not fixed strings** (vendors change provider names
between versions). Compiled defaults (case-insensitive substring/regex):

```
Microsoft Defender | Windows Defender | Trellix | McAfee | CrowdStrike | Falcon |
SentinelOne | Sophos | Trend ?Micro | Palo Alto | Cortex | Elastic | Rapid7 |
Insight | Fortinet | FortiEDR | Carbon Black | Defender for Endpoint | SENSE
```

Plus always-on Windows block sources by channel+eventID regardless of provider:
Defender Operational `1006/1007/1015/1116/1117`, AppLocker `8003/8004`, WDAC
`3076/3077`, Defender Firewall block events.

## Error handling

- Detection collection is **best-effort and fully isolated** from run results. A
  failed, empty, or never-submitted collection leaves the run valid; Detection
  Rate renders as **"n/a"**. It never blocks or fails a run.
- Submission is **idempotent** (REPLACE, no append, no status guard) — re-delivery
  heals, consistent with the existing run-result reconciliation model.
- Payload is bounded (max events/bytes) with a `truncated` flag surfaced in the
  report so an analyst knows collection was capped.

## Testing

- Server `correlate` and `score` are **pure functions** → unit tests:
  window edge inclusivity, two steps inside one window (alert attributed to the
  nearest preceding step, may match multiple), prevented-precedence (a PASS step
  never becomes detected), confidence high/low by corroboration, matchedBy
  contents, MTTD math, the three rates incl. prevented-excluded denominator,
  empty-alerts → all undetected.
- Agent `CollectAlerts` window bounds + cap/truncation logic tested against
  synthetic event records (no live EDR).
- No live SIEM/EDR; no prod/real Postgres.

## Out of scope for v1 (clean follow-ons the raw-capture model enables)

- Central SIEM/EDR **API pull** (Splunk/Sentinel/Elastic/CrowdStrike/Defender ATP).
- **Precise technique→event mapping** beyond the opportunistic corroboration.
- The fleet-wide **Detections nav dashboard** (ATT&CK heatmap, cross-run trends).
  The `detection_summary` + denormalized rates are stored to make this cheap later.
- **Linux/macOS** collection (the posix `collectRecentEvents` stub stays a no-op).
- (Not deferred — already present: the **Logged** telemetry tier exists in
  `classifyDetection` and is retained.)
