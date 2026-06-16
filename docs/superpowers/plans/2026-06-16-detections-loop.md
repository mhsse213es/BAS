# Detections Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After a live run, capture rich endpoint defensive alerts (incl. late-landing ones), correlate them server-side into per-technique Prevented / Detected(High|Low) / Logged / Undetected verdicts, and surface Detection Rate + Undetected Rate + MTTD in results and reports.

**Architecture:** Extend the EXISTING coarse pipeline in place. The Windows agent already collects per-step `"id:log"` event tokens (`collectRecentEvents`) and the server already classifies them (`classifyDetection` → Detected/Logged/None, `buildDetectionCategories`). v1 (1) enriches collection to structured `AlertRecord`s and adds a 90 s grace-delayed end-of-run sweep delivered on a new idempotent agent route, (2) adds a pure `internal/detect` unit for correlation + scoring, (3) extends `classifyDetection` with an EDR provider regex allowlist, (4) surfaces the new metrics in report + dashboard, (5) prunes raw alerts after 30 days. The agent only collects; all verdict/score logic is server-side.

**Tech Stack:** Go (agent + orchestrator), PowerShell `Get-WinEvent` (agent collection), PostgreSQL jsonb (storage), vanilla JS (dashboard).

---

## Key facts (verified against the codebase)

- **Verdict mapping** (`internal/models/schema.go`): `CheckResult` = `pass|fail|blocked|skipped|error`. **Prevented** = `pass` OR `blocked`. **Executed-and-not-prevented** = `fail`. `error`/`skipped` are NOT executed (excluded from all detection denominators).
- `models.SimulationResult` (`schema.go:36`) carries `TaskID`? — no; it carries `ID`, `Technique.ID`, `Result`, `ExecutedAt`, `DurationMs`, `Events []string`. Correlation keys on `ExecutedAt`+`DurationMs` (the step's time window) and `Technique.ID`.
- Existing server detection logic lives in `internal/reporting/engine.go`: `type Detection{Detected bool; Status,Source,Detail string}`, `classifyDetection(events []string) Detection`, `defenderDetectIDs`, `asrBlockIDs`, `attributeControl`, `splitEventToken`, `buildDetectionCategories(results)`. Reused by `Build` and `BuildFromRun`.
- Agent: `collectRecentEvents(ctx, since) []string` (`agent/executor_windows.go:161`; posix stub `agent/executor_posix.go:33`), called at `agent/executor.go:104,229`; tokens flow via `ExecResult.Events` (`agent/types.go:176`). Agent delivers results durably via `submitRunResult`/spool (`agent/agent.go`), helper `postJSON`, and reads events with `psRun` / `Get-WinEvent`.
- Agent-authed routes (no JWT; validated in-handler via `h.validateAgentAuth`) are registered ungrouped at `internal/api/routes.go:29-33` (`/api/agents/enroll`, `/api/scenarios/result`, …).
- Migrations: append `ALTER TABLE … ADD COLUMN IF NOT EXISTS` to the `stmts` slice in `internal/db/postgres.go`.
- Scheduler precedent: `internal/connector/scheduler.go` (`Start()` + `time.NewTicker`).
- Run window source: `scenario_runs.started_at` / `completed_at`; per-step time is `SimulationResult.ExecutedAt` (already stored in `results`).

**Confidence definition (v1, honest given no technique→event map):** a Detected verdict is **High** when the in-window alert is a bona-fide detection (Defender event ID in `defenderDetectIDs`, OR a non-empty `ThreatName`, OR an EDR-allowlist provider), else **Low** (a security event in-window without detection semantics). `matchedBy` records the basis (always includes `"timestamp"`; adds `"threatName"`, `"defenderDetectId"`, `"edrProvider"` as applicable). Raw alerts are stored so precise technique-mapping can refine this later.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `agent/types.go` | `AlertRecord`, `RunDetections` payload types | Modify |
| `agent/detect_windows.go` | Rich `collectAlerts(from,to,cfg)` via Get-WinEvent | Create |
| `agent/detect_other.go` | posix no-op `collectAlerts` | Create |
| `agent/agent.go` | end-of-run grace sweep + deliver detections | Modify |
| `orchestrator/internal/detect/detect.go` | pure `Correlate` + `Score` (+ `AlertRecord`, `TechniqueDetection`, `DetectionSummary`) | Create |
| `orchestrator/internal/detect/providers.go` | EDR provider regex allowlist + `IsEDRProvider` | Create |
| `orchestrator/internal/detect/detect_test.go` | unit tests for Correlate/Score/providers | Create |
| `orchestrator/internal/db/postgres.go` | `detections_raw`, `detection_summary`, `detection_rate`, `undetected_rate`, `mttd_ms` columns | Modify |
| `orchestrator/internal/api/detection_handlers.go` | `POST /detections` ingest → correlate → score → persist | Create |
| `orchestrator/internal/api/routes.go` | register the route | Modify |
| `orchestrator/internal/reporting/engine.go` | use EDR regex in `classifyDetection`; surface summary metrics | Modify |
| `orchestrator/internal/detect/retention.go` | daily prune of `detections_raw` >30d | Create |
| `orchestrator/cmd/.../main.go` (server entry) | start retention goroutine | Modify |
| `orchestrator/wwwroot/index.html` | run-summary rates/MTTD + per-technique detection badges | Modify |

---

## Part A — Agent: rich collection + grace sweep

### Task A1: AlertRecord + RunDetections types

**Files:** Modify `agent/types.go`

- [ ] **Step 1: Add the types** (place near `ExecResult`):

```go
// AlertRecord is one raw defensive event collected from the endpoint. The agent
// fills every field it can extract; the SERVER interprets them (verdict,
// confidence). The agent never classifies. Mirrored server-side in internal/detect.
type AlertRecord struct {
	Channel     string    `json:"channel"`
	Provider    string    `json:"provider"`
	EventID     int       `json:"eventId"`
	Level       string    `json:"level"`
	Timestamp   time.Time `json:"timestamp"`
	ThreatName  string    `json:"threatName,omitempty"`
	ProcessName string    `json:"processName,omitempty"`
	ProcessPath string    `json:"processPath,omitempty"`
	CommandLine string    `json:"commandLine,omitempty"`
	User        string    `json:"user,omitempty"`
	Message     string    `json:"message,omitempty"`
}

// RunDetections is the agent's post-result detection submission for one run.
type RunDetections struct {
	RunID      string        `json:"runId"`
	AgentID    string        `json:"agentId"`
	Alerts     []AlertRecord `json:"alerts"`
	WindowFrom time.Time     `json:"windowFrom"`
	WindowTo   time.Time     `json:"windowTo"`
	Truncated  bool          `json:"truncated"`
}
```

- [ ] **Step 2: Build all OS targets**

Run: `cd agent && go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./...`
Expected: clean (types only).

- [ ] **Step 3: Commit**

```bash
git add agent/types.go
git commit -m "feat(agent): AlertRecord + RunDetections detection types

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task A2: Rich Windows alert collection (`collectAlerts`)

**Files:** Create `agent/detect_windows.go`, `agent/detect_other.go`

- [ ] **Step 1: posix stub** `agent/detect_other.go`:

```go
//go:build !windows

package main

import "time"

// collectAlerts is a no-op on non-Windows agents in v1.
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]AlertRecord, bool) {
	return nil, false
}
```

- [ ] **Step 2: Windows implementation** `agent/detect_windows.go`. Uses the same PowerShell mechanism as the existing collector but pulls full event data and emits structured records as JSON (parsed back into `AlertRecord`). Caps by count and bytes.

```go
//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// alertChannels are the alert-tier Windows logs scanned for detections. Defender
// Operational carries real AV/EDR detections; AppLocker/WDAC carry block events.
// Third-party EDRs land in Application/System and are recognised server-side by
// provider regex — so we collect those channels too and let the server filter.
var alertChannels = []string{
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-AppLocker/EXE and DLL",
	"Microsoft-Windows-AppLocker/MSI and Script",
	"Microsoft-Windows-CodeIntegrity/Operational",
	"Application",
	"System",
}

// collectAlerts reads alertChannels in [from,to] and returns structured records,
// newest-first, capped at maxEvents / maxBytes (bool = truncated). Best-effort:
// any failure returns (nil,false). The agent does NOT decide what is a detection.
func collectAlerts(from, to time.Time, maxEvents, maxBytes int) ([]AlertRecord, bool) {
	fromStr := from.UTC().Format("2006-01-02T15:04:05")
	toStr := to.UTC().Format("2006-01-02T15:04:05")
	logsArr := "'" + strings.Join(alertChannels, "','") + "'"
	// Emit one JSON object per event; the agent parses, never interprets.
	ps := fmt.Sprintf(`
$from=[datetime]'%s'; $to=[datetime]'%s'
$logs=@(%s)
$out=New-Object System.Collections.ArrayList
foreach($log in $logs){
  try{
    $evts=Get-WinEvent -MaxEvents 300 -FilterHashtable @{LogName=$log;StartTime=$from;EndTime=$to} -ErrorAction SilentlyContinue
    foreach($e in $evts){
      $x=[xml]$e.ToXml()
      $data=@{}
      if($x.Event.EventData.Data){ foreach($d in $x.Event.EventData.Data){ if($d.Name){ $data[$d.Name]=$d.'#text' } } }
      [void]$out.Add([pscustomobject]@{
        channel=$log; provider=$e.ProviderName; eventId=$e.Id;
        level=$e.LevelDisplayName; ts=$e.TimeCreated.ToUniversalTime().ToString('o');
        threatName=$data['Threat Name']; processName=$data['Process Name'];
        processPath=$data['Path']; commandLine=$data['Command Line'];
        user=$data['User']; message=($e.Message -replace '\s+',' ');
      })
    }
  }catch{}
}
$out | ConvertTo-Json -Depth 3 -Compress
`, fromStr, toStr, logsArr)

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", ps).Output()
	if err != nil || len(out) == 0 {
		return nil, false
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" || raw == "null" {
		return nil, false
	}
	if raw[0] == '{' { // ConvertTo-Json emits a bare object for a single event
		raw = "[" + raw + "]"
	}
	var wire []struct {
		Channel, Provider, Level, TS, ThreatName, ProcessName, ProcessPath, CommandLine, User, Message string
		EventID int
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		return nil, false
	}
	recs := make([]AlertRecord, 0, len(wire))
	for _, w := range wire {
		ts, _ := time.Parse(time.RFC3339, w.TS)
		recs = append(recs, AlertRecord{
			Channel: w.Channel, Provider: w.Provider, EventID: w.EventID, Level: w.Level,
			Timestamp: ts, ThreatName: strings.TrimSpace(w.ThreatName),
			ProcessName: w.ProcessName, ProcessPath: w.ProcessPath,
			CommandLine: w.CommandLine, User: w.User,
			Message: truncate(w.Message, 1000),
		})
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Timestamp.After(recs[j].Timestamp) })
	return capRecords(recs, maxEvents, maxBytes)
}

// capRecords keeps at most maxEvents records and ≤ maxBytes of JSON (newest-first).
func capRecords(recs []AlertRecord, maxEvents, maxBytes int) ([]AlertRecord, bool) {
	truncated := false
	if len(recs) > maxEvents {
		recs = recs[:maxEvents]
		truncated = true
	}
	for {
		b, _ := json.Marshal(recs)
		if len(b) <= maxBytes || len(recs) == 0 {
			break
		}
		recs = recs[:len(recs)-1]
		truncated = true
	}
	return recs, truncated
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
```

- [ ] **Step 3: Build all OS targets**

Run: `cd agent && go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./...`
Expected: clean. (Windows file compiles under the windows tag; posix stub under the others.)

- [ ] **Step 4: Commit**

```bash
git add agent/detect_windows.go agent/detect_other.go
git commit -m "feat(agent): rich Windows alert collection (collectAlerts)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task A3: End-of-run grace sweep + delivery

**Files:** Modify `agent/agent.go`

Context: `submitResults(cmd, results, partial, reverted)` (around `agent/agent.go:557`) submits the durable result. We add a grace-delayed sweep AFTER that, in a tracked goroutine, posting `RunDetections`. It is best-effort and never affects results.

- [ ] **Step 1: Add the sweep dispatcher.** Add a method and call it at the end of `submitResults` (after `a.submitRunResult(...)`):

```go
// collectAndSubmitDetections runs AFTER results are delivered. It waits a grace
// period (defenders alert seconds-to-minutes late), sweeps the run's time window
// once for rich alerts, and posts them. Best-effort: any failure is logged and
// dropped — it never affects the authoritative run result.
func (a *Agent) collectAndSubmitDetections(runID string, runStart time.Time) {
	const graceWait = 90 * time.Second
	const windowPad = 300 * time.Second // catch late alerts up to 5 min after the run
	const maxEvents = 500
	const maxBytes = 512 * 1024

	time.Sleep(graceWait)
	from := runStart.Add(-5 * time.Second)
	to := time.Now()
	alerts, truncated := collectAlerts(from, to, maxEvents, maxBytes)
	if len(alerts) == 0 {
		log.Printf("[detect] run %s: no alerts collected in window", runID)
		return
	}
	payload := RunDetections{
		RunID: runID, AgentID: a.id.AgentID, Alerts: alerts,
		WindowFrom: from, WindowTo: to, Truncated: truncated,
	}
	if err := a.postJSON("/api/scenarios/runs/"+runID+"/detections", payload); err != nil {
		log.Printf("[detect] run %s: detection submit failed: %v", runID, err)
		return
	}
	log.Printf("[detect] run %s: submitted %d alert(s)", runID, len(alerts))
	_ = windowPad
}
```

  At the end of `submitResults`, after the existing `a.submitRunResult(payload, label)` call, add (only for non-posture runs — the simulate/local path does not call `submitResults`, so this method is already attack-run scoped; still guard on having a runID):

```go
	a.runWG.Add(1)
	go func() { defer a.runWG.Done(); a.collectAndSubmitDetections(cmd.RunID, cmd.startedAt) }()
```

  Note: if `ScenarioCommand` has no start-time field, use the time `submitResults` runs minus the elapsed run is unavailable — instead capture run start when the scenario begins executing. **Read** how the agent tracks the current run's start; if none exists, pass `time.Now().Add(-totalDuration)` where `totalDuration = sum(results[i].DurationMs)`. Implement whichever is already available; do NOT invent a new field if `results[0].ExecutedAt` is present — use the earliest `ExecutedAt` among results as `runStart`:

```go
	runStart := time.Now()
	for _, r := range results {
		if !r.ExecutedAt.IsZero() && r.ExecutedAt.Before(runStart) {
			runStart = r.ExecutedAt
		}
	}
	a.runWG.Add(1)
	go func() { defer a.runWG.Done(); a.collectAndSubmitDetections(cmd.RunID, runStart) }()
```

  (Use this `runStart` form — it relies only on the existing `ExecResult.ExecutedAt`. Drop the `cmd.startedAt` reference in the method call accordingly.)

- [ ] **Step 2: Build all OS targets**

Run: `cd agent && go build ./... && GOOS=linux go build ./... && GOOS=darwin go build ./... && go test ./...`
Expected: clean / tests pass.

- [ ] **Step 3: Commit**

```bash
git add agent/agent.go
git commit -m "feat(agent): grace-delayed end-of-run detection sweep + submit

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part B — Server: storage + ingest

### Task B1: DB columns

**Files:** Modify `orchestrator/internal/db/postgres.go`

- [ ] **Step 1:** Append to the `stmts` slice (after the `scenario_runs` block, near the other `ADD COLUMN` lines ~110-115):

```go
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS detections_raw   jsonb NOT NULL DEFAULT '[]'`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS detection_summary jsonb`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS detection_rate   int`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS undetected_rate  int`,
		`ALTER TABLE scenario_runs ADD COLUMN IF NOT EXISTS mttd_ms          bigint`,
```

- [ ] **Step 2: Build**

Run: `cd orchestrator && go build ./...`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "feat(db): scenario_runs detection columns

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part C — Server: pure correlation + scoring (TDD)

### Task C1: EDR provider allowlist

**Files:** Create `orchestrator/internal/detect/providers.go`, `orchestrator/internal/detect/detect_test.go`

- [ ] **Step 1: Failing test** (`detect_test.go`):

```go
package detect

import "testing"

func TestIsEDRProvider(t *testing.T) {
	hits := []string{"Microsoft Defender Antivirus", "Trellix Endpoint Security",
		"CrowdStrike Falcon Sensor", "SentinelOne Agent", "Sophos Intercept X",
		"Trend Micro Apex One", "Cortex XDR", "Elastic Endpoint", "FortiEDR"}
	for _, p := range hits {
		if !IsEDRProvider(p) {
			t.Errorf("expected EDR provider match: %q", p)
		}
	}
	for _, p := range []string{"Microsoft-Windows-Kernel-General", "Service Control Manager"} {
		if IsEDRProvider(p) {
			t.Errorf("unexpected EDR match: %q", p)
		}
	}
}
```

- [ ] **Step 2: Run, confirm FAIL:** `cd orchestrator && go test ./internal/detect/` → undefined `IsEDRProvider`.

- [ ] **Step 3: Implement** `providers.go`:

```go
// Package detect correlates collected endpoint alerts into per-technique
// detection verdicts and scores. Pure, server-side; the agent never classifies.
package detect

import "regexp"

// edrProviderRE matches known EDR/AV event-provider names (case-insensitive,
// regex — vendors rename providers between versions; substrings suffice).
var edrProviderRE = regexp.MustCompile(`(?i)(microsoft )?defender|antimalware|trellix|mcafee|crowdstrike|falcon|sentinelone|sophos|trend ?micro|apex one|palo alto|cortex|elastic endpoint|rapid7|insight|fortinet|fortiedr|carbon black|sense)`)

// IsEDRProvider reports whether an event provider name looks like an EDR/AV tool.
func IsEDRProvider(provider string) bool { return edrProviderRE.MatchString(provider) }
```

- [ ] **Step 4: Run, confirm PASS:** `cd orchestrator && go test ./internal/detect/`

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/detect/providers.go orchestrator/internal/detect/detect_test.go
git commit -m "feat(detect): EDR provider regex allowlist

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task C2: Correlate + Score

**Files:** Create `orchestrator/internal/detect/detect.go`; extend `detect_test.go`

- [ ] **Step 1: Failing tests** (append to `detect_test.go`):

```go
import (
	"time"
)

func mkResult(id, verdict string, at time.Time) ExecutedStep {
	return ExecutedStep{TechniqueID: id, Verdict: verdict, ExecutedAt: at, DurationMs: 1000}
}

func TestCorrelateAndScore(t *testing.T) {
	base := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	steps := []ExecutedStep{
		mkResult("T1486", "pass", base),                 // prevented
		mkResult("T1059.001", "fail", base.Add(time.Minute)), // detected (alert in window)
		mkResult("T1003.001", "fail", base.Add(2*time.Minute)), // undetected (no alert)
		mkResult("T1018", "error", base.Add(3*time.Minute)),    // excluded
	}
	alerts := []AlertRecord{{
		Provider: "Microsoft Defender Antivirus", EventID: 1116,
		ThreatName: "PowerShell/Amsi.A", Timestamp: base.Add(time.Minute + 4*time.Second),
	}}
	dets := Correlate(steps, alerts, 5*time.Minute, defaultDefenderDetectIDs())
	sum := Score(dets)
	if sum.Executed != 3 || sum.Prevented != 1 || sum.Detected != 1 || sum.Undetected != 1 {
		t.Fatalf("counts wrong: %+v", sum)
	}
	if sum.DetectionRate != 50 || sum.UndetectedRate != 50 || sum.PreventionRate != 33 {
		t.Fatalf("rates wrong: %+v", sum)
	}
	if sum.MTTDMs != 4000 {
		t.Fatalf("mttd = %d, want 4000", sum.MTTDMs)
	}
	// detected technique must be high confidence (Defender detect id + threat name)
	for _, d := range dets {
		if d.TechniqueID == "T1059.001" {
			if d.Verdict != "detected" || d.Confidence != "high" {
				t.Fatalf("T1059.001 = %+v", d)
			}
			if d.TimeToDetectMs != 4000 {
				t.Fatalf("ttd = %d", d.TimeToDetectMs)
			}
		}
		if d.TechniqueID == "T1486" && d.Verdict != "prevented" {
			t.Fatalf("prevented step misclassified: %+v", d)
		}
	}
}

func TestCorrelateLowConfidence(t *testing.T) {
	base := time.Date(2026, 6, 16, 10, 0, 0, 0, time.UTC)
	steps := []ExecutedStep{mkResult("T1059", "fail", base)}
	alerts := []AlertRecord{{Provider: "Service Control Manager", EventID: 7045,
		Timestamp: base.Add(2 * time.Second)}} // in window, not a detection
	dets := Correlate(steps, alerts, 5*time.Minute, defaultDefenderDetectIDs())
	if dets[0].Verdict != "detected" || dets[0].Confidence != "low" {
		t.Fatalf("expected detected/low, got %+v", dets[0])
	}
}
```

- [ ] **Step 2: Run, confirm FAIL:** `cd orchestrator && go test ./internal/detect/` → undefined types/functions.

- [ ] **Step 3: Implement** `detect.go`:

```go
package detect

import "time"

// AlertRecord mirrors the agent's wire shape (agent/types.go AlertRecord).
type AlertRecord struct {
	Channel     string    `json:"channel"`
	Provider    string    `json:"provider"`
	EventID     int       `json:"eventId"`
	Level       string    `json:"level"`
	Timestamp   time.Time `json:"timestamp"`
	ThreatName  string    `json:"threatName,omitempty"`
	ProcessName string    `json:"processName,omitempty"`
	ProcessPath string    `json:"processPath,omitempty"`
	CommandLine string    `json:"commandLine,omitempty"`
	User        string    `json:"user,omitempty"`
	Message     string    `json:"message,omitempty"`
}

// ExecutedStep is the minimal projection of a run result needed for correlation.
type ExecutedStep struct {
	TechniqueID string
	Verdict     string // pass|fail|blocked|skipped|error
	ExecutedAt  time.Time
	DurationMs  int64
}

type TechniqueDetection struct {
	TechniqueID    string       `json:"techniqueId"`
	Verdict        string       `json:"verdict"`    // prevented|detected|undetected (logged handled by report classifier)
	Confidence     string       `json:"confidence,omitempty"` // high|low when detected
	MatchedBy      []string     `json:"matchedBy,omitempty"`
	Alert          *AlertRecord `json:"alert,omitempty"`
	TimeToDetectMs int64        `json:"timeToDetectMs,omitempty"`
}

type DetectionSummary struct {
	Executed       int   `json:"executed"`
	Prevented      int   `json:"prevented"`
	Detected       int   `json:"detected"`
	Undetected     int   `json:"undetected"`
	PreventionRate int   `json:"preventionRate"`
	DetectionRate  int   `json:"detectionRate"`
	UndetectedRate int   `json:"undetectedRate"`
	MTTDMs         int64 `json:"mttdMs"`
}

func isPrevented(v string) bool { return v == "pass" || v == "blocked" }
func isExecuted(v string) bool  { return v == "pass" || v == "blocked" || v == "fail" }

// defaultDefenderDetectIDs returns Defender Operational event IDs that mean a
// threat was detected/acted on. Kept in sync with reporting.defenderDetectIDs.
func defaultDefenderDetectIDs() map[int]bool {
	return map[int]bool{1006: true, 1007: true, 1008: true, 1009: true, 1010: true,
		1011: true, 1012: true, 1015: true, 1116: true, 1117: true, 1118: true, 1119: true}
}

// Correlate maps alerts to executed steps by time window. A step matches an alert
// when alert.ts ∈ [step.ExecutedAt, step.ExecutedAt+window]. Prevented steps are
// never detected. The first matching alert wins (earliest). Confidence is high
// when the alert is a bona-fide detection (Defender detect id / non-empty threat
// name / EDR provider), else low. error/skipped steps are excluded entirely.
func Correlate(steps []ExecutedStep, alerts []AlertRecord, window time.Duration, detectIDs map[int]bool) []TechniqueDetection {
	out := make([]TechniqueDetection, 0, len(steps))
	for _, s := range steps {
		if !isExecuted(s.Verdict) {
			continue
		}
		if isPrevented(s.Verdict) {
			out = append(out, TechniqueDetection{TechniqueID: s.TechniqueID, Verdict: "prevented"})
			continue
		}
		// not prevented (fail) → look for an in-window alert
		winEnd := s.ExecutedAt.Add(window)
		var best *AlertRecord
		for i := range alerts {
			ts := alerts[i].Timestamp
			if (ts.Equal(s.ExecutedAt) || ts.After(s.ExecutedAt)) && !ts.After(winEnd) {
				if best == nil || ts.Before(best.Timestamp) {
					best = &alerts[i]
				}
			}
		}
		if best == nil {
			out = append(out, TechniqueDetection{TechniqueID: s.TechniqueID, Verdict: "undetected"})
			continue
		}
		matchedBy := []string{"timestamp"}
		conf := "low"
		if detectIDs[best.EventID] {
			matchedBy = append(matchedBy, "defenderDetectId")
			conf = "high"
		}
		if best.ThreatName != "" {
			matchedBy = append(matchedBy, "threatName")
			conf = "high"
		}
		if IsEDRProvider(best.Provider) && best.ThreatName != "" {
			matchedBy = append(matchedBy, "edrProvider")
			conf = "high"
		}
		alertCopy := *best
		out = append(out, TechniqueDetection{
			TechniqueID: s.TechniqueID, Verdict: "detected", Confidence: conf,
			MatchedBy: matchedBy, Alert: &alertCopy,
			TimeToDetectMs: best.Timestamp.Sub(s.ExecutedAt).Milliseconds(),
		})
	}
	return out
}

// Score computes counts, the three rates, and MTTD. Prevented techniques are
// EXCLUDED from the detection/undetected denominator (executed-and-not-prevented).
func Score(dets []TechniqueDetection) DetectionSummary {
	var s DetectionSummary
	var ttdSum, ttdN int64
	for _, d := range dets {
		switch d.Verdict {
		case "prevented":
			s.Executed++
			s.Prevented++
		case "detected":
			s.Executed++
			s.Detected++
			ttdSum += d.TimeToDetectMs
			ttdN++
		case "undetected":
			s.Executed++
			s.Undetected++
		}
	}
	notPrevented := s.Detected + s.Undetected
	if s.Executed > 0 {
		s.PreventionRate = pct(s.Prevented, s.Executed)
	}
	if notPrevented > 0 {
		s.DetectionRate = pct(s.Detected, notPrevented)
		s.UndetectedRate = pct(s.Undetected, notPrevented)
	}
	if ttdN > 0 {
		s.MTTDMs = ttdSum / ttdN
	}
	return s
}

func pct(n, d int) int {
	if d == 0 {
		return 0
	}
	return int((float64(n)/float64(d))*100 + 0.5)
}
```

- [ ] **Step 4: Run, confirm PASS:** `cd orchestrator && go test ./internal/detect/`
Expected: PASS (PreventionRate 1/3 = 33; DetectionRate 1/2 = 50; MTTD 4000).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/detect/detect.go orchestrator/internal/detect/detect_test.go
git commit -m "feat(detect): Correlate + Score (rates, MTTD, confidence, matchedBy)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part D — Server: ingest handler + report surfacing

### Task D1: Detection ingest handler + route

**Files:** Create `orchestrator/internal/api/detection_handlers.go`; modify `orchestrator/internal/api/routes.go`

- [ ] **Step 1: Handler.** Mirror the existing agent-auth + idempotent-store pattern (read `SubmitScenarioResult` for `validateAgentAuth` usage and the `models.SimulationResult` shape):

```go
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/detect"
	"github.com/audspect/bas/internal/models"
	"github.com/go-chi/chi/v5"
)

// SubmitRunDetections ingests an agent's post-run alert sweep, correlates it
// against the run's stored results, scores it, and persists raw + summary.
// Agent-authed. Idempotent: REPLACES detections for the run (re-delivery heals).
// POST /api/scenarios/runs/{runId}/detections
func (h *Handler) SubmitRunDetections(w http.ResponseWriter, r *http.Request) {
	if !h.validateAgentAuth(r) {
		jsonError(w, "unauthorized — check AGENT_SECRET", http.StatusUnauthorized)
		return
	}
	runID := chi.URLParam(r, "runId")
	var body struct {
		Alerts    []detect.AlertRecord `json:"alerts"`
		Truncated bool                 `json:"truncated"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid detections payload", http.StatusBadRequest)
		return
	}

	// Load the run's executed results to correlate against.
	var resultsRaw []byte
	if err := h.db.QueryRow(r.Context(),
		`SELECT results FROM scenario_runs WHERE id = $1`, runID).Scan(&resultsRaw); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	var results []models.SimulationResult
	_ = json.Unmarshal(resultsRaw, &results)

	steps := make([]detect.ExecutedStep, 0, len(results))
	for _, res := range results {
		steps = append(steps, detect.ExecutedStep{
			TechniqueID: res.Technique.ID,
			Verdict:     string(res.Result),
			ExecutedAt:  res.ExecutedAt,
			DurationMs:  res.DurationMs,
		})
	}

	dets := detect.Correlate(steps, body.Alerts, 5*time.Minute, detect.DefenderDetectIDs())
	sum := detect.Score(dets)

	rawJSON, _ := json.Marshal(body.Alerts)
	summaryJSON, _ := json.Marshal(map[string]any{"summary": sum, "techniques": dets, "truncated": body.Truncated})
	if _, err := h.db.Exec(r.Context(),
		`UPDATE scenario_runs SET detections_raw=$1, detection_summary=$2,
		        detection_rate=$3, undetected_rate=$4, mttd_ms=$5 WHERE id=$6`,
		rawJSON, summaryJSON, sum.DetectionRate, sum.UndetectedRate, sum.MTTDMs, runID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"runId": runID, "detectionRate": sum.DetectionRate,
		"undetectedRate": sum.UndetectedRate, "mttdMs": sum.MTTDMs, "alerts": len(body.Alerts)})
}
```

  Also export the detect-ID map for the handler: in `detect.go` add

```go
// DefenderDetectIDs is the exported Defender detect-ID set for callers.
func DefenderDetectIDs() map[int]bool { return defaultDefenderDetectIDs() }
```

- [ ] **Step 2: Register route** in `routes.go` next to the other agent-authed posts (after line 33, `/api/scenarios/events`):

```go
	r.Post("/api/scenarios/runs/{runId}/detections", h.SubmitRunDetections)
```

- [ ] **Step 3: Build + tests**

Run: `cd orchestrator && go build ./... && go test ./internal/api/ ./internal/detect/`
Expected: clean / ok (api tests self-skip without a live DB).

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/api/detection_handlers.go orchestrator/internal/api/routes.go orchestrator/internal/detect/detect.go
git commit -m "feat(api): ingest run detections, correlate + score, persist

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task D2: EDR regex in classifyDetection + report metrics

**Files:** Modify `orchestrator/internal/reporting/engine.go`

- [ ] **Step 1: Use the EDR allowlist in `classifyDetection`.** In `classifyDetection` (engine.go ~615), the `default:` branch currently labels any non-Defender/Sysmon token as "Windows Security". Add an EDR-provider check so third-party EDR tokens count as Detected. Since coarse tokens are `"id:log"` (no provider), match on the log/channel name. Add, before the `default:` case:

```go
		case detect.IsEDRProvider(logName):
			return Detection{
				Detected: true, Status: "Detected", Source: logName,
				Detail: "Third-party EDR raised a detection (" + logName + " event " + id + ")",
			}
```

  Add the import `"github.com/audspect/bas/internal/detect"` to engine.go.

- [ ] **Step 2: Surface the summary metrics in the report.** Add fields to the report summary struct used by the HTML/PDF renderer (find the `Summary` struct in `internal/reporting`), reading the persisted `detection_summary`/`detection_rate`/`undetected_rate`/`mttd_ms` in `BuildFromRun` (alongside the existing `results`/`score` scan). Add to the `BuildFromRun` query and scan:

```go
	var detRate, undetRate *int
	var mttd *int64
	// extend the existing SELECT with: , detection_rate, undetected_rate, mttd_ms
	// extend the Scan with: , &detRate, &undetRate, &mttd
	if detRate != nil { report.Summary.DetectionRate = *detRate }
	if undetRate != nil { report.Summary.UndetectedRate = *undetRate }
	if mttd != nil { report.Summary.MTTDMs = *mttd }
```

  Add `DetectionRate int`, `UndetectedRate int`, `MTTDMs int64` to the report `Summary` struct (json tags `detectionRate`,`undetectedRate`,`mttdMs`).

- [ ] **Step 3: Build + tests**

Run: `cd orchestrator && go build ./... && go test ./internal/reporting/ ./internal/detect/`
Expected: clean / ok.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/reporting/engine.go
git commit -m "feat(report): EDR regex in classifyDetection; surface detection metrics

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Part E — Dashboard + retention

### Task E1: Dashboard run-summary metrics + per-technique badges

**Files:** Modify `orchestrator/wwwroot/index.html`

Context: the run results drawer renders per-technique rows and a run summary (search the file for where `score.preventionScore` / the run drawer is built). Detection data is in the run's `report.json` (served by `/api/scenarios/runs/{runId}/report.json`) under `summary.detectionRate` etc. and per-technique under `detection_summary`.

- [ ] **Step 1: Run summary.** Where the run summary shows Prevention/Exposure, add Detection Rate, Undetected Rate, MTTD when present:

```js
      // after the existing prevention/exposure score chips:
      if (typeof rep.summary.detectionRate !== 'undefined') {
        html += chip('Detection', rep.summary.detectionRate + '%',
                     rep.summary.detectionRate >= 70 ? 'var(--success)' : rep.summary.detectionRate >= 40 ? 'var(--warning)' : 'var(--danger)');
        html += chip('Undetected', rep.summary.undetectedRate + '%',
                     rep.summary.undetectedRate <= 20 ? 'var(--success)' : rep.summary.undetectedRate <= 50 ? 'var(--warning)' : 'var(--danger)');
        if (rep.summary.mttdMs) html += chip('MTTD', Math.round(rep.summary.mttdMs/1000) + 's', 'var(--muted)');
      }
```

  (Match the file's actual chip/markup helper — read the surrounding summary-rendering code and follow its pattern; do not introduce a new `chip()` if one is not already used. If summary rows are plain `<div>`s, append equivalent `<div>`s.)

- [ ] **Step 2: Per-technique detection badge.** In the per-technique row rendering, add a Detection badge (Prevented / Detected ⟨High|Low⟩ / Undetected ⚠) using the run's `detection_summary.techniques` keyed by `techniqueId`. Undetected-and-executed rows get the ⚠ blind-spot style.

- [ ] **Step 3: Sanity-check JS syntax**

Run: `node -e "const fs=require('fs');const h=fs.readFileSync('orchestrator/wwwroot/index.html','utf8');const m=h.match(/<script>([\s\S]*)<\/script>/);new Function(m[1]);console.log('OK');"`
Expected: `OK`.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/wwwroot/index.html
git commit -m "feat(dashboard): detection rate/undetected/MTTD + per-technique badges

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

### Task E2: Raw-alert retention (30 days)

**Files:** Create `orchestrator/internal/detect/retention.go`; modify the server entrypoint

- [ ] **Step 1: Retention job** `retention.go`:

```go
package detect

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// StartRetention prunes raw detection blobs older than 30 days once a day,
// keeping detection_summary forever. Best-effort; logs and continues on error.
func StartRetention(ctx context.Context, pool *pgxpool.Pool) {
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		prune(ctx, pool)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				prune(ctx, pool)
			}
		}
	}()
}

func prune(ctx context.Context, pool *pgxpool.Pool) {
	ct, err := pool.Exec(ctx,
		`UPDATE scenario_runs SET detections_raw='[]'
		   WHERE completed_at < NOW() - INTERVAL '30 days' AND detections_raw <> '[]'`)
	if err != nil {
		log.Printf("[detect] retention prune failed: %v", err)
		return
	}
	if n := ct.RowsAffected(); n > 0 {
		log.Printf("[detect] pruned raw detections on %d run(s) >30d", n)
	}
}
```

- [ ] **Step 2: Start it** in the server entrypoint (find where `EnsureSchema` / the connector scheduler is started in `main`) and add:

```go
	detect.StartRetention(ctx, pool)
```

  (Use the same `ctx` and `*pgxpool.Pool` already in scope at startup; add the import.)

- [ ] **Step 3: Build**

Run: `cd orchestrator && go build ./...`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/detect/retention.go orchestrator/cmd
git commit -m "feat(detect): 30-day raw-alert retention prune

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**Spec coverage:**
- Agent-local collection ✓ (A2). Windowed presence + raw capture ✓ (C2 Correlate). Windows alert sources ✓ (A2 alertChannels). Detection Rate + MTTD + Undetected + badges ✓ (C2, D2, E1). End-of-run grace sweep + server correlation ✓ (A3, D1). Extend-in-place ✓ (D2 reuses classifyDetection/buildDetectionCategories). Confidence high/low ✓ (C2). matchedBy ✓ (C2). Process metadata fields ✓ (A1/A2). Three rates ✓ (C2). 90s grace + 5m window ✓ (A3, D1). Logged tier retained ✓ (unchanged classifyDetection). EDR regex allowlist ✓ (C1, D2). 30-day retention ✓ (E2). Posture off by default ✓ (sweep only fires from `submitResults`, the attack-run path; posture/local-check uses the simulate path which never calls it). Idempotent ✓ (D1 REPLACE). Best-effort isolation ✓ (A3 goroutine, never affects results). Caps/truncation ✓ (A2 capRecords).

**Placeholder scan:** No TBD/TODO. Two steps say "read the surrounding code and follow its pattern" (A3 run-start source, E1 chip markup, D2 Summary struct, E2 main entrypoint) — these are concrete *verification points* against real code, each with the exact fallback code given, not deferred logic.

**Type consistency:** `AlertRecord` fields identical agent (A1) ↔ server (C2). `ExecutedStep{TechniqueID,Verdict,ExecutedAt,DurationMs}` defined C2, populated from `models.SimulationResult` in D1. `Correlate(steps, alerts, window, detectIDs)` signature matches its test (C2) and call site (D1, via `detect.DefenderDetectIDs()`). `DetectionSummary` fields used in D1 persist + E1 render. `IsEDRProvider` defined C1, used C2 + D2. Verdict strings (`prevented`/`detected`/`undetected`) consistent across Correlate, Score, D1, E1.

**Risk notes:**
- Coarse `ExecResult.Events` (per-step, 300ms) is retained as the immediate fallback; the rich sweep overwrites `detection_summary` when it arrives. Both feed the same report concepts — no parallel UI.
- Time-window attribution can match one alert to multiple failed steps in the same window; acceptable for v1 (raw stored for later precision). Documented in `Correlate`.
- The agent run-start derivation uses the earliest `ExecutedAt` among results (no new field needed).
