# DLP Exfiltration Sink Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace self-reported local success/failure with a destination-side verified receipt for DLP exfiltration scenario steps wired to it, proven end-to-end with one new generic HTTPS-POST channel.

**Architecture:** At dispatch time, the orchestrator substitutes a per-attempt `crypto/rand` token and its own reachable sink URL into any step's command text containing `{{SINK_TOKEN}}`/`{{SINK_URL}}` placeholders (the agent is unaware this happened — it just runs the resulting script, unchanged). A new unauthenticated `POST /api/dlp/sink` endpoint (mirroring the existing single-use-token tracker route pattern) logs receipts. `internal/verifysync`'s existing verdict-persistence poller — the one confirmed-live production path that computes automatic DLP verdicts — annotates each run's results with whether its sink token was received before handing off to the existing (unmodified) pure verification engine, which gains one new sink-primary branch alongside its existing local-marker fallback.

**Tech Stack:** Go (orchestrator backend), PostgreSQL (via pgx), YAML scenario content (RSA-4096 signed).

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md`

## Global Constraints

- Sink is on-prem only in this plan — no internet-reachable mode.
- Token generation must use `crypto/rand`, never `newID()` (`internal/api/handlers.go:3128`, a nanosecond timestamp — confirmed not cryptographically random).
- The agent receives no new capability and no code changes — all substitution happens server-side before dispatch.
- `internal/reporting`'s verification engine stays a pure function with no I/O — this is a deliberate, explicitly-documented invariant of that package (`detection_validation.go:8-10`). The DB-backed sink lookup happens in the caller (`internal/verifysync`), never inside `internal/reporting`.
- The sink payload's raw content is never persisted — only its SHA-256 hash and size.
- The existing 5-step `scenarios/dlp-exfiltration-validation.yaml` is not modified — the new channel is a separate, standalone scenario file.

---

## File Structure

| File | Responsibility |
|---|---|
| `orchestrator/internal/db/postgres.go` | New `dlp_sink_tokens` and `dlp_sink_receipts` tables. |
| `orchestrator/internal/api/dlp_sink.go` | New file: token generation, placeholder substitution, the sink HTTP handler. |
| `orchestrator/internal/api/dlp_sink_test.go` | Tests for the above. |
| `orchestrator/internal/api/handlers.go` | `dispatchRun` calls the new substitution helper after `scenario.BuildSteps`. |
| `orchestrator/internal/api/routes.go` | New `POST /api/dlp/sink` route. |
| `orchestrator/internal/api/rbac_matrix_test.go` | `publicRoutes` entry for the new route. |
| `orchestrator/internal/models/schema.go` | `SimulationResult` gains `SinkTokenObserved *bool`. |
| `orchestrator/internal/reporting/detection_validation.go` | `StepEvidence` gains `SinkTokenObserved *bool`; `evidenceByTechnique` copies it through. |
| `orchestrator/internal/reporting/dlp.go` | `dlpVerifier.Verify` gains the sink-primary branch. |
| `orchestrator/internal/reporting/dlp_test.go` | Tests for the above — including a regression test proving the existing 5 local-marker-only steps are unaffected. |
| `orchestrator/internal/verifysync/job.go` | `processRun` looks up sink receipts and annotates `results` before calling `ComputeAutomaticVerifications`. |
| `orchestrator/internal/verifysync/job_test.go` | Tests for the above. |
| `scenarios/dlp-exfiltration-sink-https.yaml` | New V1 scenario: one step, generic HTTPS POST channel. |
| `scenarios/detection-profiles/windows_dlp_exfiltration.yaml` | Gains a 6th `expected_detection` entry for the new technique. |

---

## Task 1: Database schema

**Files:**
- Modify: `orchestrator/internal/db/postgres.go`

**Interfaces:**
- Produces: `dlp_sink_tokens (token, run_id, technique_id, created_at, expires_at)` and `dlp_sink_receipts (id, token, received_at, source_ip, payload_hash, payload_size, channel)` tables — consumed by Tasks 2, 3, and 5.

- [ ] **Step 1: Locate the schema statement list**

Run: `grep -n "stmts := \[\]string{" orchestrator/internal/db/postgres.go`

Find the same guarded, evolutionary statement list this session's earlier sweep-disconnect-resilience work already appended to (the one containing the `em_sweeps`/`vex_sweeps` migration lines). Confirm its exact current line range before editing.

- [ ] **Step 2: Add the two new tables**

Append to that same statement list, after its last existing entry:

```go
	// DLP exfiltration sink service: dlp_sink_tokens records a per-attempt
	// token issued at dispatch time (crypto/rand, not newID() -- see
	// internal/api/dlp_sink.go); dlp_sink_receipts is an append-only log of
	// whatever the sink endpoint actually received. token is NOT unique in
	// dlp_sink_receipts -- a retried request can legitimately produce more
	// than one receipt for the same token; the verifier only needs "was it
	// received at least once", not exactly-once. See
	// docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md.
	`CREATE TABLE IF NOT EXISTS dlp_sink_tokens (
		token text PRIMARY KEY,
		run_id text NOT NULL,
		technique_id text NOT NULL,
		created_at timestamptz NOT NULL DEFAULT NOW(),
		expires_at timestamptz NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS idx_dlp_sink_tokens_run_id ON dlp_sink_tokens (run_id)`,
	`CREATE TABLE IF NOT EXISTS dlp_sink_receipts (
		id bigserial PRIMARY KEY,
		token text NOT NULL,
		received_at timestamptz NOT NULL DEFAULT NOW(),
		source_ip text NOT NULL DEFAULT '',
		payload_hash text NOT NULL DEFAULT '',
		payload_size integer NOT NULL DEFAULT 0,
		channel text NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_dlp_sink_receipts_token ON dlp_sink_receipts (token)`,
```

- [ ] **Step 3: Run the full `internal/api` test suite to confirm the schema applies cleanly**

Run in background (8-17 minutes observed this session):

```bash
cd orchestrator && go test ./internal/api/... -v -timeout 20m > <scratchpad>/dlp_sink_task1_full.log 2>&1
```

Use `Monitor` to watch for the `ok`/`FAIL` line (grep the log for `^(ok|FAIL)[[:space:]]+github.com/audspect/bas/internal/api`), then read the actual full log file after the notification and confirm zero `--- FAIL` lines. If it times out, retry once cleanly with the same `-timeout 20m` before concluding anything is broken.

- [ ] **Step 4: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "$(cat <<'EOF'
feat(db): dlp_sink_tokens/dlp_sink_receipts tables

Groundwork for the DLP exfiltration sink service -- a per-attempt token
issued at dispatch time and an append-only log of what the sink endpoint
actually received, replacing self-reported local success/failure as the
verified source of truth for sink-wired DLP scenario steps.
EOF
)"
git push
```

---

## Task 2: Token generation & placeholder substitution

**Files:**
- Create: `orchestrator/internal/api/dlp_sink.go`
- Create: `orchestrator/internal/api/dlp_sink_test.go`
- Modify: `orchestrator/internal/api/handlers.go` (`dispatchRun`, after the `scenario.BuildSteps` call — currently around line 1462, confirm exact line at implementation time)

**Interfaces:**
- Consumes: `dlp_sink_tokens` table (Task 1); `cfg.PublicBaseURL` (already wired into `cmd/server/main.go:421` for the exercise tracker's `/x/*` URLs — same value, reused here); `scenario.ScenarioStep` (existing type, has a `.Command` field carrying the PowerShell text).
- Produces: `func generateSinkToken() (string, error)`; `func (h *Handler) issueSinkTokensAndSubstitute(ctx context.Context, runID, publicBaseURL string, steps []scenario.ScenarioStep) ([]scenario.ScenarioStep, error)` — consumed by `dispatchRun` in this task, and conceptually by Task 3's sink handler (which reads what this task writes).

- [ ] **Step 1: Write the failing test for token generation**

```go
package api

import (
	"strings"
	"testing"
)

func TestGenerateSinkToken_ProducesUniqueUnpredictableValues(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := generateSinkToken()
		if err != nil {
			t.Fatalf("generateSinkToken: %v", err)
		}
		if len(tok) < 32 {
			t.Fatalf("token %q too short to be meaningfully unpredictable (crypto/rand, not a timestamp)", tok)
		}
		if seen[tok] {
			t.Fatalf("generateSinkToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}

func TestIssueSinkTokensAndSubstitute_ReplacesPlaceholdersOnlyWherePresent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T9999", Command: "Invoke-RestMethod -Uri '{{SINK_URL}}' -Body @{token='{{SINK_TOKEN}}'}"},
			{TechniqueID: "T1052.001", Command: "Copy-Item -Path $src -Destination $dest"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-sink-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if strings.Contains(out[0].Command, "{{SINK_TOKEN}}") || strings.Contains(out[0].Command, "{{SINK_URL}}") {
			t.Fatalf("step 0 still has unsubstituted placeholders: %s", out[0].Command)
		}
		if !strings.Contains(out[0].Command, "https://orchestrator.example:9443/api/dlp/sink") {
			t.Fatalf("step 0 command doesn't contain the expected sink URL: %s", out[0].Command)
		}
		if out[1].Command != "Copy-Item -Path $src -Destination $dest" {
			t.Fatalf("step 1 (no placeholder) was modified: %s", out[1].Command)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-sink-1' AND technique_id = 'T9999'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows for run-sink-1/T9999 = %d, want 1", count)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGenerateSinkToken|TestIssueSinkTokensAndSubstitute" -v`
Expected: FAIL to compile — `generateSinkToken`, `issueSinkTokensAndSubstitute` undefined.

- [ ] **Step 3: Implement `dlp_sink.go`**

```go
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/audspect/bas/internal/scenario"
)

// sinkTokenTTL bounds how long an issued token remains valid for the sink
// endpoint to accept a receipt against -- generous relative to any single
// step's own timeout_sec, since a slow/queued network path shouldn't cause
// a spurious "not received" verdict.
const sinkTokenTTL = 10 * time.Minute

// generateSinkToken returns a cryptographically random, hex-encoded token
// for one DLP sink-verified attempt. Deliberately not newID()
// (internal/api/handlers.go) -- that's a hex-encoded nanosecond timestamp,
// not a secret, and would be guessable within a narrow window.
func generateSinkToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// issueSinkTokensAndSubstitute scans each step's Command for the
// {{SINK_TOKEN}}/{{SINK_URL}} placeholders. For any step that has them, it
// generates a fresh token, persists {token, runID, techniqueID, expiresAt}
// to dlp_sink_tokens, and substitutes both placeholders into the command
// text before returning -- the agent that eventually runs this step has no
// awareness the substitution happened, matching this platform's existing
// "dumb executor" principle. Steps without the placeholder are returned
// unchanged.
func (h *Handler) issueSinkTokensAndSubstitute(ctx context.Context, runID, publicBaseURL string, steps []scenario.ScenarioStep) ([]scenario.ScenarioStep, error) {
	sinkURL := strings.TrimRight(publicBaseURL, "/") + "/api/dlp/sink"
	out := make([]scenario.ScenarioStep, len(steps))
	for i, st := range steps {
		out[i] = st
		if !strings.Contains(st.Command, "{{SINK_TOKEN}}") {
			continue
		}
		token, err := generateSinkToken()
		if err != nil {
			return nil, err
		}
		if _, err := h.db.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
			 VALUES ($1, $2, $3, NOW() + make_interval(secs => $4))`,
			token, runID, st.TechniqueID, int(sinkTokenTTL.Seconds()),
		); err != nil {
			return nil, err
		}
		cmd := strings.ReplaceAll(st.Command, "{{SINK_TOKEN}}", token)
		cmd = strings.ReplaceAll(cmd, "{{SINK_URL}}", sinkURL)
		out[i].Command = cmd
	}
	return out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGenerateSinkToken|TestIssueSinkTokensAndSubstitute" -v`
Expected: PASS.

- [ ] **Step 5: Wire it into `dispatchRun`**

In `orchestrator/internal/api/handlers.go`, find the line calling `scenario.BuildSteps` inside `dispatchRun` (currently `steps, calderaSkipped, err := scenario.BuildSteps(buildSc, h.calderaURL, h.calderaKey, h.artStore, agentOS)`, around line 1462 — confirm exact line at implementation time, since this file has shifted repeatedly this session). Immediately after the existing error check for that call, insert:

```go
	steps, err = h.issueSinkTokensAndSubstitute(ctx, runID, h.publicBaseURL, steps)
	if err != nil {
		_, _ = h.db.Exec(context.Background(),
			`UPDATE scenario_runs SET status = 'failed', completed_at = NOW() WHERE id = $1`, runID)
		return "", "", fmt.Errorf("issue sink tokens: %w", err)
	}
```

This requires a `publicBaseURL string` field on `Handler` (find the `Handler` struct definition in this same file, add the field alongside similar existing config fields like `licPath`), and a corresponding `WithPublicBaseURL(url string) *Handler` setter method (mirror the existing `WithLicensePath` setter's exact shape, found earlier this session at `handlers.go:365`), wired from `cmd/server/main.go` using `cfg.PublicBaseURL` (the same value already passed to the exercise tracker at `cmd/server/main.go:421`).

- [ ] **Step 6: Run the full `internal/api` test suite**

Same background + `Monitor` + full-log-read procedure as Task 1 Step 3.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/dlp_sink.go orchestrator/internal/api/dlp_sink_test.go orchestrator/internal/api/handlers.go orchestrator/cmd/server/main.go
git commit -m "$(cat <<'EOF'
feat(api): per-attempt sink token issuance at dispatch time

dispatchRun now substitutes {{SINK_TOKEN}}/{{SINK_URL}} placeholders in a
step's command text with a fresh crypto/rand token and this server's own
reachable URL before sending it to the agent -- the agent runs the
resulting script exactly as it runs any other step, no new agent
capability needed. Reuses cfg.PublicBaseURL (already wired for the
exercise tracker's single-use-token URLs) rather than inventing a second
"how do agents reach us" config value.
EOF
)"
git push
```

---

## Task 3: Sink HTTP endpoint

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go`
- Modify: `orchestrator/internal/api/dlp_sink_test.go`
- Modify: `orchestrator/internal/api/routes.go`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go`

**Interfaces:**
- Consumes: `dlp_sink_receipts` table (Task 1).
- Produces: `func (h *Handler) DLPSink(w http.ResponseWriter, r *http.Request)` — an HTTP handler, mounted at `POST /api/dlp/sink`, consumed by Task 5's verification lookup (which reads what this writes).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/dlp_sink_test.go`:

```go
func TestDLPSink_RecordsReceiptForAnyPostedToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]any{
			"token":   "some-token-value",
			"payload": "[BAS-SIM-DLP] fake regulated data",
			"channel": "https-post",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", bytes.NewReader(body))
		req.RemoteAddr = "10.0.0.5:54321"
		rec := httptest.NewRecorder()
		h.DLPSink(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var count int
		var sourceIP, channel string
		var payloadSize int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_receipts WHERE token = 'some-token-value'`,
		).Scan(&count); err != nil {
			t.Fatalf("count receipts: %v", err)
		}
		if count != 1 {
			t.Fatalf("receipt count = %d, want 1", count)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT source_ip, channel, payload_size FROM dlp_sink_receipts WHERE token = 'some-token-value'`,
		).Scan(&sourceIP, &channel, &payloadSize); err != nil {
			t.Fatalf("read receipt: %v", err)
		}
		if !strings.HasPrefix(sourceIP, "10.0.0.5") {
			t.Errorf("source_ip = %q, want prefix 10.0.0.5", sourceIP)
		}
		if channel != "https-post" {
			t.Errorf("channel = %q, want https-post", channel)
		}
		if payloadSize == 0 {
			t.Error("payload_size should reflect the posted payload's length")
		}

		var rawPayloadStored bool
		rows, _ := pool.Query(context.Background(), `SELECT column_name FROM information_schema.columns WHERE table_name = 'dlp_sink_receipts'`)
		for rows.Next() {
			var col string
			rows.Scan(&col)
			if col == "payload" || col == "raw_payload" {
				rawPayloadStored = true
			}
		}
		rows.Close()
		if rawPayloadStored {
			t.Error("dlp_sink_receipts must never store the raw payload, only a hash -- found a raw-payload column")
		}
	})
}

func TestDLPSink_UnrecognizedTokenStillReturns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]any{"token": "never-issued-token", "payload": "x", "channel": "https-post"})
		req := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.DLPSink(rec, req)
		// Deliberately identical response whether or not the token is
		// recognized -- revealing "that token isn't valid" would itself be a
		// signal to anything inspecting the response en route.
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 even for an unrecognized token", rec.Code)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestDLPSink" -v`
Expected: FAIL to compile — `h.DLPSink` undefined.

- [ ] **Step 3: Implement the handler**

Add to `orchestrator/internal/api/dlp_sink.go`:

```go
import (
	// ...existing imports...
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
)

type dlpSinkRequest struct {
	Token   string `json:"token"`
	Payload string `json:"payload"`
	Channel string `json:"channel"`
}

// DLPSink is POST /api/dlp/sink -- deliberately unauthenticated (see
// routes.go's publicRoutes and the design spec's rationale: the point is
// testing whether *content* gets intercepted in flight, not testing access
// control). Logs whatever it receives; never errors on an unrecognized
// token -- that distinction is exactly what an inspecting proxy/DLP
// shouldn't be able to learn from the response.
func (h *Handler) DLPSink(w http.ResponseWriter, r *http.Request) {
	var req dlpSinkRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	sum := sha256.Sum256([]byte(req.Payload))

	_, _ = h.db.Exec(r.Context(),
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		req.Token, host, hex.EncodeToString(sum[:]), len(req.Payload), req.Channel,
	)
	w.WriteHeader(http.StatusOK)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestDLPSink" -v`
Expected: PASS.

- [ ] **Step 5: Register the route**

In `orchestrator/internal/api/routes.go`, find the "Exercise tracking — no auth" block (currently around line 127-135, the `/x/open/{token}` etc. registrations). Add immediately after it:

```go
	// DLP exfiltration sink — no auth; a per-attempt single-use token
	// (issued at dispatch time, see internal/api/dlp_sink.go) is the sole
	// correlation mechanism. Same "no auth; single-use tokens gate access"
	// pattern as the exercise-tracking routes above.
	r.Post("/api/dlp/sink", h.DLPSink)
```

- [ ] **Step 6: Add the `publicRoutes` entry**

In `orchestrator/internal/api/rbac_matrix_test.go`, find the `publicRoutes` map (documented as "every routes.go registration OUTSIDE the JWT-authenticated group", currently ending around line 399-400 with `"GET /health": true,`). Add:

```go
	"POST /api/dlp/sink":                          true,
```

- [ ] **Step 7: Run `TestRBACMatrix_NoDrift` explicitly, then the full suite**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS.

Then the full background suite as in prior tasks.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/dlp_sink.go orchestrator/internal/api/dlp_sink_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "$(cat <<'EOF'
feat(api): DLP sink endpoint -- POST /api/dlp/sink

Unauthenticated by design (mirrors the existing exercise-tracker /x/*
routes' "no auth; single-use tokens gate access" pattern) -- the point is
testing whether content-based inspection catches a transfer in flight,
not testing access control. Logs receipts (source IP, payload hash/size,
channel) without ever storing the raw payload; never distinguishes a
recognized from an unrecognized token in its response, since that
distinction would itself leak information to anything inspecting the
traffic.
EOF
)"
git push
```

---

## Task 4: `dlpVerifier` sink-primary logic

**Files:**
- Modify: `orchestrator/internal/models/schema.go` (`SimulationResult` struct)
- Modify: `orchestrator/internal/reporting/detection_validation.go` (`StepEvidence` struct, `evidenceByTechnique`)
- Modify: `orchestrator/internal/reporting/dlp.go` (`dlpVerifier.Verify`)
- Modify: `orchestrator/internal/reporting/dlp_test.go`

**Interfaces:**
- Consumes: nothing new from earlier tasks (this task is self-contained within `internal/models`/`internal/reporting`, pure logic, no I/O).
- Produces: `models.SimulationResult.SinkTokenObserved *bool`; `StepEvidence.SinkTokenObserved *bool` — consumed by Task 5 (`internal/verifysync`, which sets this field before calling into this package).

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/reporting/dlp_test.go`, after the existing `TestDLPVerifier`:

```go
func boolPtr(b bool) *bool { return &b }

func TestDLPVerifier_SinkPrimary_TokenReceived(t *testing.T) {
	exp := dlpExp("dlp-https-block", "Block")
	// Sink says the token WAS received -- data reached the destination, DLP
	// failed to catch it -- regardless of what any local marker claims.
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "DLP_OBSERVATION: OperationBlocked", // local script thought it was blocked
		SinkTokenObserved: boolPtr(true),                       // but the sink proves it actually arrived
	})
	if r.Status != StatusNotDetected || r.Comparison != Mismatch {
		t.Errorf("sink-received must be authoritative (Succeeded) even when the local marker disagrees: got status=%s comparison=%v", r.Status, r.Comparison)
	}
	if r.ObservedOutcome != ObservationSucceeded {
		t.Errorf("ObservedOutcome = %q, want %q", r.ObservedOutcome, ObservationSucceeded)
	}
}

func TestDLPVerifier_SinkPrimary_TokenNotReceived(t *testing.T) {
	exp := dlpExp("dlp-https-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		SinkTokenObserved: boolPtr(false),
	})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("token-not-received must resolve Blocked: got status=%s comparison=%v", r.Status, r.Comparison)
	}
	if r.ObservedOutcome != ObservationBlocked {
		t.Errorf("ObservedOutcome = %q, want %q", r.ObservedOutcome, ObservationBlocked)
	}
}

func TestDLPVerifier_NoSinkToken_UnaffectedByNewLogic(t *testing.T) {
	// Regression test: the existing 5 local-marker-only
	// dlp-exfiltration-validation.yaml steps never set SinkTokenObserved --
	// nil must still take the pre-existing local-marker regex path exactly
	// as before this task.
	exp := dlpExp("dlp-usb-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput: "DLP_OBSERVATION: OperationBlocked",
		// SinkTokenObserved deliberately left nil.
	})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("nil SinkTokenObserved must fall back to the local-marker path: got status=%s comparison=%v", r.Status, r.Comparison)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/... -run "TestDLPVerifier_SinkPrimary|TestDLPVerifier_NoSinkToken" -v`
Expected: FAIL to compile — `StepEvidence` has no field `SinkTokenObserved`.

- [ ] **Step 3: Add the field to `models.SimulationResult`**

In `orchestrator/internal/models/schema.go`, find the `SimulationResult` struct (starting at line 36, confirmed this session). Add a new field alongside `DetectionVerdict`:

```go
	// SinkTokenObserved is set (non-nil) only for a step whose command was
	// wired to the DLP exfiltration sink (see internal/api/dlp_sink.go).
	// true = the sink received this step's token (data reached the
	// destination); false = it never arrived within the token's window.
	// nil means this step was never sink-wired -- verification falls back
	// to the pre-existing local-marker path. Populated by
	// internal/verifysync, never by the agent itself.
	SinkTokenObserved *bool `json:"sinkTokenObserved,omitempty"`
```

- [ ] **Step 4: Add the field to `StepEvidence` and thread it through `evidenceByTechnique`**

In `orchestrator/internal/reporting/detection_validation.go`, add to the `StepEvidence` struct (currently ending at line 50 with the `RawOutput` field):

```go
	// SinkTokenObserved mirrors models.SimulationResult's field of the same
	// name -- see its doc comment.
	SinkTokenObserved *bool
```

In `evidenceByTechnique` (currently around line 617-642), add the copy alongside the existing field assignments:

```go
		ev := StepEvidence{
			TechniqueID:       r.ID,
			DetectionVerdict:  r.DetectionVerdict,
			Events:            r.Events,
			RawOutput:         r.RawOutput,
			SinkTokenObserved: r.SinkTokenObserved,
		}
```

- [ ] **Step 5: Add the sink-primary branch to `dlpVerifier.Verify`**

In `orchestrator/internal/reporting/dlp.go`, replace:

```go
func (dlpVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)

	observed := ObservationUnknown
	if m := dlpMarkerRe.FindStringSubmatch(ev.RawOutput); m != nil {
		switch m[1] {
		case ObservationSucceeded, ObservationBlocked:
			observed = m[1]
		}
	}
	r.ObservedOutcome = observed
	r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
	r.Status = collapseToStatus(r.Comparison)
	return r
}
```

with:

```go
func (dlpVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)

	observed := ObservationUnknown
	if ev.SinkTokenObserved != nil {
		// Sink-primary: destination-side receipt is authoritative ground
		// truth for whether the data actually left, superseding the local
		// marker for this step -- see
		// docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md.
		if *ev.SinkTokenObserved {
			observed = ObservationSucceeded
		} else {
			observed = ObservationBlocked
		}
	} else if m := dlpMarkerRe.FindStringSubmatch(ev.RawOutput); m != nil {
		switch m[1] {
		case ObservationSucceeded, ObservationBlocked:
			observed = m[1]
		}
	}
	r.ObservedOutcome = observed
	r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
	r.Status = collapseToStatus(r.Comparison)
	return r
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -v`
Expected: PASS — every test in the package, including all pre-existing `TestDLPVerifier`/`TestDLPComparator`/`TestBuildDetectionValidationGoldenOutput` tests (confirms the new field/branch didn't change behavior for anything not explicitly using it).

- [ ] **Step 7: Run the full `internal/api` and `internal/reporting` suites**

```bash
cd orchestrator && go test ./internal/api/... ./internal/reporting/... -v -timeout 20m > <scratchpad>/dlp_sink_task4_full.log 2>&1
```

Same `Monitor` + full-log-read procedure as prior tasks.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/models/schema.go orchestrator/internal/reporting/detection_validation.go orchestrator/internal/reporting/dlp.go orchestrator/internal/reporting/dlp_test.go
git commit -m "$(cat <<'EOF'
feat(reporting): sink-receipt-primary verdict for DLP verification

dlpVerifier gains a second observation source: when SinkTokenObserved is
set (non-nil), it takes priority over the existing self-printed local
marker -- a destination-side confirmed receipt is stronger evidence of
whether data actually left than a script's own opinion of itself. nil
(the default for every existing step) falls back to the pre-existing
local-marker regex exactly as before, proven by an explicit regression
test. internal/reporting stays a pure function with no I/O throughout --
SinkTokenObserved is populated by the caller (internal/verifysync, next
task), never looked up from inside this package.
EOF
)"
git push
```

---

## Task 5: `verifysync` integration

**Files:**
- Modify: `orchestrator/internal/verifysync/job.go`
- Modify: `orchestrator/internal/verifysync/job_test.go`

**Interfaces:**
- Consumes: `dlp_sink_tokens`/`dlp_sink_receipts` tables (Task 1); `models.SimulationResult.SinkTokenObserved` (Task 4).
- Produces: nothing new consumed elsewhere — this task closes the loop.

- [ ] **Step 1: Write the failing test**

`orchestrator/internal/verifysync/job_test.go` already has the exact `sharedDB.RunWithPool` + `pool.Exec` seeding conventions this test follows (read in full during planning — its `TestTick_MarksProcessedRunsAutoVerified` is the closest precedent for direct-SQL seeding). Add:

```go
func TestAnnotateSinkReceipts_SetsObservedOnlyForIssuedTokens(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := verification.NewStore(pool)
		job := NewJob(pool, store, fakeResolver{})

		// T1567: token issued AND received -> want true.
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
			 VALUES ('tok-received', 'run-sink-annotate', 'T1567', NOW() + interval '10 minutes')`); err != nil {
			t.Fatalf("seed dlp_sink_tokens (received): %v", err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_receipts (token, payload_hash, payload_size, channel)
			 VALUES ('tok-received', 'deadbeef', 42, 'https-post')`); err != nil {
			t.Fatalf("seed dlp_sink_receipts: %v", err)
		}

		// T1052.001: token issued, never received -> want false.
		if _, err := pool.Exec(ctx,
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
			 VALUES ('tok-not-received', 'run-sink-annotate', 'T1052.001', NOW() + interval '10 minutes')`); err != nil {
			t.Fatalf("seed dlp_sink_tokens (not received): %v", err)
		}

		// T1115: no token issued at all -> want nil (untouched).
		results := []models.SimulationResult{
			{ID: "T1567"},
			{ID: "T1052.001"},
			{ID: "T1115"},
		}

		if err := job.annotateSinkReceipts(ctx, "run-sink-annotate", results); err != nil {
			t.Fatalf("annotateSinkReceipts: %v", err)
		}

		if results[0].SinkTokenObserved == nil || !*results[0].SinkTokenObserved {
			t.Errorf("T1567 SinkTokenObserved = %v, want true", results[0].SinkTokenObserved)
		}
		if results[1].SinkTokenObserved == nil || *results[1].SinkTokenObserved {
			t.Errorf("T1052.001 SinkTokenObserved = %v, want false", results[1].SinkTokenObserved)
		}
		if results[2].SinkTokenObserved != nil {
			t.Errorf("T1115 SinkTokenObserved = %v, want nil (no token was ever issued for this technique)", *results[2].SinkTokenObserved)
		}
	})
}
```

(This test needs `"github.com/audspect/bas/internal/models"` added to the file's import block — not currently imported there.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/verifysync/... -run TestAnnotateSinkReceipts -v`
Expected: FAIL to compile — `job.annotateSinkReceipts` undefined.

- [ ] **Step 3: Implement the annotation**

In `orchestrator/internal/verifysync/job.go`'s `processRun` (currently lines 80-91, confirmed this session), insert a new step between the existing `json.Unmarshal(resultsRaw, &results)` (line 83) and `verdicts := reporting.ComputeAutomaticVerifications(specs, results)` (line 91):

```go
func (j *Job) processRun(ctx context.Context, runID, scenarioID string, resultsRaw []byte) error {
	var results []models.SimulationResult
	if len(resultsRaw) > 0 {
		if err := json.Unmarshal(resultsRaw, &results); err != nil {
			return err
		}
	}
	if err := j.annotateSinkReceipts(ctx, runID, results); err != nil {
		return err
	}
	specs := reporting.ResolveStepDetectionSpecs(j.scenarios, scenarioID)
	if len(specs) == 0 {
		return nil // nothing declared any expectation
	}
	verdicts := reporting.ComputeAutomaticVerifications(specs, results)
	// ...rest of the function unchanged...
```

Add the new method:

```go
// annotateSinkReceipts sets SinkTokenObserved on each result whose
// technique had a sink token issued for this run -- true if
// dlp_sink_receipts shows it was received at least once, false if the
// token was issued but never received, left nil (untouched) for any
// technique with no issued token at all. Mutates results in place; this
// is the one place in the DLP sink verification path that touches the
// database -- internal/reporting stays a pure function throughout.
func (j *Job) annotateSinkReceipts(ctx context.Context, runID string, results []models.SimulationResult) error {
	rows, err := j.db.Query(ctx,
		`SELECT t.technique_id, EXISTS (
		   SELECT 1 FROM dlp_sink_receipts r WHERE r.token = t.token
		 ) AS received
		 FROM dlp_sink_tokens t WHERE t.run_id = $1`,
		runID,
	)
	if err != nil {
		return err
	}
	observed := map[string]bool{}
	for rows.Next() {
		var techniqueID string
		var received bool
		if err := rows.Scan(&techniqueID, &received); err != nil {
			rows.Close()
			return err
		}
		observed[techniqueID] = received
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range results {
		if received, ok := observed[results[i].ID]; ok {
			r := received
			results[i].SinkTokenObserved = &r
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/verifysync/... -v`
Expected: PASS — every test in the package, including all pre-existing ones.

- [ ] **Step 5: Run the full `internal/api`, `internal/reporting`, and `internal/verifysync` suites**

```bash
cd orchestrator && go test ./internal/api/... ./internal/reporting/... ./internal/verifysync/... -v -timeout 20m > <scratchpad>/dlp_sink_task5_full.log 2>&1
```

Same `Monitor` + full-log-read procedure as prior tasks.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/verifysync/job.go orchestrator/internal/verifysync/job_test.go
git commit -m "$(cat <<'EOF'
feat(verifysync): annotate results with sink receipt status

processRun now queries dlp_sink_tokens/dlp_sink_receipts for the run
before computing automatic verdicts, setting SinkTokenObserved on any
result whose technique had a sink token issued. This is the one place in
the whole sink-verification path that touches the database --
internal/reporting's verification engine remains a pure function of
(expectations, evidence) with no I/O, per that package's own documented
invariant.
EOF
)"
git push
```

---

## Task 6: V1 scenario content

**Files:**
- Create: `scenarios/dlp-exfiltration-sink-https.yaml`
- Create: `scenarios/dlp-exfiltration-sink-https.yaml.sig`
- Modify: `scenarios/detection-profiles/windows_dlp_exfiltration.yaml`

**Interfaces:**
- Consumes: `{{SINK_TOKEN}}`/`{{SINK_URL}}` placeholder substitution (Task 2); the `windows_dlp_exfiltration` detection profile's existing structure.

- [ ] **Step 1: Add the new scenario file**

Create `scenarios/dlp-exfiltration-sink-https.yaml`:

```yaml
id: dlp-exfiltration-sink-https
name: DLP Exfiltration Validation — Sink-Verified HTTPS Channel
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by dlp-exfiltration-validation.yaml (fabricated PAN, Aadhaar,
  SWIFT/BIC, UPI VPA, and credit-card patterns) via a generic HTTPS POST,
  verified by a destination-side receipt rather than a local self-reported
  marker.

  First channel of the sink-verified generation of DLP testing (see
  docs/superpowers/specs/2026-08-19-dlp-exfiltration-sink-service-design.md).
  Unlike dlp-exfiltration-validation.yaml's 5 local-marker-only steps, this
  step's verdict comes from whether the platform's own sink endpoint
  actually received the payload -- ground truth for whether the data left
  the endpoint, not an inference from a local file/clipboard/print-queue
  check. Deliberately kept as its own standalone scenario rather than a
  6th step in the existing file: mixing verification models within one
  file would muddy what each step actually proves.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The sink endpoint stores only a hash of the received payload, never
  the raw content. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:
  - name: "DLP Validation — Sink-Verified HTTPS Exfiltration (T1567)"
    technique_id: T1567
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own sink endpoint over HTTPS. No real data, no external destination -- the receiving endpoint is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3: network connection to the orchestrator's own HTTPS port"
    detection:
      - "DLP: outbound HTTPS POST body matching regulated-data patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      try {
        Invoke-RestMethod -Uri '{{SINK_URL}}' -Method Post -Body (@{token='{{SINK_TOKEN}}'; payload=$csvContent; channel='https-post'} | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "EXEC T1567: multi-type sensitive record POSTed over HTTPS. [BAS-SIM-DLP-SINK-HTTPS]"
      } catch {
        Write-Output "EXEC T1567: HTTPS POST to sink was blocked or failed before completing. [BAS-SIM-DLP-SINK-HTTPS]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the sink endpoint received the token, resolved
      # server-side by internal/verifysync, not from anything this script
      # can locally confirm.
    cleanup: ""
```

- [ ] **Step 2: Add the detection-profile entry**

In `scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, add `T1567` to the existing `technique_ids` list, and append a 6th `expected_detection` entry after the existing `dlp-local-stage-block` entry:

```yaml
technique_ids: [T1052, T1052.001, T1074.001, T1115, T1560.001, T1567]
```

```yaml
  - id: dlp-sink-https-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP did not block HTTPS exfiltration of regulated data"
      remediation: >-
        Confirm DLP/proxy content inspection covers outbound HTTPS POST
        bodies for PAN/Aadhaar/SWIFT/UPI/credit-card patterns and blocks
        the request rather than allowing it to complete.
      reference: "MITRE ATT&CK T1567 — Exfiltration Over Web Service"
```

- [ ] **Step 3: Sign the new scenario file**

From the repo root:

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-sink-https.yaml
```

Confirm `scenarios/dlp-exfiltration-sink-https.yaml.sig` was created.

- [ ] **Step 4: Confirm the scenario loads and is dispatchable**

Run: `cd orchestrator && go test ./internal/scenario/... -v`
Expected: PASS — every test in the package. None of the existing tests targets this one new file by name, but the engine's `Load` path scans the entire `scenarios/` directory, so a signature mismatch or malformed YAML in the new file would surface as a failure in `TestLoad_SourceClassification` or `TestLoad_SkipsMalformedFileWithoutBlockingOthers` (both exercise the real `scenarios/` directory contents). Confirms the new signed scenario loads cleanly alongside the existing built-ins.

- [ ] **Step 5: Commit**

```bash
git add scenarios/dlp-exfiltration-sink-https.yaml scenarios/dlp-exfiltration-sink-https.yaml.sig scenarios/detection-profiles/windows_dlp_exfiltration.yaml
git commit -m "$(cat <<'EOF'
feat(scenarios): sink-verified HTTPS DLP exfiltration channel

V1 channel proving the sink-verification architecture end-to-end. Kept as
a standalone scenario rather than a 6th step in the existing
dlp-exfiltration-validation.yaml -- that file's 5 steps use local-marker
verification, a different model than this step's sink-receipt-primary
verdict, and mixing them in one file would muddy what each step proves.
EOF
)"
git push
```

---

## Task 7: Full verification and handoff

**Files:** none (verification only)

- [ ] **Step 1: Run the full `internal/api`, `internal/reporting`, `internal/verifysync`, and `internal/scenario` test suites together**

```bash
cd orchestrator && go test ./internal/api/... ./internal/reporting/... ./internal/verifysync/... ./internal/scenario/... -v -timeout 20m > <scratchpad>/dlp_sink_final.log 2>&1
```

Use `Monitor` to watch for completion, then read the actual full log file and confirm every test passes with zero `--- FAIL` lines.

- [ ] **Step 2: Run the broader build**

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 3: No frontend changes needed**

This plan does not touch `wwwroot/index.html` — the spec's "Out of scope" section explicitly defers the DLP compliance dashboard to a later sub-project, and nothing in this plan's tasks requires a UI change (the sink service and its verdict feed the existing verification/reporting data model, which the frontend can surface later without needing today's plumbing to also ship a view for it). No JS syntax check needed for this plan.

- [ ] **Step 4: Announce completion and hand off**

Report to the user: the DLP exfiltration sink service is live — a new sink-verified HTTPS channel (`dlp-exfiltration-sink-https.yaml`) now gets a destination-side-confirmed verdict instead of a self-reported local marker, and the underlying token-issuance/sink/verification architecture is ready to extend to the other ~18 channels from the Cymulate reference as separate follow-on sub-projects. Then use the **finishing-a-development-branch** skill to verify tests one more time, detect the environment, and present the standard merge/PR/keep-as-is menu — per this session's established pattern, this plan is expected to run directly on `main` in the current working tree (no worktree).
