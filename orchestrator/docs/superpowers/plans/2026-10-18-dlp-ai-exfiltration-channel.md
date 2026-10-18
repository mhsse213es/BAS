# DLP-AI Exfiltration Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the `DLP-AI` gap (`dlp.txt` §3B) — a new sink package mimicking a public AI chat-completion API and an enterprise AI connector-ingestion API, plus a scenario that exercises both.

**Architecture:** A new standalone package `internal/aisink`, structured identically to `internal/webhooksink` (one router/shared-helpers file + one file per route), mounted on the orchestrator's existing API server. Destination-side-receipt verification only via the existing `dlp_sink_tokens`/`dlp_sink_receipts` tables — no schema change.

**Tech Stack:** Go stdlib, `chi` router, `pgx` — all already repo dependencies. No new dependency.

**Spec:** `orchestrator/docs/superpowers/specs/2026-10-18-dlp-ai-exfiltration-channel-design.md`.

## Global Constraints

- Never contact a real AI vendor API — traffic-shape simulation only, identical boundary to every sibling sink.
- Token extraction follows the exact precedent in `internal/webhooksink/slack.go`/`teams.go`: first line of a body text field, `strings.SplitN(text, "\n", 2)[0]`. No header-based or path-param-based token carrying.
- `rateLimiter`/`tokenExists`/`writeReceipt`/`MaxPayloadBytes` are duplicated into `aisink`, not imported from `webhooksink` — matches that package's own stated precedent (the type is unexported there too).
- Every handler returns a plausible success response regardless of token match; a receipt is written only when the token matches an existing `dlp_sink_tokens` row.
- `MITRE` technique on every new scenario step is `T1567` (parent "Exfiltration Over Web Service"), never a sub-technique — see spec Goal 4.
- The new scenario must be `windows`-only, `framework: custom`, `executor: powershell`, matching every sibling DLP exfiltration scenario's own `supported_os`/`framework`/`executor`.

## Review Focus

- A request whose body is malformed JSON (not valid `messages`/`content` shape) must not panic and must still return the handler's normal success response with no receipt written — mirrors `slack.go`'s own `if json.Unmarshal(body, &payload) == nil` guard; an attacker-controlled body is adversarial input by construction.
- An oversized body (over `MaxPayloadBytes`) must be rejected with a non-200 status before any token comparison — same `http.MaxBytesReader` discipline as every sibling channel.
- A request with an unmatched (never-issued or already-expired) token must still return the handler's normal success status and must never write a `dlp_sink_receipts` row — proven by `assertNoReceipt`, not just "the test didn't crash."
- Two requests carrying the same valid token (a legitimate retry) must each be allowed to write their own receipt row — `dlp_sink_receipts.token` is deliberately not unique (see `internal/db/postgres.go`'s own comment); a handler that de-duplicates receipts by token would silently break retry-evidence semantics other sinks rely on.
- The rate limiter must track `aisink`'s own request volume independently of `webhooksink`'s shared limiter instance — two different packages, two different limiter instances, confirmed by a test that exhausts one route's budget and shows the other route (in the same package) is independently limited only by its own package-level instance, not cross-package interference (this is inherent to each package owning its own `var limiter`, but the test proves it rather than assuming it).

---

### Task 1: `internal/aisink` package — router, shared helpers, both handlers

**Files:**
- Create: `orchestrator/internal/aisink/aisink.go` (router + rate limiter + `tokenExists`/`writeReceipt`, copied from `webhooksink.go`'s own shape)
- Create: `orchestrator/internal/aisink/chatcompletion.go`
- Create: `orchestrator/internal/aisink/connectoringestion.go`
- Test: `orchestrator/internal/aisink/aisink_test.go`, `chatcompletion_test.go`, `connectoringestion_test.go`

**Interfaces:**
- Consumes: `internal/testutil.TestDB`/`MustSharedTestDB` (existing shared test harness, same as `webhooksink_test.go`).
- Produces: `aisink.Routes(db *pgxpool.Pool) chi.Router`, mounted by Task 2.

- [ ] **Step 1: Write the failing tests**

`aisink_test.go` (shared helpers, copied and adapted from `webhooksink_test.go`):

```go
package aisink

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

func seedToken(t *testing.T, pool *pgxpool.Pool, token, runID, techniqueID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
		token, runID, techniqueID, time.Now().Add(10*time.Minute),
	); err != nil {
		t.Fatalf("seed dlp_sink_tokens: %v", err)
	}
}

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
	time.Sleep(200 * time.Millisecond)
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

func chatBody(t *testing.T, content string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"model":    "bas-sim-model",
		"messages": []map[string]string{{"role": "user", "content": content}},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	return b
}

func connectorBody(t *testing.T, contentValue string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"id":      "bas-sim-item",
		"content": map[string]string{"value": contentValue, "type": "text"},
	})
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

func TestTokenExists_FalseForNilDB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tokenExists(ctx, nil, "any-token") {
		t.Error("tokenExists must not panic or return true when db is nil / ctx is cancelled")
	}
}
```

`chatcompletion_test.go`:

```go
package aisink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const chatCompletionPath = "/v1/chat/completions"

func TestChatCompletion_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		seedToken(t, pool, token, "run-ai-chat-1", "T1567")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		content := token + "\n[BAS-SIM-DLP] test payload"
		body := chatBody(t, content)
		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer bas-sim-irrelevant-key")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "ai-chat-completion", len(body))
	})
}

func TestChatCompletion_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := chatBody(t, "never-issued-token\nunrelated body")
		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(body))
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

func TestChatCompletion_MalformedBodyStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader([]byte("not json at all")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for a malformed body", resp.StatusCode)
		}
	})
}

func TestChatCompletion_OversizedBodyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		tooBig := chatBody(t, string(bytes.Repeat([]byte("x"), MaxPayloadBytes+1024)))
		req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(tooBig))
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

func TestChatCompletion_RetryWithSameTokenRecordsBothReceipts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1"
		seedToken(t, pool, token, "run-ai-chat-retry", "T1567")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := chatBody(t, token+"\nretry payload")
		for i := 0; i < 2; i++ {
			req, _ := http.NewRequest(http.MethodPost, srv.URL+chatCompletionPath, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST %d: %v", i, err)
			}
			resp.Body.Close()
		}

		var count int
		deadline := timeNowPlus5s()
		for {
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM dlp_sink_receipts WHERE token = $1`, token).Scan(&count); err == nil && count >= 2 {
				break
			}
			if pastDeadline(deadline) {
				t.Fatalf("expected 2 receipts for retried token, got %d", count)
			}
			sleep50ms()
		}
	})
}
```

(The last test's `timeNowPlus5s`/`pastDeadline`/`sleep50ms`/`context` helpers: use `time.Now().Add(5*time.Second)`, `time.Now().After(deadline)`, `time.Sleep(50*time.Millisecond)`, and `"context"` directly inline rather than as named helpers — written as separate calls above only to keep this plan's code block narrow; the implementer writes them inline exactly as `assertReceiptRecorded` already does above.)

`connectoringestion_test.go` — same 5-test shape as `chatcompletion_test.go`, substituting:
- Path: `/v1.0/external/connections/bas-sim-connection/items/bas-sim-item`
- Body builder: `connectorBody(t, content)`
- Expected channel: `"ai-connector-ingestion"`
- Expected success status: `201` (not 200)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test github.com/audspect/bas/internal/aisink/... -v`
Expected: FAIL (package `aisink` does not exist yet — build failure, not a runtime failure)

- [ ] **Step 3: Implement**

`aisink.go` — copy `webhooksink.go`'s `rateLimiter`/`windowCount`/`newRateLimiter`/`allow`/`tokenExists`/`writeReceipt`/`MaxPayloadBytes`/`rateLimitPerSecond`/`limiter` verbatim (package `aisink`), plus:

```go
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Post("/v1/chat/completions", handleChatCompletion(db))
	r.Post("/v1.0/external/connections/{connectionId}/items/{itemId}", handleConnectorIngestion(db))
	return r
}
```

`chatcompletion.go` — `handleChatCompletion(db *pgxpool.Pool) http.HandlerFunc`, same structural shape as `slack.go`'s `handleSlackWebhook`: rate-limit check, `MaxBytesReader`, `io.ReadAll`, unmarshal into `struct { Messages []struct{ Content string `json:"content"` } `json:"messages"` } }`, token = first line of `Messages[0].Content` (guard the empty-messages case — return token `""`), `tokenExists`+`writeReceipt` with channel `"ai-chat-completion"`, respond 200 with `{"choices":[{"message":{"content":"ok"}}]}`.

`connectoringestion.go` — `handleConnectorIngestion(db *pgxpool.Pool) http.HandlerFunc`, same shape, unmarshal into `struct { Content struct{ Value string `json:"value"` } `json:"content"` } }`, token = first line of `Content.Value`, channel `"ai-connector-ingestion"`, respond 201 with `{"id":"bas-sim-item"}`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test github.com/audspect/bas/internal/aisink/... -v`
Expected: PASS (all tests in both new test files, plus the 2 shared-helper tests)

- [ ] **Step 5: `gofmt -l` and `go vet` the package**

Run: `gofmt -l orchestrator/internal/aisink/` and `go vet github.com/audspect/bas/internal/aisink/...`
Expected: no output from either (verify any `gofmt -l` hit with a CRLF-stripped diff before concluding it's a real issue — known Windows checkout artifact on this host)

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/aisink/
git commit -m "feat(aisink): add AI chat-completion and connector-ingestion exfiltration sink"
```

---

### Task 2: Mount `/aisink` routes and add the DLP-AI scenario

**Files:**
- Modify: `orchestrator/internal/api/routes.go` (mount point only)
- Create: `scenarios/dlp-exfiltration-ai-prompt.yaml`
- Create: `scenarios/dlp-exfiltration-ai-prompt.yaml.sig` (signed, see Step 5)

**Interfaces:**
- Consumes: Task 1's `aisink.Routes(db *pgxpool.Pool) chi.Router`.
- Produces: nothing further downstream — this is the terminal task of this plan.

- [ ] **Step 1: Mount the routes**

In `routes.go`, add the import and, in the same block as the existing `/cloudsink`/`/webhooksink` mounts:

```go
r.Mount("/aisink", aisink.Routes(h.db))
```

- [ ] **Step 2: Write the scenario**

`scenarios/dlp-exfiltration-ai-prompt.yaml` — 4 steps, `windows`-only, `framework: custom`, `executor: powershell`, `technique_id: T1567` on every step, tags including `dlp`/`data-protection-validation`/`exfiltration`/`ai`/`windows`/`mitre-attack`/`bfsi`/`india` (matching sibling scenarios' own tag set):

1. Chat-completion — stock BFSI/India multi-type record (fabricated PAN/Aadhaar/SWIFT/UPI/card), `{{SINK_TOKEN}}`/`{{SINK_URL}}` placeholders, `Invoke-RestMethod -Uri "{{SINK_URL}}/aisink/v1/chat/completions" -Method Post -Body (@{model="bas-sim-model";messages=@(@{role="user";content="{{SINK_TOKEN}}`n[BAS-SIM-DLP] <record>"})} | ConvertTo-Json -Depth 5) -ContentType "application/json"` (follow `dlp-exfiltration-webhook.yaml`'s own PowerShell step structure and `Write-Output`/exception-handling convention exactly).
2. Chat-completion — a source-code-shaped synthetic record (distinct data type, per content-type-diversity precedent).
3. Connector-ingestion — stock BFSI/India record, posted to `{{SINK_URL}}/aisink/v1.0/external/connections/bas-sim-connection/items/bas-sim-item`.
4. Connector-ingestion — a second distinct data type (e.g. a contract/employment-agreement-shaped record, matching a type already used by a sibling scenario per the content-diversity precedent, for cross-scenario consistency).

Scenario-level `description` must state plainly: traffic-shape simulation only, no real AI vendor contacted, and must name the scope boundary from the spec's Anti-goals (no multi-turn conversation state, no RAG retrieval simulation, no prompt-injection/jailbreak testing — this is a DLP exfiltration-channel test only).

- [ ] **Step 3: Verify the scenario against the existing YAML schema**

Run the repo's scenario-signature/schema validation command used for every prior DLP scenario (check `orchestrator/scripts/` or the scenario-loading test suite for the exact command; this plan does not re-specify it since it's identical across every sibling scenario in this program).

- [ ] **Step 4: Run the full build + the new package's tests one more time**

Run: `go build github.com/audspect/bas/... ` and `go test github.com/audspect/bas/internal/aisink/... -v`
Expected: both clean / PASS

- [ ] **Step 5: Sign the scenario**

Use the same signing mechanism/script every other `scenarios/*.yaml.sig` file in this repo was produced by (the private key copied into this worktree at setup time per this session's own worktree convention).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/routes.go scenarios/dlp-exfiltration-ai-prompt.yaml scenarios/dlp-exfiltration-ai-prompt.yaml.sig
git commit -m "feat(dlp): mount aisink routes and add DLP-AI exfiltration scenario"
```

---

## Self-Review Notes

- **Spec coverage:** Goal 1 (2 route shapes) → Task 1. Goal 2 (destination-side-receipt discipline) → Task 1's tests, directly mirroring `webhooksink`'s own test names. Goal 3 (scenario with ≥2 data-type-diverse steps per shape) → Task 2 Step 2. Goal 4 (T1567 parent technique) → Task 2 Step 2's explicit instruction.
- **Step scan:** Task 1's handler bodies are described by exact struct shapes and the token-extraction line, not transcribed in full — matches `slack.go`'s own brevity; the implementer writes the body, the plan fixes only what it must (channel string, response code, response body shape).
- **Type consistency:** `chatBody`/`connectorBody` helper signatures match what both test files call; channel strings (`"ai-chat-completion"`/`"ai-connector-ingestion"`) are identical between the Task 1 test assertions and the Task 1 implementation instructions.
- **Review Focus:** all 5 items have a named test above (malformed body, oversized body, unmatched token, same-token retry, and the independent-rate-limiter property — the last one covered implicitly by `aisink` owning its own `var limiter`, proven the same way `webhooksink`'s own `TestRateLimiter_TracksSourcesIndependently` proves per-source independence; this plan's shared-helpers test list already includes `TestRateLimiter_AllowsUpToLimitPerWindow`, and the per-package-instance independence from `webhooksink` is structural, not re-tested by a redundant cross-package test).
- **Proportion check:** 2 tasks for a 2-route sink package plus 1 scenario — smaller than DLP-ENF's 2-task split, proportionate to a single new package with a well-established precedent to copy.
- **Anti-goal check:** no real AI vendor contacted anywhere in this plan; no prompt-injection/jailbreak content in any test or scenario step; the scenario's own description explicitly states the 2026-10-18 scope boundary per the spec's Anti-goals section.
