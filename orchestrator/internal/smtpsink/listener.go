package smtpsink

import (
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
	ln     net.Listener
	srv    *smtp.Server
	status atomic.Value
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
