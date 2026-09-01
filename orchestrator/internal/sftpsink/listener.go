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
