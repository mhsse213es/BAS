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
