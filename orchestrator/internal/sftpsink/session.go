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
