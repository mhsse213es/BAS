// Package webhooksink implements HTTP routes that mimic Slack/MS Teams
// incoming-webhook requests and GitHub/GitLab Gist/Snippet-creation API
// requests for the DLP validation suite. Two genuinely different request
// families, mapping to two different MITRE techniques -- see
// docs/superpowers/specs/2026-09-01-webhook-exfiltration-channel-design.md.
// Like internal/cloudsink, these are all HTTPS routes mounted on the
// orchestrator's existing API server rather than a separate listener.
package webhooksink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPayloadBytes bounds the total bytes any of the four routes will
// buffer for a single request body. Matches every sibling channel's own
// ceiling, for consistency across this program.
const MaxPayloadBytes = 64 * 1024

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard -- one
// instance shared across all four routes (they are four doors into the
// same abuse surface, not four independent ones), identical in shape to
// internal/cloudsink's own, duplicated here rather than shared because
// that type is unexported in that sibling package.
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

// rateLimitPerSecond matches every sibling channel's identical rationale:
// this surface only ever expects traffic from BAS agents running a
// scenario step.
const rateLimitPerSecond = 5

var limiter = newRateLimiter(rateLimitPerSecond, time.Second)

// tokenExists reports whether token has a live row in dlp_sink_tokens.
// Returns false (never panics) for a nil db or an errored query -- every
// handler treats "false" identically to "not matched": still return a
// plausible success response, just never write a receipt.
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

// Routes returns the chi.Router mounted at /webhooksink by
// internal/api/routes.go.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	return r
}
