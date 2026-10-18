// Package aisink implements HTTP routes that mimic a public AI
// chat-completion API and an enterprise AI connector-ingestion API for the
// DLP validation suite's DLP-AI exfiltration channel -- see
// docs/superpowers/specs/2026-10-18-dlp-ai-exfiltration-channel-design.md.
// Never contacts a real AI vendor; traffic-shape simulation only. Like
// internal/webhooksink, these are HTTPS routes mounted on the
// orchestrator's existing API server rather than a separate listener.
package aisink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPayloadBytes bounds the total bytes either route will buffer for a
// single request body. Matches every sibling channel's own ceiling.
const MaxPayloadBytes = 64 * 1024

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard, one
// instance shared across both routes in this package -- identical in
// shape to internal/webhooksink's own, duplicated here rather than shared
// because that type is unexported in that sibling package.
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

// writeReceipt hashes body (SHA-256, raw content never persisted) and
// writes one dlp_sink_receipts row for the given channel. Callers must
// have already confirmed the token exists via tokenExists.
func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP, channel string, body []byte) error {
	sum := sha256.Sum256(body)
	_, err := db.Exec(ctx,
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		token, sourceIP, hex.EncodeToString(sum[:]), len(body), channel,
	)
	return err
}

// Routes returns the chi.Router mounted at /aisink by
// internal/api/routes.go.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Post("/v1/chat/completions", handleChatCompletion(db))
	r.Post("/v1.0/external/connections/{connectionId}/items/{itemId}", handleConnectorIngestion(db))
	return r
}
