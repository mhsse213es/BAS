// Package telnetsink implements an HTTP route that simulates Telnet
// exfiltration by receiving a JSON-encoded conversation (connect →
// prompt → command → response → close) and validating/recording the
// contained token. Routes are mounted on the existing HTTPS API server,
// not a separate listener.
package telnetsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxPayloadBytes bounds the total bytes the route will buffer for a
// single request body. Matches every sibling channel's ceiling.
const MaxPayloadBytes = 64 * 1024

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard.
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

const rateLimitPerSecond = 5

var limiter = newRateLimiter(rateLimitPerSecond, time.Second)

// tokenExists reports whether token has a live row in dlp_sink_tokens.
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

// writeReceipt hashes body (SHA-256) and writes one dlp_sink_receipts row.
func writeReceipt(ctx context.Context, db *pgxpool.Pool, token, sourceIP, channel string, body []byte) error {
	sum := sha256.Sum256(body)
	_, err := db.Exec(ctx,
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		token, sourceIP, hex.EncodeToString(sum[:]), len(body), channel,
	)
	return err
}

type TelnetSession struct {
	Token   string      `json:"token"`
	Session []StateStep `json:"session"`
}

type StateStep struct {
	Type string `json:"type"` // "connect", "prompt", "command", "response", "close"
	Data string `json:"data,omitempty"`
}

func handleTelnetSession(db *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		sourceIP := strings.Split(r.RemoteAddr, ":")[0]

		// Rate limit
		if !limiter.allow(sourceIP) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"rate_limited"}`)
			return
		}

		// Enforce max payload
		r.Body = http.MaxBytesReader(w, r.Body, MaxPayloadBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"oversized"}`)
			return
		}

		// Parse request
		var session TelnetSession
		if err := json.Unmarshal(body, &session); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"invalid_json"}`)
			return
		}

		// Validate token
		if !tokenExists(ctx, db, session.Token) {
			// No match: still return 200 with plausible response, but no receipt
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"ok","message":"Session closed"}`)
			return
		}

		// Token matched: write receipt
		if err := writeReceipt(ctx, db, session.Token, sourceIP, "telnet", body); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `{"result":"receipt_error"}`)
			return
		}

		// Success
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"result":"ok","message":"Session closed"}`)
	}
}

// Routes returns the chi.Router mounted at /telnet by internal/api/routes.go.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Post("/session", handleTelnetSession(db))
	return r
}
