// Package cloudsink implements HTTP routes that mimic seven cloud-storage
// providers' real upload-request shapes (path, method, headers, body
// structure) for the DLP validation suite. Unlike internal/dnssink,
// internal/sftpsink, and internal/smtpsink -- each a genuinely distinct
// non-HTTP wire protocol needing its own listener -- these seven providers
// are all HTTPS REST APIs, so this package exposes routes mounted on the
// orchestrator's existing API server rather than owning a separate
// listener. No real cryptographic request signing (SigV4, Azure SAS,
// OAuth) is implemented anywhere in this package -- see
// docs/superpowers/specs/2026-09-01-cloud-storage-exfiltration-channel-design.md.
package cloudsink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MaxUploadBytes bounds the total bytes any of the seven routes will buffer
// for a single request body. Matches sftpsink.MaxUploadBytes and
// smtpsink.MaxMessageBytes exactly, for consistency across every channel in
// this program.
const MaxUploadBytes = 64 * 1024

// rateLimiter is a coarse, fixed-window per-source-IP abuse guard -- one
// instance shared across all seven routes (they are seven doors into the
// same abuse surface, not seven independent ones), identical in shape to
// internal/sftpsink's and internal/smtpsink's own, duplicated here rather
// than shared because that type is unexported in each sibling package.
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

// rateLimitPerSecond is a coarse per-source-IP abuse guard, matching every
// sibling channel's identical rationale: this surface only ever expects
// traffic from BAS agents running a scenario step.
const rateLimitPerSecond = 5

var limiter = newRateLimiter(rateLimitPerSecond, time.Second)

// tokenExists reports whether token has a live row in dlp_sink_tokens.
// Returns false (never panics) for a nil db or a cancelled/errored query --
// every handler treats "false" identically to "not matched": still return a
// plausible success response, just never write a receipt. Cloud storage
// validates the token before writing a receipt (unlike the HTTP/SFTP
// accept-anything pattern) because seven open, unauthenticated endpoints
// accepting any request body is a meaningfully larger accidental-scanning
// surface than one SMTP listener or one narrow SFTP filename check -- same
// reasoning SMTP's Subject-match requirement already established.
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

// Routes returns the chi.Router mounted at /cloudsink by
// internal/api/routes.go.
func Routes(db *pgxpool.Pool) chi.Router {
	r := chi.NewRouter()
	r.Put("/s3/{bucket}/{key}", handleS3Put(db))
	r.Put("/azureblob/{container}/{blob}", handleAzureBlobPut(db))
	r.Put("/graph/v1.0/me/drive/root:/{filename}:/content", handleOneDrivePut(db))
	r.Post("/gdrive/upload/drive/v3/files", handleGDriveUpload(db))
	r.Post("/dropbox/2/files/upload", handleDropboxUpload(db))
	r.Post("/gcs/upload/storage/v1/b/{bucket}/o", handleGCSUpload(db))
	r.Post("/box/2.0/files/content", handleBoxUpload(db))
	return r
}
