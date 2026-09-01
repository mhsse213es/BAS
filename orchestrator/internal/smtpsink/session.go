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
