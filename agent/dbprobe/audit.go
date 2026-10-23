package dbprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"audspect/agent/protocol"
)

// Audit evidence bounds. Evidence is minimised: only events carrying the
// probe's own marker, at most AuditMaxEvents of them, each statement cut to
// AuditMaxStatementBytes on a rune boundary.
const (
	AuditMaxEvents         = 50
	AuditMaxStatementBytes = 512
)

// Audit status values carried in protocol.DBProbeResult.AuditStatus.
const (
	AuditStatusUnsupported = protocol.DBAuditUnsupported
	AuditStatusAbsent      = protocol.DBAuditAbsent
	AuditStatusFound       = protocol.DBAuditFound
	AuditStatusIncomplete  = protocol.DBAuditIncomplete
	AuditStatusError       = protocol.DBAuditError
)

// AuditWindowSkew pads the collection window on both sides. The probe's start
// and end are taken from the database clock where the engine reports one, but
// the audit source (log writer, performance_schema timer conversion) can lag
// or be off by a second or two, so the window is deliberately generous. The
// marker, not the window, is what ties an event to the run.
const AuditWindowSkew = 5 * time.Second

// MetaStatementTag is the leading comment of the adapter's own metadata and
// audit queries (markerComment of the "dbsim-meta" marker). Events whose text
// carries it are the collector reading the log, never evidence about a probe.
var MetaStatementTag = MarkerComment(MetaMarker)

// MetaMarker is the marker of the adapters' own metadata and audit queries.
const MetaMarker = "dbsim-meta"

// SyncMarkerPrefix prefixes the per-collection sentinel marker.
const SyncMarkerPrefix = "dbsim-sync:"

var unsafeMarker = regexp.MustCompile(`[^A-Za-z0-9._:-]`)

// SanitizeMarker reduces a marker to [A-Za-z0-9._:-] and at most max bytes, so
// it can neither terminate nor turn the leading SQL comment into an executable
// /*! ... */ comment.
func SanitizeMarker(m string, max int) string {
	m = unsafeMarker.ReplaceAllString(m, "_")
	if len(m) > max {
		m = m[:max]
	}
	return m
}

// MarkerComment is the leading SQL comment carrying a marker. It is the single
// definition used by the adapters (to tag the statements they run) and by the
// audit matcher (to recognise them again), so the two can never drift.
func MarkerComment(marker string) string {
	m := SanitizeMarker(marker, 120)
	if m == "" {
		m = "none"
	}
	return "/* dbsim:" + m + " */"
}

// NewSentinelMarker returns a fresh random marker for one sync sentinel.
func NewSentinelMarker() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	}
	return SyncMarkerPrefix + hex.EncodeToString(b[:])
}

// auditSourceWords are fragments naming the audit sources themselves. A
// statement mentioning any of them is an audit lookup or configuration read,
// never evidence about a probe (defence in depth beside the tag checks).
var auditSourceWords = []string{"general_log", "events_statements_history_long", "pg_log", "dbsim_audit"}

// ownStatement reports whether stmt is the probe's own statement: its trimmed
// text BEGINS with the probe's marker comment, and it is not the collector's
// own meta/audit-lookup statement. A statement that merely contains the marker
// (in a WHERE clause, in another run's statement) is not the probe's. If an
// audit path strips or normalises the leading comment the statement is not
// identified, which yields absent/incomplete, never found.
func ownStatement(stmt, marker string) bool {
	s := strings.TrimSpace(stmt)
	if !strings.HasPrefix(s, MarkerComment(marker)) || strings.Contains(s, MetaStatementTag) {
		return false
	}
	low := strings.ToLower(s)
	for _, w := range auditSourceWords {
		if strings.Contains(low, w) {
			return false
		}
	}
	return true
}

var (
	// ErrAuditUnsupported means the adapter discovered no usable audit source.
	// Callers must treat it as SKIPPED, never as a pass.
	ErrAuditUnsupported = errors.New("dbprobe: no audit source available")
	// ErrAuditIncomplete means the returned slice may be missing events: the
	// source's retained window starts after the requested Since (rotated or
	// evicted), or the result hit the cap.
	ErrAuditIncomplete = errors.New("dbprobe: audit evidence incomplete")
)

// AuditIncompleteError is ErrAuditIncomplete with a reason. The events returned
// alongside it are valid but not necessarily all of them.
type AuditIncompleteError struct{ Reason string }

func (e *AuditIncompleteError) Error() string {
	if e.Reason == "" {
		return ErrAuditIncomplete.Error()
	}
	return ErrAuditIncomplete.Error() + ": " + e.Reason
}

// Is makes errors.Is(err, ErrAuditIncomplete) true.
func (e *AuditIncompleteError) Is(target error) bool { return target == ErrAuditIncomplete }

// AuditStatusOf maps a CollectAudit result to the wire status. An unknown
// error is always "error", never "absent": a failed collection proves nothing.
func AuditStatusOf(events []AuditEvent, err error) string {
	switch {
	case err == nil && len(events) > 0:
		return AuditStatusFound
	case err == nil:
		return AuditStatusAbsent
	case errors.Is(err, ErrAuditUnsupported):
		return AuditStatusUnsupported
	case errors.Is(err, ErrAuditIncomplete):
		return AuditStatusIncomplete
	}
	return AuditStatusError
}

// EscapeLike escapes the LIKE wildcards and the default escape character so s
// matches literally. Both PostgreSQL and MySQL use backslash as the default
// LIKE escape, so no ESCAPE clause (whose quoting differs by sql_mode) is used.
func EscapeLike(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// TruncateUTF8 cuts s to at most max bytes without splitting a rune.
func TruncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// NormalizeAudit is the shared evidence-minimisation step for both engines.
// raw is whatever the source returned for the marker pattern (already
// time-ordered); sourceOverflow says the source had more rows than the cap.
// It keeps only events whose statement contains the exact marker (LIKE
// collations can be case-insensitive), drops the collector's own queries and
// events of a different known principal, redacts, truncates and caps. When the
// cap or the source overflowed it returns the events with an
// *AuditIncompleteError.
func NormalizeAudit(q AuditQuery, raw []AuditEvent, redact func(string) string, sourceOverflow bool) ([]AuditEvent, error) {
	out := make([]AuditEvent, 0, len(raw))
	for _, e := range raw {
		if !ownStatement(e.Statement, q.Marker) {
			continue
		}
		// The Principal filter only narrows: an event with an EMPTY principal
		// (history_long once the thread has ended) passes it, because the
		// positive marker-comment match above already ties it to this run.
		if q.Principal != "" && e.Principal != "" && e.Principal != q.Principal {
			continue
		}
		e.Statement = TruncateUTF8(redact(e.Statement), AuditMaxStatementBytes)
		out = append(out, e)
	}
	if len(out) > AuditMaxEvents {
		return out[:AuditMaxEvents], &AuditIncompleteError{Reason: "event cap reached"}
	}
	if sourceOverflow {
		return out, &AuditIncompleteError{Reason: "source returned more rows than the cap"}
	}
	return out, nil
}

// AuditFetch is one read of the audit source for a marker.
type AuditFetch struct {
	Raw      []AuditEvent // time-ordered rows matching the marker pattern (at most cap+1)
	Covered  bool         // the retained log reaches back to the window start
	Overflow bool         // the source had more rows than the cap
}

// AuditFetchFunc reads the audit source for marker within q's window.
type AuditFetchFunc func(ctx context.Context, marker string, q AuditQuery) (AuditFetch, error)

// AuditSync injects the clock and sleep used while waiting for the audit
// source to catch up (zero values use the real ones; tests inject fakes).
type AuditSync struct {
	Now    func() time.Time
	Sleep  func(ctx context.Context, d time.Duration) error
	Budget time.Duration // total wait, default 5s
}

const (
	syncPollStart = 250 * time.Millisecond
	syncPollMax   = time.Second
	syncBudget    = 5 * time.Second
)

func (s AuditSync) withDefaults() AuditSync {
	if s.Now == nil {
		s.Now = time.Now
	}
	if s.Sleep == nil {
		s.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	if s.Budget <= 0 {
		s.Budget = syncBudget
	}
	return s
}

// CollectWithSync reads marker evidence only once the audit source has proven
// it caught up. Some sources (PostgreSQL csvlog) are written asynchronously, so
// "no marker event yet" proves nothing at the instant the probe ends. It first
// runs sentinel (the adapter issues one extra READ ONLY statement tagged with a
// fresh random marker and returns that marker), then polls the source with
// backoff (250ms doubling to 1s, bounded by the total budget, honouring ctx)
// until the sentinel statement is visible. Only then does the lookup for q.Marker
// run, and only then may it conclude absent. If the sentinel never appears the
// result is incomplete ("audit source did not catch up"), never absent. A
// sentinel or fetch failure is an error. Sentinel statements are never returned
// as events.
func CollectWithSync(ctx context.Context, q AuditQuery, sentinel func(context.Context) (string, error),
	fetch AuditFetchFunc, redact func(string) string, s AuditSync) ([]AuditEvent, error) {
	s = s.withDefaults()
	sm, err := sentinel(ctx)
	if err != nil {
		return nil, err
	}
	win := q
	win.Marker = sm
	win.Until = q.Until.Add(time.Minute) // the sentinel runs after the probe window closes
	deadline := s.Now().Add(s.Budget)
	interval := syncPollStart
	caught := false
	for {
		f, err := fetch(ctx, sm, win)
		if err != nil {
			return nil, err
		}
		for _, e := range f.Raw {
			if ownStatement(e.Statement, sm) {
				caught = true
				break
			}
		}
		if caught || !s.Now().Before(deadline) {
			break
		}
		if err := s.Sleep(ctx, interval); err != nil {
			return nil, err
		}
		if interval *= 2; interval > syncPollMax {
			interval = syncPollMax
		}
	}
	f, err := fetch(ctx, q.Marker, q)
	if err != nil {
		return nil, err
	}
	events, nerr := NormalizeAudit(q, f.Raw, redact, f.Overflow)
	if nerr == nil && !f.Covered {
		nerr = &AuditIncompleteError{Reason: "audit source retains no entry at or before the window start (rotated, evicted or enabled mid-run)"}
	}
	if nerr == nil && !caught {
		nerr = &AuditIncompleteError{Reason: "audit source did not catch up"}
	}
	return events, nerr
}
