package dbprobe

import (
	"errors"
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
const MetaStatementTag = "/* dbsim:dbsim-meta */"

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
		if !strings.Contains(e.Statement, q.Marker) || strings.Contains(e.Statement, MetaStatementTag) {
			continue
		}
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
