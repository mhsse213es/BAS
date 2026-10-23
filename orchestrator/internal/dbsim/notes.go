package dbsim

import (
	"regexp"
	"strconv"
	"strings"
)

// The agent reports probe observations that have no typed wire field as
// DBProbeResult.Notes lines of the form "key=value" (rows_read, bytes_read,
// truncated, row_cap_applied, duration_ms, shape, settings such as
// log_statement, ...) plus the audit coverage summary "audit_config: <v>".
// ParseNotes is the single parser for them; grading and reports must use it
// rather than scanning Notes with ad-hoc string matching. Notes are untrusted
// agent output, so parsing is bounded and tolerant: anything that does not
// look like a note is ignored, never an error.
const (
	maxParsedNotes    = 64
	maxNoteBytes      = 1024
	maxNoteValueBytes = 256
	maxNoteCount      = int64(1) << 40
)

var reNoteKey = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

// Notes is the parsed key/value view of DBProbeResult.Notes. The first
// occurrence of a key wins, so a later line cannot override an earlier one.
type Notes struct{ kv map[string]string }

// ParseNotes parses at most 64 notes, each at most 1 KiB, keeping values to
// 256 bytes.
func ParseNotes(notes []string) Notes {
	n := Notes{kv: map[string]string{}}
	for i, line := range notes {
		if i >= maxParsedNotes {
			break
		}
		if len(line) > maxNoteBytes {
			line = line[:maxNoteBytes]
		}
		var k, v string
		if rest, ok := strings.CutPrefix(line, "audit_config:"); ok {
			k, v = "audit_config", strings.TrimSpace(rest)
		} else if kk, vv, ok := strings.Cut(line, "="); ok && reNoteKey.MatchString(kk) {
			k, v = kk, strings.TrimSpace(vv)
		} else {
			continue
		}
		if len(v) > maxNoteValueBytes {
			v = v[:maxNoteValueBytes]
		}
		if _, dup := n.kv[k]; !dup {
			n.kv[k] = v
		}
	}
	return n
}

// Get returns the raw value for key.
func (n Notes) Get(key string) (string, bool) {
	v, ok := n.kv[key]
	return v, ok
}

// Int returns key as a non-negative count; a missing, non-numeric, negative or
// absurdly large value is reported as absent.
func (n Notes) Int(key string) (int, bool) {
	v, ok := n.kv[key]
	if !ok {
		return 0, false
	}
	x, err := strconv.ParseInt(v, 10, 64)
	if err != nil || x < 0 || x > maxNoteCount {
		return 0, false
	}
	return int(x), true
}

// Bool returns key as a boolean ("true"/"false"/"1"/"0").
func (n Notes) Bool(key string) (bool, bool) {
	v, ok := n.kv[key]
	if !ok {
		return false, false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, false
	}
	return b, true
}

// Audit coverage values reported by read_audit_config ("audit_config: <v>").
const (
	AuditConfigCovered = "covered"
	AuditConfigPartial = "partial"
	AuditConfigNone    = "none"
)

// AuditConfig returns the audit coverage summary of a read_audit_config
// result: covered, partial or none. Any other value is reported as absent.
func (n Notes) AuditConfig() (string, bool) {
	switch v := n.kv["audit_config"]; v {
	case AuditConfigCovered, AuditConfigPartial, AuditConfigNone:
		return v, true
	}
	return "", false
}
