package dbcorrelate

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/detectverify"
)

// AlertRefs reduces matched alerts to what a report keeps: alert id, time,
// rule name, host, and one redacted excerpt around the marker (at most
// dbsim.MaxAlertExcerptBytes). The raw alert document is never returned: it can
// carry the audited SQL text and event.original. At most dbsim.MaxAlertRefs
// alerts are kept. Alert data is untrusted: unparsable JSON yields a ref
// without host or excerpt rather than an error.
func AlertRefs(alerts []detectverify.MatchedAlert, marker string) []dbsim.AlertRef {
	var out []dbsim.AlertRef
	for i, a := range alerts {
		if i >= dbsim.MaxAlertRefs {
			break
		}
		ref := dbsim.AlertRef{ID: a.AlertID, Time: a.Timestamp, Rule: a.RuleName}
		ref.Host = alertHost(a.RawJSON)
		ref.Excerpt = markerExcerpt(alertTexts(a.RawJSON), marker)
		// ToRecord/BuildReport redact again on storage; do it here too so the
		// Outcome itself never holds unredacted alert text.
		ref.ID = dbsim.Redact(ref.ID)
		ref.Rule = dbsim.Redact(ref.Rule)
		ref.Host = dbsim.Redact(ref.Host)
		out = append(out, ref)
	}
	return out
}

func alertHost(raw json.RawMessage) string {
	var doc struct {
		Source map[string]any `json:"source"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Source == nil {
		return ""
	}
	if s, ok := doc.Source["host.name"].(string); ok {
		return s
	}
	if h, ok := doc.Source["host"].(map[string]any); ok {
		if s, ok := h["name"].(string); ok {
			return s
		}
	}
	return ""
}

// markerExcerpt returns a redacted excerpt of at most MaxAlertExcerptBytes
// centred on the first occurrence of marker in texts, or "" if it is absent.
func markerExcerpt(texts []string, marker string) string {
	if marker == "" {
		return ""
	}
	for _, t := range texts {
		i := strings.Index(t, marker)
		if i < 0 {
			continue
		}
		// Redact a bounded SUPERSET first, then cut: a cut taken before
		// redaction can land inside "password=..." and leave the value.
		const margin = 2 * dbsim.MaxAlertExcerptBytes
		lo, hi := i-margin, i+len(marker)+margin
		if lo < 0 {
			lo = 0
		}
		if hi > len(t) {
			hi = len(t)
		}
		for lo > 0 && lo < len(t) && !utf8.RuneStart(t[lo]) {
			lo++
		}
		for hi < len(t) && !utf8.RuneStart(t[hi]) {
			hi--
		}
		red := dbsim.Redact(t[lo:hi])
		j := strings.Index(red, marker)
		if j < 0 {
			j = 0 // the marker itself was redacted away; keep the head
		}
		start := j - dbsim.MaxAlertExcerptBytes/4
		if start < 0 {
			start = 0
		}
		for start > 0 && start < len(red) && !utf8.RuneStart(red[start]) {
			start++
		}
		end := start + dbsim.MaxAlertExcerptBytes
		if end > len(red) {
			end = len(red)
		}
		for end < len(red) && !utf8.RuneStart(red[end]) {
			end--
		}
		return red[start:end]
	}
	return ""
}
