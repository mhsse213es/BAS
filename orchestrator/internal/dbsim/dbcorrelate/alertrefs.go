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
		const half = dbsim.MaxAlertExcerptBytes / 2
		lo, hi := i-half/2, i+len(marker)+half/2
		if lo < 0 {
			lo = 0
		}
		if hi > len(t) {
			hi = len(t)
		}
		for lo < len(t) && lo > 0 && !utf8.RuneStart(t[lo]) {
			lo++
		}
		for hi < len(t) && !utf8.RuneStart(t[hi]) {
			hi--
		}
		ex := dbsim.Redact(t[lo:hi])
		if len(ex) > dbsim.MaxAlertExcerptBytes {
			cut := dbsim.MaxAlertExcerptBytes
			for cut > 0 && !utf8.RuneStart(ex[cut]) {
				cut--
			}
			ex = ex[:cut]
		}
		return ex
	}
	return ""
}
