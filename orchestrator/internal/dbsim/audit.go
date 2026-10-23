package dbsim

import (
	"strings"
	"unicode/utf8"

	"github.com/audspect/bas/internal/dlpreport"
)

// Bounds applied to agent-supplied audit evidence. The agent already caps and
// redacts it, but the orchestrator treats everything an agent returns as
// untrusted data: it is re-bounded, re-redacted, matched against the run's own
// marker and never interpreted or executed.
const (
	MaxStoredAuditEvents    = 10
	MaxAuditStatementBytes  = 512
	maxAuditPrincipalBytes  = 128
	maxAuditSourceBytes     = 64
	maxMarkerScanBytes      = 4096
	markerTokenChars        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
	auditUnsupportedMessage = "Audit evidence was not tested: the target exposes no queryable audit source (audit status unsupported); this is neither a pass nor a failure of the control."
)

func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// afterCommentPrefix: the agent writes "/* dbsim:<marker> */", so the marker is
// preceded by the word "dbsim:" whose ':' is itself a token character. Same
// rule as dbcorrelate (which dbsim must not import, R-AG).
func afterCommentPrefix(s string, start int) bool {
	const prefix = "dbsim:"
	p := start - len(prefix)
	if p < 0 || s[p:start] != prefix {
		return false
	}
	return p == 0 || strings.IndexByte(markerTokenChars, s[p-1]) < 0
}

// containsMarkerToken reports whether marker occurs in s as a whole token (a
// longer identifier that merely starts with it, e.g. abc1234 for abc123, does
// not count). Case sensitive.
func containsMarkerToken(s, marker string) bool {
	if marker == "" {
		return false
	}
	s = cutUTF8(s, maxMarkerScanBytes)
	for from := 0; from <= len(s)-len(marker); {
		i := strings.Index(s[from:], marker)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(marker)
		from = start + 1
		if start > 0 && strings.IndexByte(markerTokenChars, s[start-1]) >= 0 && !afterCommentPrefix(s, start) {
			continue
		}
		if end < len(s) && strings.IndexByte(markerTokenChars, s[end]) >= 0 {
			// one trailing sentence punctuation mark ends the token
			if strings.IndexByte("._:-", s[end]) >= 0 && (end+1 >= len(s) || strings.IndexByte(markerTokenChars, s[end+1]) < 0) {
				return true
			}
			continue
		}
		return true
	}
	return false
}

// auditHasMarkerEvidence reports whether at least one reported audit event
// carries this run's marker. An agent that claims "found" without such an
// event is not believed.
func auditHasMarkerEvidence(o Outcome) bool {
	for _, e := range o.Probe.AuditEvents {
		if containsMarkerToken(e.Statement, o.Marker) {
			return true
		}
	}
	return false
}

// SanitizeAuditEvents returns at most MaxStoredAuditEvents events with every
// free-text field redacted and bounded, and the number of events not kept.
func SanitizeAuditEvents(events []DBProbeAuditEvent) (kept []DBProbeAuditEvent, dropped int) {
	for i, e := range events {
		if i >= MaxStoredAuditEvents {
			dropped = len(events) - MaxStoredAuditEvents
			break
		}
		kept = append(kept, DBProbeAuditEvent{
			Time:      e.Time,
			Principal: cutUTF8(redact(e.Principal), maxAuditPrincipalBytes),
			Statement: cutUTF8(redact(cutUTF8(e.Statement, 4*MaxAuditStatementBytes)), MaxAuditStatementBytes),
			Source:    cutUTF8(redact(e.Source), maxAuditSourceBytes),
		})
	}
	return kept, dropped
}

// auditGrade grades the audit-coverage dimension and returns the limitation
// lines that explain it. It returns DimNotExpected when the scenario expects
// neither the audit configuration nor audit evidence.
//
//	ExpectAuditConfig (read_audit_config): covered pass, none fail, partial or
//	  unreadable unverifiable.
//	ExpectAudit (marker readback): found WITH a marker-bearing event pass;
//	  unsupported skipped (never a pass); absent fail, because the agent only
//	  reports absent when the source was healthy and had caught up; incomplete,
//	  error, empty, unknown, or found without marker evidence unverifiable.
//
// When both are expected the worst grade wins (fail, unverifiable, skipped,
// pass).
func auditGrade(s ScenarioMeta, o Outcome) (DimensionGrade, []string) {
	if !s.ExpectAudit && !s.ExpectAuditConfig {
		return DimNotExpected, nil
	}
	var grades []DimensionGrade
	var lims []string
	if s.ExpectAuditConfig {
		cov, ok := ParseNotes(o.Probe.Notes).AuditConfig()
		switch {
		case !ok:
			grades = append(grades, DimUnverifiable)
			lims = append(lims, "Audit configuration coverage was not reported by the probe (no audit_config summary): audit coverage is unverifiable.")
		case cov == AuditConfigCovered:
			grades = append(grades, DimPass)
		case cov == AuditConfigNone:
			grades = append(grades, DimFail)
			lims = append(lims, "Audit configuration summary is none: the target logs no statements and exposes no queryable audit source.")
		default:
			grades = append(grades, DimUnverifiable)
			lims = append(lims, "Audit configuration summary is partial: some logging exists but statement reads are not both logged and queryable by the test account, so coverage cannot be confirmed.")
		}
	}
	if s.ExpectAudit {
		switch o.Probe.AuditStatus {
		case AuditFound:
			if auditHasMarkerEvidence(o) {
				grades = append(grades, DimPass)
			} else {
				grades = append(grades, DimUnverifiable)
				lims = append(lims, "The agent reported audit status found but returned no audit event carrying this run's marker: audit evidence is unverifiable.")
			}
		case AuditUnsupported:
			grades = append(grades, DimSkipped)
			lims = append(lims, auditUnsupportedMessage)
		case AuditAbsent:
			grades = append(grades, DimFail)
			lims = append(lims, "No audit event for this probe's marker was found although the audit source was healthy and caught up; the marker comment may not survive the audit path, so check the source before concluding the control is missing.")
		case AuditIncomplete:
			grades = append(grades, DimUnverifiable)
			lims = append(lims, "Audit evidence is incomplete (the audit window rotated or was capped, or the source did not catch up): absence of the event proves nothing.")
		case AuditError:
			grades = append(grades, DimUnverifiable)
			lims = append(lims, "Audit collection failed on the agent: audit evidence is unverifiable.")
		default:
			grades = append(grades, DimUnverifiable)
			lims = append(lims, "No usable audit status was reported (older agent or no audit attempt): audit evidence is unverifiable.")
		}
	}
	return worstDimension(grades), lims
}

func worstDimension(gs []DimensionGrade) DimensionGrade {
	rank := func(g DimensionGrade) int {
		switch g {
		case DimFail:
			return 4
		case DimUnverifiable:
			return 3
		case DimSkipped:
			return 2
		case DimPass:
			return 1
		}
		return 0
	}
	worst := DimNotExpected
	for _, g := range gs {
		if rank(g) > rank(worst) {
			worst = g
		}
	}
	return worst
}

// auditTelemetry derives the Record's Telemetry from the audit slice when no
// alert correlation was attempted, and downgrades a Present alert to
// Incomplete when the audit slice cannot back it (spec section 7). ok is false
// when audit evidence does not influence Telemetry.
func auditTelemetry(s ScenarioMeta, o Outcome, alertTel dlpreport.TelemetryOutcome, correlated bool) (dlpreport.TelemetryOutcome, string, bool) {
	var fromAudit dlpreport.TelemetryOutcome
	switch {
	case s.ExpectAudit:
		switch o.Probe.AuditStatus {
		case AuditFound:
			if auditHasMarkerEvidence(o) {
				fromAudit = dlpreport.TelemetryPresent
			} else {
				fromAudit = dlpreport.TelemetryUnverifiable
			}
		case AuditAbsent:
			fromAudit = dlpreport.TelemetryAbsent
		case AuditIncomplete:
			fromAudit = dlpreport.TelemetryIncomplete
		default:
			fromAudit = dlpreport.TelemetryUnverifiable
		}
	case s.ExpectAuditConfig:
		cov, _ := ParseNotes(o.Probe.Notes).AuditConfig()
		switch cov {
		case AuditConfigCovered:
			fromAudit = dlpreport.TelemetryPresent
		case AuditConfigNone:
			fromAudit = dlpreport.TelemetryAbsent
		case AuditConfigPartial:
			fromAudit = dlpreport.TelemetryIncomplete
		default:
			fromAudit = dlpreport.TelemetryUnverifiable
		}
	default:
		return alertTel, "", false
	}
	if !correlated {
		return fromAudit, "Telemetry reflects the target's own audit configuration or audit slice only: no SIEM alert correlation was attempted.", true
	}
	if s.ExpectAudit && o.Probe.AuditStatus == AuditUnsupported {
		// No audit slice exists to back or contradict the alert; the alert
		// stands on its own evidence and the audit dimension is skipped.
		return alertTel, "", false
	}
	if alertTel == dlpreport.TelemetryPresent && fromAudit != dlpreport.TelemetryPresent {
		return dlpreport.TelemetryIncomplete, "A correlated alert exists but the target's audit slice does not back it with a marker event, so telemetry is incomplete.", true
	}
	return alertTel, "", false
}
