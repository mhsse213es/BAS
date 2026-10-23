package dbcorrelate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

// Package dbcorrelate lives apart from internal/dbsim on purpose (ruling
// R-AG): detectverify imports internal/verification, whose tests reach
// internal/db and therefore internal/dbsim. dbsim must never import
// detectverify or this package.

// Match is the correlator's confidence grade. report.go (package dbsim) names
// are canonical; these are thin aliases only.
type Match = dbsim.MatchGrade

const (
	MatchExact     = dbsim.MatchExactMarker
	MatchStrong    = dbsim.MatchStrongContextual
	MatchAmbiguous = dbsim.MatchAmbiguous
	MatchNone      = dbsim.MatchNone
)

// ResponseNotAssessedNote is the limitation the correlator always records:
// it proves telemetry detection only.
const ResponseNotAssessedNote = "Response was not assessed: the correlator proves telemetry detection only, not alert triage, case creation or remediation."

// MaxTrustedSkew is the clock-skew allowance above which latency and the
// delayed/on-time boundary are no longer trustworthy (R1, R7). Normal NTP-
// synchronised hosts are well inside it.
const MaxTrustedSkew = 30 * time.Second

// CorrelationInput describes one probe whose detection telemetry is checked.
type CorrelationInput struct {
	Marker, Principal, RunID string
	DBHost, DBIP, AgentIP    string
	ProbeAt                  time.Time
	Window, SkewAllowance    time.Duration
}

// Result is the correlator's honest finding. It only ever proves telemetry
// detection; Response is always NotTested.
type Result struct {
	Match       Match
	Telemetry   dlpreport.TelemetryOutcome
	Response    dlpreport.ResponseOutcome
	Latency     time.Duration
	Alerts      []detectverify.MatchedAlert
	Limitations string
	// TimingConfidence is "normal" or "low" (skew above MaxTrustedSkew).
	TimingConfidence string
}

// ToCorrelation converts the result into the report layer's input.
func (r Result) ToCorrelation() dbsim.Correlation {
	return dbsim.Correlation{
		Evaluated: true, Telemetry: r.Telemetry, Response: r.Response,
		Latency: r.Latency, Match: r.Match, Alerts: len(r.Alerts), Limitations: r.Limitations,
	}
}

const markerCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"

var reAnyMarker = regexp.MustCompile(`bas-dbsim:[A-Za-z0-9._:-]+`)

func inCharset(b byte) bool { return strings.IndexByte(markerCharset, b) >= 0 }

// markerCommentPrefix is what the agent writes immediately before the marker:
// the statement's leading comment is "/* dbsim:<marker> */"
// (agent/dbprobe.MarkerComment), so in a real alert the marker is preceded by
// "dbsim:", whose ':' is itself a token character.
const markerCommentPrefix = "dbsim:"

// afterMarkerCommentPrefix reports whether s[:start] ends with the comment
// prefix as its own word (not glued to a longer identifier).
func afterMarkerCommentPrefix(s string, start int) bool {
	p := start - len(markerCommentPrefix)
	if p < 0 || s[p:start] != markerCommentPrefix {
		return false
	}
	return p == 0 || !inCharset(s[p-1])
}

// containsToken reports whether tok occurs in s as a whole token: not preceded
// by a token character, and not followed by one (a single trailing sentence
// punctuation mark . : - _ is tolerated when it ends the token). Case
// sensitive.
func containsToken(s, tok string) bool {
	if tok == "" {
		return false
	}
	for from := 0; from <= len(s)-len(tok); {
		i := strings.Index(s[from:], tok)
		if i < 0 {
			return false
		}
		start := from + i
		end := start + len(tok)
		from = start + 1
		if start > 0 && inCharset(s[start-1]) && !afterMarkerCommentPrefix(s, start) {
			continue
		}
		if end < len(s) && inCharset(s[end]) {
			// tolerate trailing punctuation only when it terminates the token
			if strings.IndexByte("._:-", s[end]) >= 0 && (end+1 >= len(s) || !inCharset(s[end+1])) {
				return true
			}
			continue
		}
		return true
	}
	return false
}

// hasForeignMarker reports whether raw carries a bas-dbsim marker token other
// than ours.
func hasForeignMarker(texts []string, ours string) bool {
	for _, raw := range texts {
		for _, t := range reAnyMarker.FindAllString(raw, -1) {
			t = strings.TrimRight(t, "._:-")
			if t != strings.TrimRight(ours, "._:-") {
				return true
			}
		}
	}
	return false
}

// anyToken reports whether tok occurs as a whole token in any of texts.
func anyToken(texts []string, tok string) bool {
	for _, s := range texts {
		if containsToken(s, tok) {
			return true
		}
	}
	return false
}

// alertTexts returns the DECODED string values of the alert JSON (so a marker
// after a JSON "\n" escape is judged on the real newline, not on the letter n).
// Only values are searched, never object keys: a marker is statement content,
// and a key can be chosen by whoever shapes the document. If the raw data is
// not valid JSON it is searched as plain text.
func alertTexts(raw json.RawMessage) []string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{string(raw)}
	}
	var out []string
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			out = append(out, t)
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

func rawTruncated(raw json.RawMessage) bool {
	var f struct {
		T bool `json:"sourceTruncated"`
	}
	_ = json.Unmarshal(raw, &f)
	return f.T
}

type alertClass int

const (
	classOurs alertClass = iota
	classStrong
	classForeign
	classUnattributed
)

// classify decides what one alert proves for THIS run.
func classify(a detectverify.MatchedAlert, in CorrelationInput) alertClass {
	texts := alertTexts(a.RawJSON)
	if anyToken(texts, in.Marker) {
		return classOurs
	}
	if rawTruncated(a.RawJSON) {
		// The marker may lie beyond the cut: cannot attribute either way.
		return classUnattributed
	}
	if hasForeignMarker(texts, in.Marker) {
		return classForeign
	}
	if in.Principal != "" && in.RunID != "" && anyToken(texts, in.Principal) && anyToken(texts, in.RunID) {
		return classStrong
	}
	return classUnattributed
}

type lookup struct {
	name string
	req  detectverify.VerifyRequest
}

// Correlate checks, with exact-marker evidence, whether the SIEM raised an
// alert for this probe. It never uses VerifyResult.Verdict: the Elastic
// connector reports Detected for ANY alert on the host in the window.
func Correlate(ctx context.Context, c detectverify.Connector, in CorrelationInput) (Result, error) {
	res := Result{Match: MatchNone, Telemetry: dlpreport.TelemetryUnverifiable, Response: dlpreport.ResponseNotTested, TimingConfidence: "normal"}
	var lims []string
	lims = append(lims, ResponseNotAssessedNote)
	finish := func(err error) (Result, error) {
		res.Limitations = strings.Join(lims, " ")
		return res, err
	}
	if c == nil {
		return finish(errors.New("dbsim: correlate: no detection connector"))
	}
	if strings.TrimSpace(in.Marker) == "" {
		return finish(errors.New("dbsim: correlate: empty marker"))
	}
	if in.ProbeAt.IsZero() || in.Window <= 0 {
		return finish(errors.New("dbsim: correlate: probe time and a positive window are required"))
	}
	skew := in.SkewAllowance
	if skew < 0 {
		skew = 0
	}
	if skew > MaxTrustedSkew {
		res.TimingConfidence = "low"
		lims = append(lims, fmt.Sprintf("Clock skew allowance %s exceeds the trusted %s: alert latency and the on-time/delayed boundary are low confidence.", skew, MaxTrustedSkew))
	}
	onTimeEnd := in.ProbeAt.Add(in.Window + skew)
	start := in.ProbeAt.Add(-skew)
	// Look beyond the window by one more window so a late alert is seen and
	// reported Delayed instead of being invisible (and wrongly Absent).
	end := onTimeEnd.Add(in.Window)

	dbHost, dbIP, agentIP := strings.TrimSpace(in.DBHost), strings.TrimSpace(in.DBIP), strings.TrimSpace(in.AgentIP)
	var lookups []lookup
	base := detectverify.VerifyRequest{
		RunID: in.RunID, ExpectationID: "dbsim", StepExecutedAt: in.ProbeAt,
		WindowStart: start, WindowEnd: end,
	}
	if dbHost != "" || dbIP != "" {
		r := base
		r.HostName, r.HostIP = dbHost, dbIP
		lookups = append(lookups, lookup{"database host", r})
	}
	sameHost := agentIP != "" && (agentIP == dbIP || agentIP == dbHost)
	if agentIP != "" && !sameHost {
		r := base
		r.HostIP = agentIP
		lookups = append(lookups, lookup{"agent host", r})
	}
	if sameHost {
		lims = append(lims, "The agent and the database run on the same host: host-based correlation cannot separate agent activity from database activity; attribution rests on the marker alone.")
	}
	if len(lookups) == 0 {
		lims = append(lims, "No host identity (database host/IP or agent IP) was supplied, so no alert query could be scoped.")
		return finish(errors.New("dbsim: correlate: no host identity to query"))
	}

	seen := map[string]bool{}
	var union []detectverify.MatchedAlert
	var errs []error
	for _, l := range lookups {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		vr, err := c.Verify(ctx, l.req)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s alert lookup: %w", l.name, err))
			continue
		}
		for _, a := range vr.MatchedAlerts {
			key := a.AlertID
			if key == "" {
				key = string(a.RawJSON)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			union = append(union, a)
		}
	}
	sort.SliceStable(union, func(i, j int) bool { return union[i].Timestamp.Before(union[j].Timestamp) })

	var ours, strong, unattributed []detectverify.MatchedAlert
	var foreign int
	for _, a := range union {
		if !a.Timestamp.IsZero() && (a.Timestamp.Before(start) || a.Timestamp.After(end)) {
			continue // outside the queried range: not evidence for this probe
		}
		switch classify(a, in) {
		case classOurs:
			ours = append(ours, a)
		case classStrong:
			strong = append(strong, a)
		case classForeign:
			foreign++
		default:
			unattributed = append(unattributed, a)
		}
	}
	if foreign > 0 {
		lims = append(lims, fmt.Sprintf("%d alert(s) carried another run's marker and were not credited to this run.", foreign))
	}
	if len(errs) > 0 {
		lims = append(lims, "Some alert lookups failed; the absence of an alert cannot be concluded.")
	}

	positive := func(alerts []detectverify.MatchedAlert, m Match) {
		res.Match = m
		res.Alerts = alerts
		onTime := false
		var first time.Time
		for _, a := range alerts {
			if first.IsZero() || (!a.Timestamp.IsZero() && a.Timestamp.Before(first)) {
				first = a.Timestamp
			}
			if a.Timestamp.IsZero() || !a.Timestamp.After(onTimeEnd) {
				onTime = true
			}
		}
		if !first.IsZero() {
			if res.Latency = first.Sub(in.ProbeAt); res.Latency < 0 {
				res.Latency = 0
			}
		}
		if onTime {
			res.Telemetry = dlpreport.TelemetryPresent
		} else {
			res.Telemetry = dlpreport.TelemetryDelayed
			lims = append(lims, fmt.Sprintf("The alert arrived after the %s detection window.", in.Window))
		}
		if m == MatchStrong {
			lims = append(lims, "No exact marker was found in the alert; attribution rests on principal, run id, host and time window (strong contextual).")
		}
	}

	switch {
	case len(ours) > 0:
		positive(ours, MatchExact)
		if len(errs) > 0 {
			errs = nil // a positive observation stands despite a failed lookup
		}
	case len(strong) > 0:
		positive(strong, MatchStrong)
		errs = nil
	case len(unattributed) > 0:
		res.Match, res.Telemetry, res.Alerts = MatchAmbiguous, dlpreport.TelemetryUnverifiable, unattributed
		lims = append(lims, fmt.Sprintf("%d alert(s) exist on the host in the window but none can be attributed to this probe (no marker in the available alert data, or the data was truncated); a wide alert may be a different event.", len(unattributed)))
	case len(errs) > 0:
		// stays None / Unverifiable
	default:
		res.Match, res.Telemetry = MatchNone, dlpreport.TelemetryAbsent
		lims = append(lims, "No alert for this probe was found in the detection window on a healthy source.")
	}
	if len(errs) > 0 {
		return finish(errors.Join(errs...))
	}
	return finish(nil)
}
