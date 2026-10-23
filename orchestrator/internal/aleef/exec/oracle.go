package exec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/runner"
)

// stateEvidence is the state diff the runner acted on: the last two
// snapshots it took (just before the attack, just after it).
type stateEvidence struct {
	known, changed bool
}

const truncatedMarker = "...[truncated]"

func verdict(f Finding, k property.OracleKind, format string, a ...any) Verdict {
	return Verdict{Finding: f, Oracle: k, Reason: fmt.Sprintf(format, a...)}
}

// judge applies the template's oracle to the runner's report. See
// property.OracleKind for the rule each kind implements. Where a rule is
// ambiguous the conservative reading (inconclusive rather than yes) is used.
func (e *Executor) judge(t generate.Test, rep runner.Report, st stateEvidence) Verdict {
	tpl := t.Template
	k := tpl.Oracle
	inc := func(format string, a ...any) Verdict { return verdict(FindingInconclusive, k, format, a...) }

	// A run that did not get as far as the attack proves nothing. The one
	// SKIPPED reason that does not block is "evidence inconclusive": it is the
	// runner saying the final status was neither denied nor a finding, which
	// the oracles below re-examine themselves.
	switch rep.Outcome.Result {
	case grade.ERROR:
		return inc("runner error: %s", rep.Outcome.Reason)
	case grade.SKIPPED:
		if rep.Outcome.Reason != grade.ReasonEvidenceInconclusive {
			return inc("runner skipped: %s", rep.Outcome.Reason)
		}
	}
	if len(rep.Exchanges) < 2 {
		return inc("no attack exchange was recorded")
	}

	steps := t.Scenario.Steps
	lastID := steps[len(steps)-1].ID
	after := rep.Exchanges[1:] // everything after the baseline
	var attack []runner.Exchange
	for _, x := range after {
		if x.StepID == lastID {
			attack = append(attack, x)
		}
	}
	final := after[len(after)-1]
	denied := func(x runner.Exchange) bool { return tpl.Denied(x.Status, []byte(x.Body)) }
	request := requestText(t)

	switch k {
	case property.OracleRunnerGrade:
		return e.judgeRunnerGrade(t, rep, st, attack, final, request, denied)

	case property.OracleStateChange:
		if !st.known {
			return inc("state diff unavailable")
		}
		if st.changed {
			return verdict(FindingYes, k, "the attack changed state")
		}
		if denied(final) {
			return verdict(FindingNo, k, "attack refused (status %d) and state unchanged", final.Status)
		}
		return inc("no state change and status %d is not a refusal", final.Status)

	case property.OracleStateChangeOnReplay:
		if !st.known {
			return inc("state diff unavailable")
		}
		if st.changed {
			return verdict(FindingYes, k, "the replay changed state")
		}
		if denied(final) {
			return verdict(FindingNo, k, "replay refused (status %d) and state unchanged", final.Status)
		}
		if tpl.CleanIsEnforced && final.Status/100 == 2 {
			return verdict(FindingNo, k, "replay accepted with no state change")
		}
		return inc("no state change and status %d is not a refusal", final.Status)

	case property.OracleRepeatAccepted:
		if len(attack) == 0 {
			return inc("the attack step was never sent")
		}
		if hasFault(attack) {
			return inc("server error in an attack response")
		}
		if truncatedSuccess(tpl, attack) {
			return inc("body truncated")
		}
		n := tpl.AcceptedCount(responses(attack))
		if n > tpl.MaxAccepted {
			return verdict(FindingYes, k, "%d attack responses accepted, limit %d", n, tpl.MaxAccepted)
		}
		return verdict(FindingNo, k, "%d attack responses accepted, limit %d", n, tpl.MaxAccepted)

	case property.OracleAcceptedOverLimit:
		if tpl.MaxAccepted <= 0 {
			return inc("template declares no limit")
		}
		if hasFault(after) {
			return inc("server error in an attack response")
		}
		if truncatedSuccess(tpl, after) {
			return inc("body truncated")
		}
		rs := responses(after)
		if tpl.ExceedsLimit(rs) {
			return verdict(FindingYes, k, "%d attack responses accepted, limit %d", tpl.AcceptedCount(rs), tpl.MaxAccepted)
		}
		return verdict(FindingNo, k, "%d attack responses accepted, limit %d", tpl.AcceptedCount(rs), tpl.MaxAccepted)

	case property.OracleForbiddenValues:
		if len(attack) == 0 {
			if denied(final) {
				return verdict(FindingNo, k, "setup step refused (status %d)", final.Status)
			}
			return inc("the attack step was never sent and the setup step was not a refusal")
		}
		hits, echoed, complete := 0, 0, true
		for _, x := range attack {
			h, ec, c := scanForbidden(x.Body, tpl.ForbiddenValues, request)
			hits += h
			echoed += ec
			complete = complete && c
		}
		switch {
		case hits > 0:
			return verdict(FindingYes, k, "forbidden value in the attack response")
		case echoed > 0:
			return inc("value present in request")
		case !complete:
			return inc("response body truncated; forbidden values cannot be ruled out")
		}
		last := attack[len(attack)-1]
		switch {
		case denied(last):
			return verdict(FindingNo, k, "attack refused (status %d)", last.Status)
		case last.Status/100 == 2 && tpl.CleanIsEnforced:
			return verdict(FindingNo, k, "2xx response with no forbidden value")
		}
		return inc("status %d is neither a refusal nor a clean success", last.Status)
	}
	return inc("unknown oracle %q", string(k))
}

func (e *Executor) judgeRunnerGrade(t generate.Test, rep runner.Report, st stateEvidence, attack []runner.Exchange, final runner.Exchange, request string, denied func(runner.Exchange) bool) Verdict {
	tpl := t.Template
	k := tpl.Oracle
	switch rep.Outcome.Result {
	case grade.PASS:
		return verdict(FindingNo, k, "runner: control enforced")
	case grade.SKIPPED:
		// evidence inconclusive: a 2xx soft failure is still a refusal
		if len(attack) > 0 && denied(final) {
			return verdict(FindingNo, k, "attack refused (status %d)", final.Status)
		}
		return verdict(FindingInconclusive, k, "runner: evidence inconclusive (status %d)", final.Status)
	case grade.FAIL:
	default:
		return verdict(FindingInconclusive, k, "runner outcome %s", rep.Outcome.Result)
	}

	// FAIL: find out which signal caused it. The runner reports only the
	// outcome, so the causes are recomputed from the evidence.
	if st.known && st.changed && tpl.RunnerStateValid {
		return verdict(FindingYes, k, "the attack changed state")
	}
	forbidden, echoedForbidden := 0, 0
	for _, x := range attack {
		h, ec, _ := scanForbidden(x.Body, tpl.ForbiddenValues, request)
		forbidden += h
		echoedForbidden += ec
	}
	if forbidden > 0 {
		return verdict(FindingYes, k, "forbidden value in the attack response")
	}
	leaked := 0
	for _, x := range attack {
		leaked += x.Leaked
	}
	if leaked > 0 && tpl.RunnerLeakValid {
		if e.protectedInRequest(t, request) {
			return verdict(FindingInconclusive, k, "value present in request")
		}
		return verdict(FindingYes, k, "protected value in the attack response")
	}
	if echoedForbidden > 0 {
		return verdict(FindingInconclusive, k, "value present in request")
	}
	return verdict(FindingInconclusive, k, "runner failure not attributable to a valid signal")
}

// protectedInRequest reports whether any protected value of the scenario's
// fixture object appears in the attack request.
func (e *Executor) protectedInRequest(t generate.Test, request string) bool {
	obj, ok := e.cfg.Fixture.Object(t.Scenario.Preconditions.Object)
	if !ok {
		return false
	}
	for _, v := range obj.Protected {
		if v != "" && strings.Contains(request, v) {
			return true
		}
	}
	return false
}

func hasFault(xs []runner.Exchange) bool {
	for _, x := range xs {
		if x.Status >= 500 || x.Status == 0 {
			return true
		}
	}
	return false
}

func responses(xs []runner.Exchange) []property.Response {
	out := make([]property.Response, len(xs))
	for i, x := range xs {
		out[i] = property.Response{Status: x.Status, Body: []byte(x.Body)}
	}
	return out
}

// requestText is everything the attack step sends that the application could
// echo back: path, body and header values.
func requestText(t generate.Test) string {
	steps := t.Scenario.Steps
	s := steps[len(steps)-1]
	var b strings.Builder
	b.WriteString(strings.ReplaceAll(s.Path, "{object}", t.Scenario.Preconditions.Object))
	b.WriteString(" ")
	b.WriteString(s.Body)
	for _, v := range s.Headers {
		b.WriteString(" ")
		b.WriteString(v)
	}
	for _, h := range s.ExtraHeaders {
		b.WriteString(" ")
		b.WriteString(h.Value)
	}
	return b.String()
}

// scanForbidden counts forbidden values found at any depth of a response
// body. A value that also appears in the request is not a hit; it is counted
// in echoed when the response contains it. complete is false when the
// recorded body was truncated and so cannot rule a value out.
func scanForbidden(body string, values []string, request string) (hits, echoed int, complete bool) {
	complete = !strings.HasSuffix(body, truncatedMarker)
	if len(values) == 0 {
		return 0, 0, complete
	}
	texts := bodyTexts(body)
	for _, v := range values {
		if v == "" {
			continue
		}
		found := false
		for _, tx := range texts {
			if strings.Contains(tx, v) {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		if strings.Contains(request, v) {
			echoed++
		} else {
			hits++
		}
	}
	return hits, echoed, complete
}

// bodyTexts returns every searchable string of a body: the keys and string or
// number values of a JSON document at any depth, or the whole body.
func bodyTexts(body string) []string {
	if !json.Valid([]byte(body)) {
		return []string{body}
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(body)))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return []string{body}
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				out = append(out, k)
				walk(val)
			}
		case []any:
			for _, val := range x {
				walk(val)
			}
		case string:
			out = append(out, x)
		case json.Number:
			out = append(out, x.String())
		}
	}
	walk(doc)
	return out
}

// truncatedSuccess reports whether a 2xx response that is not refused by
// status has a body the runner truncated. The soft-failure rule needs the
// whole JSON body, so such a response can be neither counted as accepted nor
// as refused.
func truncatedSuccess(tpl property.Template, xs []runner.Exchange) bool {
	if !tpl.SoftFailure {
		return false
	}
	for _, x := range xs {
		if x.Status/100 == 2 && strings.HasSuffix(x.Body, truncatedMarker) && !tpl.Denied(x.Status, nil) {
			return true
		}
	}
	return false
}
