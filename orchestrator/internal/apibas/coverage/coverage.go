// Package coverage counts API BAS coverage without letting unsupported protocols inflate it.
//
// Five separate measures are reported. They are not PASS divided by total, because that hides
// what was excluded:
//
//   - Catalogued: scenarios defined in the catalog. This is the denominator of every ratio.
//   - Implemented: scenarios whose protocol has an executable adapter.
//   - Evaluated: scenarios with at least one valid security verdict (PASS or FAIL with an
//     exploitability value; never SKIPPED or ERROR).
//   - Validated: scenarios with a valid verdict in both builds, where the vulnerable build FAILs
//     as exploited and the fixed build PASSes with control enforced.
//   - Excluded: catalogued scenarios that do not count toward evaluated coverage, split into
//     Unsupported (no adapter), Errored (execution or environment failure), and Unevaluated
//     (implemented, but no valid verdict: skipped, or not run).
//
// An unsupported scenario is in Catalogued, and never in Evaluated or Validated.
package coverage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/grade"
)

// Verdicts are the outcomes of one scenario in each build. A nil outcome means the scenario was
// not run in that build.
type Verdicts struct {
	Vulnerable *grade.Outcome
	Fixed      *grade.Outcome
}

// Status is the coverage class of one catalogued scenario.
type Status string

const (
	Validated   Status = "validated"
	Evaluated   Status = "evaluated"
	Unsupported Status = "unsupported"
	Errored     Status = "error"
	Unevaluated Status = "unevaluated"
)

// Entry is one catalogued scenario and its class.
type Entry struct {
	ID       string
	Protocol string
	Status   Status
	Reason   string
}

// Report is the coverage result. Every ratio's denominator is Catalogued.
type Report struct {
	Catalogued  int
	Implemented int
	Evaluated   int // includes Validated
	Validated   int
	Unsupported int
	Errored     int
	Unevaluated int
	Entries     []Entry
}

// valid reports whether an outcome is a valid security verdict.
func valid(o *grade.Outcome) bool {
	if o == nil {
		return false
	}
	if o.Result != grade.PASS && o.Result != grade.FAIL {
		return false
	}
	return o.Exploitability == grade.Exploited || o.Exploitability == grade.NotExploited
}

// validated reports whether a build pair proves the scenario: the vulnerable build FAILs as
// exploited, and the fixed build PASSes with control enforced.
func validated(v Verdicts) bool {
	if v.Vulnerable == nil || v.Fixed == nil {
		return false
	}
	vuln := v.Vulnerable
	fixed := v.Fixed
	return vuln.Result == grade.FAIL && vuln.Exploitability == grade.Exploited &&
		fixed.Result == grade.PASS && fixed.Control == grade.Enforced
}

// Build classifies every catalogued scenario. supported decides which protocols have an
// adapter, so a test can model a future adapter. Results may omit scenarios, which are then not
// run.
func Build(catalog []contract.Scenario, supported func(protocol string) bool, results map[string]Verdicts) Report {
	var r Report
	r.Catalogued = len(catalog)
	for _, s := range catalog {
		e := Entry{ID: s.ID, Protocol: protocolOf(s)}
		if !supported(s.Protocol) {
			e.Status = Unsupported
			e.Reason = grade.ReasonUnsupportedProtocol
			r.Unsupported++
			r.Entries = append(r.Entries, e)
			continue
		}
		r.Implemented++
		v := results[s.ID]
		switch {
		case validated(v):
			e.Status = Validated
			r.Validated++
			r.Evaluated++
		case valid(v.Vulnerable) || valid(v.Fixed):
			e.Status = Evaluated
			r.Evaluated++
		case isError(v.Vulnerable) || isError(v.Fixed):
			e.Status = Errored
			e.Reason = errorReason(v)
			r.Errored++
		default:
			e.Status = Unevaluated
			e.Reason = unevaluatedReason(v)
			r.Unevaluated++
		}
		r.Entries = append(r.Entries, e)
	}
	return r
}

func protocolOf(s contract.Scenario) string {
	if s.Protocol == "" {
		return "http"
	}
	return s.Protocol
}

func isError(o *grade.Outcome) bool {
	return o != nil && o.Result == grade.ERROR
}

func errorReason(v Verdicts) string {
	for _, o := range []*grade.Outcome{v.Vulnerable, v.Fixed} {
		if isError(o) {
			return o.Reason
		}
	}
	return ""
}

func unevaluatedReason(v Verdicts) string {
	for _, o := range []*grade.Outcome{v.Vulnerable, v.Fixed} {
		if o != nil {
			return o.Reason
		}
	}
	return "not run"
}

// Consistent reports whether the classes add up to the catalog size, so no scenario is lost or
// counted twice.
func (r Report) Consistent() bool {
	return r.Evaluated+r.Unsupported+r.Errored+r.Unevaluated == r.Catalogued &&
		r.Validated <= r.Evaluated && r.Implemented+r.Unsupported == r.Catalogued
}

// Format renders the report with numerators, denominators and exclusions. Every ratio is shown
// as numerator/denominator, so none of them can be read without its exclusions.
func Format(r Report) string {
	var b strings.Builder
	pct := func(n, d int) string {
		if d == 0 {
			return "n/a"
		}
		return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(d))
	}
	fmt.Fprintf(&b, "Catalogued:   %d\n", r.Catalogued)
	fmt.Fprintf(&b, "Implemented:  %d/%d (%s)\n", r.Implemented, r.Catalogued, pct(r.Implemented, r.Catalogued))
	fmt.Fprintf(&b, "Evaluated:    %d/%d (%s)  <- primary coverage; numerator excludes every exclusion below\n",
		r.Evaluated, r.Catalogued, pct(r.Evaluated, r.Catalogued))
	fmt.Fprintf(&b, "Validated:    %d/%d (%s)  <- vulnerable FAILs as exploited and fixed PASSes enforced\n",
		r.Validated, r.Catalogued, pct(r.Validated, r.Catalogued))
	fmt.Fprintf(&b, "Exclusions (denominator still includes them):\n")
	fmt.Fprintf(&b, "  unsupported (no adapter):       %d\n", r.Unsupported)
	fmt.Fprintf(&b, "  errored (execution/environment): %d\n", r.Errored)
	fmt.Fprintf(&b, "  unevaluated (implemented, no valid verdict): %d\n", r.Unevaluated)
	if !r.Consistent() {
		fmt.Fprintf(&b, "WARNING: classes do not sum to the catalog size\n")
	}
	b.WriteString("Scenarios not validated (evaluated-only, or excluded from evaluation):\n")
	rows := make([]Entry, 0)
	for _, e := range r.Entries {
		if e.Status == Validated {
			continue
		}
		rows = append(rows, e)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, e := range rows {
		fmt.Fprintf(&b, "  %-22s %-12s %-10s %s\n", e.ID, e.Protocol, e.Status, e.Reason)
	}
	return b.String()
}
