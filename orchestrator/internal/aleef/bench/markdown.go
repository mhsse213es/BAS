package bench

import (
	"fmt"
	"sort"
	"strings"
)

const limitations = `- Lab only: every run targeted a synthetic bank API on a loopback listener under a lab engagement. No production system and no real bank was touched.
- The target is a synthetic bank with seeded defects; results show the generator can find those defects, not that it finds flaws in a real bank.
- 6 of 8 is a prototype acceptance threshold, not proof of broad discovery capability.
- No real-bank readiness is claimed. A design-partner UAT run is required before any such statement.`

func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func writeCoverage(b *strings.Builder, cov map[string]int, reasons map[string]string) {
	ops := make([]string, 0, len(cov))
	for op := range cov {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	b.WriteString("| Operation | Tests generated |\n|---|---|\n")
	for _, op := range ops {
		if cov[op] == 0 {
			why := ""
			if r := reasons[op]; r != "" {
				why = ": " + r
			}
			fmt.Fprintf(b, "| %s | 0 (NO TESTS%s) |\n", cell(op), cell(why))
		} else {
			fmt.Fprintf(b, "| %s | %d |\n", cell(op), cov[op])
		}
	}
}

func writeDropped(b *strings.Builder, label string, dropped map[string]int) {
	if len(dropped) == 0 {
		return
	}
	types := make([]string, 0, len(dropped))
	for t := range dropped {
		types = append(types, t)
	}
	sort.Strings(types)
	fmt.Fprintf(b, "\nTests dropped for a missing fixture object (%s):\n\n", label)
	for _, t := range types {
		fmt.Fprintf(b, "- no fixture object of resource type %s: %d\n", cell(t), dropped[t])
	}
}

func writeRefs(b *strings.Builder, refs []FindingRef, none string) {
	if len(refs) == 0 {
		b.WriteString(none + "\n")
		return
	}
	b.WriteString("| Finding | Test | Property | Operation |\n|---|---|---|---|\n")
	for _, r := range refs {
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", cell(r.FindingID), cell(r.TestID), cell(r.Property), cell(r.Operation))
	}
}

func writeSafety(b *strings.Builder, checks map[string]bool, notAssessed []string) {
	names := make([]string, 0, len(checks))
	for k := range checks {
		names = append(names, k)
	}
	sort.Strings(names)
	b.WriteString("| Check | Result |\n|---|---|\n")
	for _, k := range names {
		res := "PASS"
		if !checks[k] {
			res = "FAIL"
		}
		fmt.Fprintf(b, "| %s | %s |\n", cell(k), res)
	}
	for _, n := range notAssessed {
		fmt.Fprintf(b, "| %s | not assessed by harness (owner assesses from the bank's own logs) |\n", cell(n))
	}
}

// Markdown renders the report for pasting into the QA log.
func (r Report) Markdown() string {
	var b strings.Builder
	verdict := r.Headline()
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- Milestone 1 evaluation: **%s**\n", verdict)
	fmt.Fprintf(&b, "- Flaws detected: %d of %d (required %d), recall %.2f\n", r.Verified, r.Labels, r.Required, r.Recall)
	fmt.Fprintf(&b, "- Verified findings on the fixed build: %d (must be 0)\n", r.FixedBuildVerified)
	fmt.Fprintf(&b, "- Vulnerable build: %d tests generated, %d run\n", r.TestsGenerated, r.TestsRun)
	fmt.Fprintf(&b, "- Fixed build: %d tests generated, %d run\n", r.FixedTestsGenerated, r.FixedTestsRun)
	for _, build := range []string{BuildFixed, BuildVulnerable} {
		if h := r.Halted[build]; h != "" {
			fmt.Fprintf(&b, "- Campaign halted on the %s build: %s\n", build, h)
		}
	}
	b.WriteString("\nCriteria:\n\n")
	for _, s := range r.PassReasons {
		fmt.Fprintf(&b, "- %s\n", s)
	}

	b.WriteString("\n## Per flaw\n\n")
	b.WriteString("| Flaw | Operation | Detected | Reason | Findings | Property | Test | Controls | Regression | Reproductions | Tests on operation |\n|---|---|---|---|---|---|---|---|---|---|---|\n")
	for _, f := range r.PerFlaw {
		reason := f.Reason
		if f.Detail != "" {
			reason += " (" + f.Detail + ")"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %d | %d |\n", cell(f.ID), cell(f.Operation), yn(f.Verified), cell(reason),
			cell(strings.Join(f.FindingIDs, ", ")), cell(strings.Join(f.Properties, ", ")), cell(strings.Join(f.TestIDs, ", ")), yn(f.Controls), yn(f.Regression), f.Reproductions, f.TestsOnOperation)
	}

	b.WriteString("\n## Coverage per operation (vulnerable build)\n\n")
	writeCoverage(&b, r.CoveragePerOperation, r.SkipReasons)
	writeDropped(&b, "vulnerable build", r.NoFixtureDropped)
	b.WriteString("\n### Coverage per operation (fixed build)\n\n")
	writeCoverage(&b, r.FixedCoveragePerOperation, r.FixedSkipReasons)
	writeDropped(&b, "fixed build", r.FixedNoFixtureDropped)

	b.WriteString("\n## Safety checks\n\n")
	writeSafety(&b, r.SafetyChecks, r.SafetyNotAssessed)

	b.WriteString("\n## Unlabelled verified findings\n\n")
	writeRefs(&b, r.Unlabelled, "None.")
	if len(r.Unlabelled) > 0 {
		b.WriteString("\nThese match no label. They are not scored as successes and need human review.\n")
	}

	b.WriteString("\n## Fixed-build findings\n\n")
	writeRefs(&b, r.FixedBuildFindings, "No verified findings on the fixed build.")
	if len(r.FixedBuildCandidates) > 0 {
		b.WriteString("\nUnverified candidates on the fixed build (possible false positives, investigate):\n\n")
		writeRefs(&b, r.FixedBuildCandidates, "")
	}

	b.WriteString("\n## Limitations\n\n" + limitations + "\n")
	return b.String()
}

// FixedOnlyMarkdown renders a fixed-build rehearsal (no labels involved).
func FixedOnlyMarkdown(o RunOutcome) string {
	var b strings.Builder
	b.WriteString("## Fixed-build rehearsal\n\n")
	fmt.Fprintf(&b, "- Tests generated: %d, run: %d\n", o.TestsGenerated, o.TestsRun)
	fmt.Fprintf(&b, "- Verified findings: %d (must be 0)\n", len(o.Findings))
	fmt.Fprintf(&b, "- Unverified candidates: %d\n", len(o.Candidates))
	if len(o.StateCounts) > 0 {
		states := make([]string, 0, len(o.StateCounts))
		for s := range o.StateCounts {
			states = append(states, s)
		}
		sort.Strings(states)
		var parts []string
		for _, s := range states {
			parts = append(parts, fmt.Sprintf("%s %d", s, o.StateCounts[s]))
		}
		fmt.Fprintf(&b, "- End states: %s\n", strings.Join(parts, ", "))
	}
	if o.Halted != "" {
		fmt.Fprintf(&b, "- Halted: %s\n", o.Halted)
	}
	b.WriteString("\n### Coverage per operation\n\n")
	writeCoverage(&b, o.CoveragePerOperation, o.SkipReasons)
	writeDropped(&b, "this build", o.NoFixtureDropped)
	if len(o.NotClean) > 0 {
		b.WriteString("\n### Tests that did not end clean\n\n| Test | Property | Operation | State | Reason |\n|---|---|---|---|---|\n")
		for _, n := range o.NotClean {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", cell(n.TestID), cell(n.Property), cell(n.Operation), cell(n.State), cell(n.Reason))
		}
	}
	b.WriteString("\n### Verified findings\n\n")
	writeRefs(&b, refsOf(o.Findings), "None.")
	b.WriteString("\n### Candidates\n\n")
	writeRefs(&b, refsOf(o.Candidates), "None.")
	b.WriteString("\n### Safety checks\n\n")
	writeSafety(&b, o.SafetyChecks, o.SafetyNotAssessed)
	b.WriteString("\n### Limitations\n\n" + limitations + "\n")
	return b.String()
}

func refsOf(fs []Finding) []FindingRef {
	var out []FindingRef
	for _, f := range fs {
		out = append(out, ref(f))
	}
	return out
}
