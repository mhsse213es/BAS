package rwefficacy

import (
	"testing"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/db"
)

func row(tech, act, cap string, v controlval.Verdict, sr controlval.SkipReason) db.RWAttemptRow {
	return db.RWAttemptRow{TechniqueID: tech, Action: act, Capability: cap, Verdict: v, SkipReason: sr}
}

func TestLaterFailIsNotMaskedByEarlierPass(t *testing.T) {
	r := Build([]db.RWAttemptRow{
		row("T1490", "a1", "detection", controlval.VerdictPass, ""),
		row("T1490", "a2", "detection", controlval.VerdictFail, ""),
	})
	if r.Dimensions["detection"].Status != StatusGap {
		t.Fatalf("got %v", r.Dimensions["detection"].Status)
	}
	if len(r.Attempts) != 2 {
		t.Fatalf("attempts %d", len(r.Attempts))
	}
}

func TestStatusMatrix(t *testing.T) {
	ns := controlval.SkipNotTested
	cases := []struct {
		name string
		rows []db.RWAttemptRow
		want Status
	}{
		{"none", nil, StatusUnproven},
		{"all pass", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictPass, "")}, StatusProven},
		{"only skipped", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictSkipped, ns)}, StatusUnproven},
		{"only error", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictError, "")}, StatusUnproven},
		{"pass+skip", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictPass, ""), row("T2", "b", "recovery", controlval.VerdictSkipped, ns)}, StatusPartial},
		{"pass+error", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictPass, ""), row("T2", "b", "recovery", controlval.VerdictError, "")}, StatusPartial},
		{"all NA", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictSkipped, controlval.SkipNotApplicable)}, StatusNotApplicable},
		{"pass+NA", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictPass, ""), row("T2", "b", "recovery", controlval.VerdictSkipped, controlval.SkipNotApplicable)}, StatusProven},
		{"fail beats all", []db.RWAttemptRow{row("T1", "a", "recovery", controlval.VerdictPass, ""), row("T2", "b", "recovery", controlval.VerdictFail, "")}, StatusGap},
	}
	for _, c := range cases {
		if got := Build(c.rows).Dimensions["recovery"].Status; got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestOverall(t *testing.T) {
	p := controlval.VerdictPass
	all := func(f func(cap string) db.RWAttemptRow) []db.RWAttemptRow {
		return []db.RWAttemptRow{f("detection"), f("containment"), f("recovery")}
	}
	passing := all(func(c string) db.RWAttemptRow { return row("T1", "a", c, p, "") })
	if got := Build(passing).Overall; got != OverallEvidenced {
		t.Errorf("evidenced: %s", got)
	}
	// a skipped VSS-style recovery must never read as protection
	skipped := all(func(c string) db.RWAttemptRow {
		if c == "recovery" {
			return row("T1", "a", c, controlval.VerdictSkipped, controlval.SkipNotTested)
		}
		return row("T1", "a", c, p, "")
	})
	if got := Build(skipped).Overall; got != OverallUnproven {
		t.Errorf("skipped recovery: %s", got)
	}
	failed := append(append([]db.RWAttemptRow{}, passing...), row("T2", "b", "prevention", controlval.VerdictFail, ""))
	if got := Build(failed).Overall; got != OverallGapsFound {
		t.Errorf("gap: %s", got)
	}
	if got := Build(nil).Overall; got != OverallUnproven {
		t.Errorf("empty: %s", got)
	}
}

func TestAttemptsSortedAndCounts(t *testing.T) {
	r := Build([]db.RWAttemptRow{
		row("T2", "b", "detection", controlval.VerdictPass, ""),
		row("T1", "z", "detection", controlval.VerdictFail, ""),
		row("T1", "a", "detection", controlval.VerdictPass, ""),
	})
	if r.Attempts[0].TechniqueID != "T1" || r.Attempts[0].Action != "a" || r.Attempts[2].TechniqueID != "T2" {
		t.Fatalf("order %+v", r.Attempts)
	}
	d := r.Dimensions["detection"]
	if d.Pass != 2 || d.Fail != 1 || d.Attempts != 3 {
		t.Fatalf("counts %+v", d)
	}
}
