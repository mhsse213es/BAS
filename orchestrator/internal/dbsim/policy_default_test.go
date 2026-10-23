package dbsim

import (
	"strings"
	"testing"
)

// Ruling R-AK: the policy-diff requirement is default-safe. An Outcome for the
// read_grants probe can never grade PASS without a performed diff, whatever the
// caller put in ScenarioMeta.
func grantsOutcome(rows int) Outcome {
	return Outcome{ProbeID: ProbeReadGrants, ProbeRan: true, Probe: DBProbeResult{RowsRead: rows},
		CollectedAt: t0, Principal: "p", Marker: "m", RunID: "r"}
}

func TestReadGrantsWithoutFlagIsStillUnverifiable(t *testing.T) {
	for _, flag := range []bool{false, true} {
		s := db02Meta()
		s.RequirePolicyDiff = flag // caller forgot or explicitly disabled it
		rec, rep := mustValid(t, s, grantsOutcome(3))
		if rep.Result != ResultError || rep.Dimensions.Policy != DimUnverifiable {
			t.Fatalf("flag=%v: %s / %s", flag, rep.Result, rep.Dimensions.Policy)
		}
		if !strings.Contains(rec.Limitations, "policy diff not performed; grants were observable (3)") {
			t.Fatalf("flag=%v limitations %q", flag, rec.Limitations)
		}
	}
	// no expectations at all in the meta still must not look like a pass
	s := ScenarioMeta{ID: "X", Version: "1", ControlObjective: "o", Preconditions: "p", SyntheticDataManifest: "n", ActionAttempted: "a", ExpectedPrevention: "allow", Engine: "postgresql", TargetID: "t", Mode: ModeLab}
	if _, rep := mustValid(t, s, grantsOutcome(3)); rep.Result == ResultPass {
		t.Fatal("read_grants graded PASS without a diff")
	}
}

func TestReadGrantsSuppliedDiffDecidesRegardlessOfFlag(t *testing.T) {
	s := db02Meta()
	s.RequirePolicyDiff = false
	o := grantsOutcome(2)
	o.Diff = &DiffReport{PolicySource: "lab", GrantsChecked: 2, Deviations: []Deviation{}}
	if _, rep := mustValid(t, s, o); rep.Result != ResultPass {
		t.Fatalf("clean diff: %s", rep.Result)
	}
	o.Diff = &DiffReport{PolicySource: "lab", GrantsChecked: 2, Deviations: []Deviation{{Kind: DeviationExcessive, Role: "r", Object: "o", Privilege: "SELECT", PolicySource: "lab"}}}
	if _, rep := mustValid(t, s, o); rep.Result != ResultFail {
		t.Fatalf("deviating diff: %s", rep.Result)
	}
}

func TestOtherProbesAreUnaffectedByTheReadGrantsRule(t *testing.T) {
	s := meta() // DB-01 style: deny + detection
	o := denied()
	o.ProbeID = "read_restricted_table"
	if _, rep := mustValid(t, s, o); rep.Result != ResultPass || rep.Dimensions.Policy != DimNotExpected {
		t.Fatalf("%s / %s", rep.Result, rep.Dimensions.Policy)
	}
	s2 := db02Meta()
	s2.RequirePolicyDiff = false
	s2.ExpectedPrevention = "allow"
	o2 := grantsOutcome(2)
	o2.ProbeID = "read_roles"
	if _, rep := mustValid(t, s2, o2); rep.Result != ResultPass {
		t.Fatalf("read_roles: %s", rep.Result)
	}
}

// A denied read_grants has no grants to compare: the denial is the observation.
func TestDeniedReadGrantsKeepsDenialMeaning(t *testing.T) {
	s := db02Meta()
	s.ExpectedPrevention = "deny"
	o := Outcome{ProbeID: ProbeReadGrants, ProbeRan: true, Probe: DBProbeResult{Denied: true, ErrorClass: "permission_denied"},
		CollectedAt: t0, Principal: "p", Marker: "m", RunID: "r"}
	if _, rep := mustValid(t, s, o); rep.Result != ResultPass || rep.Dimensions.Policy != DimNotExpected {
		t.Fatalf("%s / %s (%s)", rep.Result, rep.Dimensions.Policy, rep.Reason)
	}
}
