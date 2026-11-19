package exfilchain

import (
	"strings"
	"testing"
)

func in(tech, step, result, details string) Input {
	return Input{TechniqueID: tech, StepName: step, Result: result, Details: details}
}

func TestPhaseOf_MapsTechniquesToChainPhases(t *testing.T) {
	cases := map[string]Phase{
		"T1083": PhaseDiscovery, "T1135": PhaseDiscovery,
		"T1005": PhaseCollection, "T1039": PhaseCollection, "T1114.001": PhaseCollection,
		"T1074.001": PhaseStaging, "T1560.001": PhaseArchive,
		"T1048.003": PhaseTransfer, "T1567.002": PhaseTransfer, "T1029": PhaseTransfer, "T1052.001": PhaseTransfer,
		"T1562.001": PhaseOther,
	}
	for tech, want := range cases {
		if got := PhaseOf(tech); got != want {
			t.Errorf("PhaseOf(%s) = %s, want %s", tech, got, want)
		}
	}
}

func TestBuild_ReportsMissingChainPhases(t *testing.T) {
	rep := Build([]Input{in("T1048.003", "upload", "fail", "run=1a2b3c4d")})
	if !contains(rep.Missing, PhaseCollection) || !contains(rep.Missing, PhaseStaging) || !contains(rep.Missing, PhaseArchive) {
		t.Fatalf("missing = %v, want collection, staging and archive", rep.Missing)
	}
}

func TestBuild_FlagsTransferWithoutCollection(t *testing.T) {
	rep := Build([]Input{in("T1048.003", "upload", "fail", "run=1a2b3c4d")})
	if !hasFinding(rep, "transfer ran before any collection") {
		t.Fatalf("expected transfer-before-collection finding, got %v", rep.Findings)
	}
}

func TestBuild_LinkedWhenAllStagesShareOneRunTag(t *testing.T) {
	rep := Build([]Input{
		in("T1005", "discover", "fail", "bas_dbexp_1a2b3c4d/customers.csv"),
		in("T1560.001", "archive", "fail", "bas_dbexp_1a2b3c4d/customers.zip"),
		in("T1048.003", "upload", "fail", "run=1a2b3c4d reached=false"),
	})
	if !rep.Linked {
		t.Fatalf("expected linked, findings %v", rep.Findings)
	}
	if len(rep.Missing) != 1 || rep.Missing[0] != PhaseStaging {
		t.Fatalf("missing = %v, want only staging", rep.Missing)
	}
}

func TestBuild_NotLinkedWhenRunTagsDiffer(t *testing.T) {
	rep := Build([]Input{
		in("T1005", "discover", "fail", "bas_dbexp_1a2b3c4d/x"),
		in("T1048.003", "upload", "fail", "run=9f8e7d6c"),
	})
	if rep.Linked || !hasFinding(rep, "stages carry different run tags") {
		t.Fatalf("expected not linked with tag-mismatch finding, got linked=%v findings=%v", rep.Linked, rep.Findings)
	}
}

func TestBuild_NotLinkedWhenNoRunTagAppears(t *testing.T) {
	rep := Build([]Input{in("T1005", "discover", "fail", "no identifiers here")})
	if rep.Linked || !hasFinding(rep, "no run tag found") {
		t.Fatalf("expected not linked with no-tag finding, got linked=%v findings=%v", rep.Linked, rep.Findings)
	}
}

func TestBuild_KeepsStepOrderAndResults(t *testing.T) {
	rep := Build([]Input{in("T1005", "a", "pass", "run=1a2b3c4d"), in("T1048.003", "b", "fail", "run=1a2b3c4d")})
	if len(rep.Stages) != 2 || rep.Stages[0].StepName != "a" || rep.Stages[1].Result != "fail" {
		t.Fatalf("stages out of order or wrong: %+v", rep.Stages)
	}
}

func contains(ps []Phase, p Phase) bool {
	for _, x := range ps {
		if x == p {
			return true
		}
	}
	return false
}

func hasFinding(r Report, sub string) bool {
	for _, f := range r.Findings {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}
