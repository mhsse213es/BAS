package dbbuild

import (
	"testing"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

func TestMetaForRejectsNonDBSimScenario(t *testing.T) {
	sc := &scenario.Scenario{ID: "dbsim-db03-unauthorized-access", ProductLine: "dlp"}
	if _, err := MetaFor(sc, dbsim.DBProbeSpec{ProbeID: "read_restricted_table"}); err == nil {
		t.Fatal("non-dbsim product line must be rejected")
	}
	if _, err := MetaFor(nil, dbsim.DBProbeSpec{ProbeID: "read_roles"}); err == nil {
		t.Fatal("nil scenario must be rejected")
	}
}

func TestMetaForFailsClosedOnUnknown(t *testing.T) {
	if _, err := MetaFor(&scenario.Scenario{ID: "dbsim-unknown", ProductLine: "dbsim"}, dbsim.DBProbeSpec{ProbeID: "read_roles"}); err == nil {
		t.Fatal("unknown scenario must be rejected")
	}
	if _, err := MetaFor(&scenario.Scenario{ID: "dbsim-db03-unauthorized-access", ProductLine: "dbsim"}, dbsim.DBProbeSpec{ProbeID: "read_roles"}); err == nil {
		t.Fatal("probe without an expectation must be rejected")
	}
}

func TestMetaForFillsIdentityFromSpec(t *testing.T) {
	sc := &scenario.Scenario{ID: "dbsim-db02-excessive-grants", ProductLine: "dbsim", Description: "x"}
	spec := dbsim.DBProbeSpec{Engine: "mysql", ProbeID: "read_grants", TargetID: "lab-db", Mode: dbsim.ExecMode("read_only")}
	m, err := MetaFor(sc, spec)
	if err != nil {
		t.Fatal(err)
	}
	if m.ID != sc.ID || m.Version != "1" || m.Engine != "mysql" || m.TargetID != "lab-db" || m.Mode != spec.Mode {
		t.Errorf("identity: %+v", m)
	}
	if m.ExpectedPrevention != "allow" || !m.ExpectDetection || !m.ExpectResponse || !m.RequireObservation || !m.RequirePolicyDiff {
		t.Errorf("expectation: %+v", m)
	}
	if m.ControlObjective == "" || m.Preconditions == "" || m.SyntheticDataManifest == "" || m.ActionAttempted == "" {
		t.Errorf("descriptive fields must be non-empty: %+v", m)
	}
	m2, err := MetaFor(&scenario.Scenario{ID: "dbsim-db07-sensitive-classification", ProductLine: "dbsim"}, dbsim.DBProbeSpec{ProbeID: "read_classified_fixture"})
	if err != nil || !m2.ExpectClassification {
		t.Errorf("db07: %+v %v", m2, err)
	}
}
