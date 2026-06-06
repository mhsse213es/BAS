package models

import "testing"

func TestEnterpriseTacticsComplete(t *testing.T) {
	if len(EnterpriseTactics) != 14 {
		t.Fatalf("expected 14 enterprise tactics, got %d", len(EnterpriseTactics))
	}
	seen := map[string]bool{}
	for _, tac := range EnterpriseTactics {
		if tac.ID == "" || tac.Name == "" || tac.AttackID == "" {
			t.Errorf("incomplete tactic: %+v", tac)
		}
		if seen[tac.ID] {
			t.Errorf("duplicate tactic id %q", tac.ID)
		}
		seen[tac.ID] = true
		if TacticName(tac.ID) != tac.Name {
			t.Errorf("TacticName(%q) = %q, want %q", tac.ID, TacticName(tac.ID), tac.Name)
		}
	}
}

func TestTacticNameUnknown(t *testing.T) {
	if got := TacticName("not-a-tactic"); got != "not-a-tactic" {
		t.Errorf("unknown tactic should echo input, got %q", got)
	}
}

// TestShippedScenarioTechniquesMapped guarantees every base technique referenced
// by the shipped scenarios resolves to a known tactic — so runs always score
// with a tactic instead of falling through to "unknown".
func TestShippedScenarioTechniquesMapped(t *testing.T) {
	tactics := map[string]bool{}
	for _, tac := range EnterpriseTactics {
		tactics[tac.ID] = true
	}
	// Base IDs that appear across scenarios/*.yaml, including the ten added in
	// this change (T1221, T1135, T1552, T1557, T1090, T1046, T1127, T1197,
	// T1115, T1569).
	shipped := []string{
		"T1003", "T1006.001", "T1010", "T1012", "T1016", "T1018", "T1021",
		"T1027", "T1033", "T1036", "T1039", "T1040", "T1046", "T1047", "T1048",
		"T1053", "T1055", "T1056", "T1057", "T1059", "T1068", "T1069", "T1070",
		"T1071", "T1078", "T1080", "T1082", "T1083", "T1087", "T1090", "T1098",
		"T1105", "T1110", "T1112", "T1113", "T1114", "T1115", "T1119", "T1124",
		"T1127", "T1134", "T1135", "T1136", "T1140", "T1190", "T1197", "T1218",
		"T1221", "T1485", "T1486", "T1489", "T1490", "T1543", "T1547", "T1548",
		"T1550", "T1552", "T1555", "T1557", "T1558", "T1562", "T1566", "T1569",
		"T1589",
	}
	for _, id := range shipped {
		tac := LookupTactic(id)
		if tac == "" {
			t.Errorf("technique %s has no tactic mapping", id)
			continue
		}
		if !tactics[tac] {
			t.Errorf("technique %s maps to unknown tactic %q", id, tac)
		}
	}
}
