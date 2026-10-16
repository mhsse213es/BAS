package waforigin

import (
	"testing"

	"github.com/audspect/bas/internal/wafcatalog"
)

func TestAudspectWAFOriginCatalog_ReturnsFiveScenariosTotal(t *testing.T) {
	bypass, protocol, consistency, err := AudspectWAFOriginCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFOriginCatalog: %v", err)
	}
	total := len(bypass) + len(protocol) + len(consistency)
	if total != 5 {
		t.Fatalf("total scenarios = %d, want 5 (got bypass=%d, protocol=%d, consistency=%d)", total, len(bypass), len(protocol), len(consistency))
	}
	if len(bypass) != 3 {
		t.Errorf("len(bypass) = %d, want 3", len(bypass))
	}
	if len(protocol) != 1 {
		t.Errorf("len(protocol) = %d, want 1", len(protocol))
	}
	if len(consistency) != 1 {
		t.Errorf("len(consistency) = %d, want 1", len(consistency))
	}
}

// Review Focus: every cross-referenced AttackVectorID must be checked
// against the real wafcatalog catalog by a test -- a typo'd ID must fail
// here, not just be asserted correct in prose.
func TestAudspectWAFOriginCatalog_CrossReferencedVectorIDsExistInWafcatalog(t *testing.T) {
	bypass, _, consistency, err := AudspectWAFOriginCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFOriginCatalog: %v", err)
	}
	realCatalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("wafcatalog.AudspectWAFAttackCatalog: %v", err)
	}
	realIDs := make(map[string]bool, len(realCatalog))
	for _, v := range realCatalog {
		realIDs[v.ID] = true
	}
	for _, s := range bypass {
		if !realIDs[s.AttackVectorID] {
			t.Errorf("bypass scenario %q references AttackVectorID %q, which does not exist in wafcatalog.AudspectWAFAttackCatalog()", s.ID, s.AttackVectorID)
		}
	}
	for _, s := range consistency {
		if !realIDs[s.AttackVectorID] {
			t.Errorf("consistency scenario %q references AttackVectorID %q, which does not exist in wafcatalog.AudspectWAFAttackCatalog()", s.ID, s.AttackVectorID)
		}
	}
}

func TestAudspectWAFOriginCatalog_BypassScenariosCoverAllThreeBypassWeaknesses(t *testing.T) {
	bypass, _, _, err := AudspectWAFOriginCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFOriginCatalog: %v", err)
	}
	seen := make(map[WeaknessType]int)
	for _, s := range bypass {
		seen[s.Weakness]++
	}
	for _, w := range []WeaknessType{WeaknessRoutingCoverageGap, WeaknessDirectOriginReachability, WeaknessFailOpenOnUnavailability} {
		if seen[w] != 1 {
			t.Errorf("weakness %q appears %d times in the bypass catalog, want exactly 1", w, seen[w])
		}
	}
}
