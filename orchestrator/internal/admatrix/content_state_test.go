package admatrix

import "testing"

// All 21 AD primitives must be classified, each with an evidence record.
func TestContentStates_CoversAllPrimitives(t *testing.T) {
	states := ContentStates()
	if len(states) != 21 {
		t.Fatalf("expected a content state for all 21 catalog primitives, got %d", len(states))
	}
	seen := map[string]bool{}
	for _, e := range states {
		if e.PrimitiveID == "" {
			t.Fatalf("content evidence with empty PrimitiveID: %+v", e)
		}
		if seen[e.PrimitiveID] {
			t.Fatalf("duplicate content evidence for %q", e.PrimitiveID)
		}
		seen[e.PrimitiveID] = true
	}
}

// Evidence invariants per AD.txt section 5 and the approved four-state model.
func TestContentStates_EvidenceInvariants(t *testing.T) {
	for _, e := range ContentStates() {
		switch e.State {
		case ContentScenarioComposable:
			// A committed scenario demonstrably implements it -> repo-verified, cited, mapped.
			if !e.RepoVerified || e.Source == "" || e.TechniqueID == "" {
				t.Fatalf("%s scenario-composable must be repo-verified with a cited source + technique: %+v", e.PrimitiveID, e)
			}
		case ContentReusableUnmapped:
			// A specific upstream implementation identified by source + technique.
			if e.Source == "" || e.TechniqueID == "" {
				t.Fatalf("%s reusable-unmapped must cite an upstream source + technique: %+v", e.PrimitiveID, e)
			}
		case ContentModelOnly:
			// Must carry an explicit reason (why no verifiable mapping).
			if e.Reason == "" {
				t.Fatalf("%s model-only must carry an explicit reason: %+v", e.PrimitiveID, e)
			}
		case ContentMissingExecutable:
			// Only valid after a sufficiently scoped inventory; none should claim it now.
			t.Fatalf("%s must NOT be missing-executable-content without a scoped live inventory", e.PrimitiveID)
		default:
			t.Fatalf("%s has an unknown content state %q", e.PrimitiveID, e.State)
		}
	}
}

// Known, verified classifications grounded in current repo content.
func TestContentStates_KnownClassifications(t *testing.T) {
	byID := map[string]ContentEvidence{}
	for _, e := range ContentStates() {
		byID[e.PrimitiveID] = e
	}

	// Kerberoasting baseline: a committed scenario performs these.
	for _, id := range []string{"spn-enumerate", "kerberoast-tgs-request", "asrep-roast-discover"} {
		if byID[id].State != ContentScenarioComposable {
			t.Errorf("%s: expected scenario-composable, got %q", id, byID[id].State)
		}
	}

	// DCSync: upstream public atomic cited in source, not integrated into a scenario.
	if dc := byID["dcsync"]; dc.State != ContentReusableUnmapped || dc.RepoVerified {
		t.Errorf("dcsync: expected reusable-unmapped + externally-referenced (RepoVerified=false), got %+v", dc)
	}

	// The gap families have no committed scenario and no cited reusable content in-repo:
	// honest model-only with the standard reason -- NOT missing-executable-content.
	for _, id := range []string{"adcs-esc6", "adcs-esc8", "kerberos-unconstrained-delegation", "trust-intra-forest-sid-history", "gpo-abuse-linked-scope", "acl-genericall-takeover", "rbcd-configure"} {
		e := byID[id]
		if e.State != ContentModelOnly {
			t.Errorf("%s: expected model-only (no verified repo content), got %q", id, e.State)
		}
		if e.Reason != reasonNoRepoMapping {
			t.Errorf("%s: expected reason %q, got %q", id, reasonNoRepoMapping, e.Reason)
		}
	}
}

func TestSummarizeContent_MeasuresRealExecutableCoverage(t *testing.T) {
	s := SummarizeContent()
	if s.Total != 21 {
		t.Fatalf("expected total 21, got %d", s.Total)
	}
	if s.ScenarioComposable != 3 {
		t.Errorf("expected 3 scenario-composable (Kerberoast baseline), got %d", s.ScenarioComposable)
	}
	if s.ReusableUnmapped != 1 {
		t.Errorf("expected 1 reusable-unmapped (DCSync), got %d", s.ReusableUnmapped)
	}
	if s.ModelOnly != 17 {
		t.Errorf("expected 17 model-only (the gap families), got %d", s.ModelOnly)
	}
	if s.MissingExecutable != 0 {
		t.Errorf("expected 0 missing-executable-content (no scoped inventory yet), got %d", s.MissingExecutable)
	}
}
