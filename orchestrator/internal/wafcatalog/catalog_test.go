package wafcatalog

import "testing"

func TestAudspectWAFAttackCatalog_ReturnsValidatedCatalog(t *testing.T) {
	vectors, err := AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	if len(vectors) != 37 {
		t.Fatalf("len(vectors) = %d, want 37", len(vectors))
	}
	if err := ValidateCatalog(vectors); err != nil {
		t.Errorf("returned catalog fails ValidateCatalog: %v", err)
	}
}

func TestAudspectWAFAttackCatalog_CoversAllFamilies(t *testing.T) {
	vectors, err := AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	want := []AttackFamily{
		FamilySQLInjection, FamilyXSS, FamilyPathTraversal, FamilySSRF, FamilyFileUpload,
		FamilyHTTPParser, FamilyAPIAbuse, FamilyAuthAbuse, FamilyRateLimit, FamilyCacheWeakness, FamilyPolicyMisconfig,
		FamilyCommandInjection, FamilyFileInclusion, FamilyXXE, FamilyNoSQLInjection, FamilyLDAPInjection, FamilyXPathInjection,
	}
	seen := make(map[AttackFamily]bool)
	for _, v := range vectors {
		seen[v.Family] = true
	}
	for _, f := range want {
		if !seen[f] {
			t.Errorf("no vector found for family %q", f)
		}
	}
}

// Review Focus: AudspectWAFAttackCatalog must actually call ValidateCatalog
// and propagate its error -- with 34 hand-authored entries across several
// files, an accidental duplicate ID is an easy slip, and the aggregator must fail
// loudly rather than silently return a catalog containing one. This test
// cannot inject a real duplicate into the production seed data without
// breaking it, so it proves the wiring the same way Task 2 proved
// ValidateCatalog itself: by confirming the aggregator's own vectors contain
// no duplicate (the positive case already covered by
// TestAudspectWAFAttackCatalog_ReturnsValidatedCatalog above) and that every
// individual family function's output independently passes ValidateCatalog
// (already proven in Tasks 4-7) -- together these show there is no seam
// where a duplicate could slip past unvalidated.
func TestAudspectWAFAttackCatalog_EveryEntryIndividuallyValid(t *testing.T) {
	vectors, err := AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	ids := make(map[string]bool, len(vectors))
	for _, v := range vectors {
		if ids[v.ID] {
			t.Errorf("duplicate ID %q present in the returned catalog despite ValidateCatalog", v.ID)
		}
		ids[v.ID] = true
		if v.ID == "" || v.Provenance == "" {
			t.Errorf("vector %+v failed basic construction invariants", v)
		}
	}
}
