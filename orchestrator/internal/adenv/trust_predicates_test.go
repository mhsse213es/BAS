package adenv

import "testing"

func TestIsIntraForestTrustAbusable(t *testing.T) {
	// Parent-child trusts do not apply SID filtering -> abusable regardless of flag.
	if !IsIntraForestTrustAbusable(Trust{Type: TrustTypeParentChild}) {
		t.Fatal("a parent-child trust must be intra-forest abusable")
	}
	if IsIntraForestTrustAbusable(Trust{Type: TrustTypeExternal}) {
		t.Fatal("an external trust is not an intra-forest trust")
	}
}

func TestIsCrossForestSIDAbusable(t *testing.T) {
	// External/forest trust with SID filtering DISABLED -> abusable.
	if !IsCrossForestSIDAbusable(Trust{Type: TrustTypeExternal, SIDFilteringDisabled: true}) {
		t.Fatal("external trust with SID filtering disabled must be abusable")
	}
	if !IsCrossForestSIDAbusable(Trust{Type: TrustTypeForest, SIDFilteringDisabled: true}) {
		t.Fatal("forest trust with SID filtering disabled must be abusable")
	}
	// Default (filtering enabled) -> not abusable.
	if IsCrossForestSIDAbusable(Trust{Type: TrustTypeExternal}) {
		t.Fatal("external trust with SID filtering enabled (default) is not abusable")
	}
	// Parent-child is intra-forest, not a cross-forest SID case.
	if IsCrossForestSIDAbusable(Trust{Type: TrustTypeParentChild, SIDFilteringDisabled: true}) {
		t.Fatal("a parent-child trust is not a cross-forest SID-filtering case")
	}
}
