package otsafety

import (
	"testing"

	"github.com/audspect/bas/internal/networktopology"
)

func TestValidateRequiredTransits_BypassRoute_FlaggedAsViolation(t *testing.T) {
	routes := []networktopology.RoutePath{{"corporate", "ot"}} // skips the DMZ entirely
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 -- the route bypasses the required DMZ zone", violations)
	}
	if violations[0].Transit.CanonicalID != "rt-1" {
		t.Fatalf("violations[0].Transit.CanonicalID = %q, want %q", violations[0].Transit.CanonicalID, "rt-1")
	}
}

func TestValidateRequiredTransits_RouteVisitsViaZone_NoViolation(t *testing.T) {
	routes := []networktopology.RoutePath{{"corporate", "dmz", "ot"}}
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- the route does visit the required DMZ zone", violations)
	}
}

// TestValidateRequiredTransits_NoRouteAtAllForTransitEndpoints_NoViolation
// pins Review Focus #1's "independent gates" half for the detection
// side: a RequiredTransit whose endpoints have no candidate route
// among the ones supplied must produce no violation -- "no route
// found" is a different finding entirely, never force-reported as a
// bypass.
func TestValidateRequiredTransits_NoRouteAtAllForTransitEndpoints_NoViolation(t *testing.T) {
	routes := []networktopology.RoutePath{} // genuinely isolated zones
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- no candidate route exists for this transit's endpoints at all", violations)
	}
}

func TestValidateRequiredTransits_UnrelatedTransit_DoesNotInterfere(t *testing.T) {
	routes := []networktopology.RoutePath{{"corporate", "ot"}}
	transits := []RequiredTransit{
		{CanonicalID: "rt-unrelated", FromZone: "guest", ToZone: "staging", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- a transit rule for a different zone pair must not match this route", violations)
	}
}

// TestValidateRequiredTransits_BypassRoute_ReverseDirection_StillFlagged
// pins Review Focus #5 and this plan's own Global Constraints --
// direction-agnostic matching from the start, incorporating Phase 6B's
// final-review lesson rather than re-learning it.
func TestValidateRequiredTransits_BypassRoute_ReverseDirection_StillFlagged(t *testing.T) {
	routes := []networktopology.RoutePath{{"ot", "corporate"}} // same bypass, reverse direction
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 -- the bypass exists regardless of which direction it was queried from", violations)
	}
}

// TestValidateRequiredTransits_DenseFixture_OnlyNonCompliantRouteFlagged
// mirrors this project's own standing lesson: a flat/trivial fixture
// can mask a real multi-tier bug (DNSSEC, TLS-cert-chain, Phase 5) --
// always test a fixture with more than one candidate route.
func TestValidateRequiredTransits_DenseFixture_OnlyNonCompliantRouteFlagged(t *testing.T) {
	routes := []networktopology.RoutePath{
		{"corporate", "ot"},
		{"corporate", "dmz", "ot"},
	}
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 (only the direct route bypasses the DMZ)", violations)
	}
	if len(violations[0].Route) != 2 {
		t.Fatalf("violations[0].Route = %v, want the 2-zone direct route, not the compliant 3-zone one", violations[0].Route)
	}
}
