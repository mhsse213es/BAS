package remoteaccess

import "testing"

func TestValidateMandatoryTransit_BypassRoute_FlaggedAsViolation(t *testing.T) {
	routes := []RoutePath{{"corporate", "production"}} // skips the bastion entirely
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 -- the route bypasses the required bastion zone", violations)
	}
	if violations[0].Transit.CanonicalID != "mt-1" {
		t.Fatalf("violations[0].Transit.CanonicalID = %q, want %q", violations[0].Transit.CanonicalID, "mt-1")
	}
}

func TestValidateMandatoryTransit_RouteVisitsViaZone_NoViolation(t *testing.T) {
	routes := []RoutePath{{"corporate", "bastion", "production"}}
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- the route does visit the required bastion zone", violations)
	}
}

// TestValidateMandatoryTransit_NoRouteAtAllForTransitEndpoints_NoViolation
// pins Review Focus #3: a MandatoryTransit whose FromZone/ToZone
// simply has no candidate route among the ones supplied must produce
// no violation -- "no route found" is a different finding entirely,
// never force-reported as a bypass.
func TestValidateMandatoryTransit_NoRouteAtAllForTransitEndpoints_NoViolation(t *testing.T) {
	routes := []RoutePath{} // genuinely isolated zones -- the caller found nothing
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- no candidate route exists for this Transit's endpoints at all", violations)
	}
}

func TestValidateMandatoryTransit_UnrelatedTransit_DoesNotInterfere(t *testing.T) {
	routes := []RoutePath{{"corporate", "production"}}
	transits := []MandatoryTransit{
		{CanonicalID: "mt-unrelated", FromZone: "guest", ToZone: "staging", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- a Transit rule for a different zone pair must not match this route", violations)
	}
}

// TestValidateMandatoryTransit_DenseFixture_OnlyNonCompliantRouteFlagged
// pins the rest of Review Focus #5: of the two distinct routes
// Task 1's dense fixture finds (a direct tunnel, and a route via the
// bastion zone), only the direct one should be flagged when a
// MandatoryTransit requires the bastion -- proving route search and
// bastion validation interact correctly across multiple real
// candidates, not just a trivial 2-zone case.
func TestValidateMandatoryTransit_DenseFixture_OnlyNonCompliantRouteFlagged(t *testing.T) {
	routes := []RoutePath{
		{"corporate", "production"},
		{"corporate", "bastion", "production"},
	}
	transits := []MandatoryTransit{
		{CanonicalID: "mt-1", FromZone: "corporate", ToZone: "production", ViaZone: "bastion"},
	}
	violations := ValidateMandatoryTransit(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 (only the direct route bypasses the bastion)", violations)
	}
	if len(violations[0].Route) != 2 {
		t.Fatalf("violations[0].Route = %v, want the 2-zone direct route, not the compliant 3-zone one", violations[0].Route)
	}
}
