package remoteaccess

// TransitViolation is evidence that a found route between a
// MandatoryTransit's FromZone and ToZone never visited ViaZone.
type TransitViolation struct {
	Transit MandatoryTransit `json:"transit"`
	Route   RoutePath        `json:"route"`
	Note    string           `json:"note"`
}

// ValidateMandatoryTransit checks each route against every
// MandatoryTransit whose FromZone/ToZone match the route's own
// endpoints (route[0] and route[len(route)-1]) in EITHER order,
// returning one TransitViolation per route that bypasses ViaZone.
// Matching is direction-agnostic because the tunnels/edges that make a
// bypass possible are themselves usable in both directions unless
// explicitly Directed, so a boundary declared between two zones must
// hold regardless of which zone a given route query started from --
// checking only one direction would leave the identical bypass
// undetected whenever queried in reverse. A route that does not match
// a Transit's endpoints (in either order) at all is not a candidate
// for that rule -- it is not a bypass, it is simply unrelated. This
// function is purely additive: it never removes a route from the
// caller's own result set, only annotates which ones violate a
// declared constraint, mirroring cloudpath.CorrelateCloudFinding's
// non-mutating discipline exactly.
func ValidateMandatoryTransit(routes []RoutePath, transits []MandatoryTransit) []TransitViolation {
	var violations []TransitViolation
	for _, route := range routes {
		if len(route) == 0 {
			continue
		}
		from, to := route[0], route[len(route)-1]
		for _, transit := range transits {
			matchesForward := transit.FromZone == from && transit.ToZone == to
			matchesReverse := transit.FromZone == to && transit.ToZone == from
			if !matchesForward && !matchesReverse {
				continue
			}
			if routeVisits(route, transit.ViaZone) {
				continue
			}
			violations = append(violations, TransitViolation{
				Transit: transit,
				Route:   route,
				Note:    "this route reaches the declared destination zone without visiting the required transit zone",
			})
		}
	}
	return violations
}

func routeVisits(route RoutePath, zone string) bool {
	for _, z := range route {
		if z == zone {
			return true
		}
	}
	return false
}
