package otsafety

import "github.com/audspect/bas/internal/networktopology"

// TransitViolation is evidence that a found route between a
// RequiredTransit's FromZone and ToZone (in either direction) never
// visited ViaZone.
type TransitViolation struct {
	Transit RequiredTransit           `json:"transit"`
	Route   networktopology.RoutePath `json:"route"`
	Note    string                    `json:"note"`
}

// ValidateRequiredTransits checks each route against every
// RequiredTransit whose FromZone/ToZone match the route's own
// endpoints (route[0] and route[len(route)-1]) in EITHER order,
// returning one TransitViolation per route that bypasses ViaZone.
// Matching is direction-agnostic because the edges that make a bypass
// possible are themselves usable in both directions unless explicitly
// Directed, so a boundary declared between two zones must hold
// regardless of which zone a given route query started from. A route
// that does not match a transit's endpoints (in either order) at all
// is not a candidate for that rule -- it is not a bypass, it is simply
// unrelated. Purely additive: it never removes a route from the
// caller's own result set, only annotates which ones violate a
// declared constraint.
func ValidateRequiredTransits(routes []networktopology.RoutePath, transits []RequiredTransit) []TransitViolation {
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

func routeVisits(route networktopology.RoutePath, zone string) bool {
	for _, z := range route {
		if z == zone {
			return true
		}
	}
	return false
}
