package networktopology

import "fmt"

const (
	MaxZonesPerTopologyImport  = 500
	MaxEdgesPerTopologyImport  = 5000
	MaxHopsPerPathQuery        = 10
	MaxCandidateRoutesPerQuery = 20

	// maxRouteSearchSteps is a defensive bound on total DFS work,
	// independent of the hop/candidate-count caps -- a dense, highly
	// cyclic topology within the zone/edge caps could still cost a lot
	// of exploration before finding MaxCandidateRoutesPerQuery results.
	// Unexported: not a caller-tunable safety knob.
	maxRouteSearchSteps = 20000
)

// RoutePath is an ordered sequence of zone names from source to
// destination, inclusive of both endpoints.
type RoutePath []string

// FindCandidateRoutes returns up to MaxCandidateRoutesPerQuery simple
// paths (no repeated zone) from sourceZone to destZone across topo's
// declared adjacency, each at most maxHops edges long. maxHops is
// clamped to MaxHopsPerPathQuery if it exceeds that ceiling, or if it is
// zero or negative (meaning "no limit specified", never "zero hops
// allowed"). Zero candidate routes is a valid result, not an error --
// callers must classify this as "no known route", never "blocked".
// sourceZone == destZone always returns exactly one trivial
// two-element route (a zone can always trivially reach itself,
// independent of any declared edge).
//
// exhausted is true when the defensive maxRouteSearchSteps budget was
// hit before the search could either find MaxCandidateRoutesPerQuery
// routes or exhaustively rule out more -- a dense/cyclic topology
// within the zone/edge caps can still cost more exploration than the
// budget allows. A zero-route result with exhausted=true is NOT the
// same finding as a zero-route result with exhausted=false: the first
// means "search was truncated, absence is not proven", the second
// means "search space was fully explored, no route exists". Callers
// must not conflate the two.
func FindCandidateRoutes(topo *TopologyImport, sourceZone, destZone string, maxHops int) ([]RoutePath, bool, error) {
	if len(topo.Zones) > MaxZonesPerTopologyImport {
		return nil, false, fmt.Errorf("networktopology: topology has too many zones -- got %d, max %d", len(topo.Zones), MaxZonesPerTopologyImport)
	}
	if len(topo.Edges) > MaxEdgesPerTopologyImport {
		return nil, false, fmt.Errorf("networktopology: topology has too many edges -- got %d, max %d", len(topo.Edges), MaxEdgesPerTopologyImport)
	}
	if sourceZone == destZone {
		return []RoutePath{{sourceZone, destZone}}, false, nil
	}
	if maxHops > MaxHopsPerPathQuery || maxHops <= 0 {
		maxHops = MaxHopsPerPathQuery
	}

	adj := buildAdjacency(topo.Edges)

	var results []RoutePath
	steps := 0
	exhausted := false
	visited := map[string]bool{sourceZone: true}
	var dfs func(current string, path RoutePath)
	dfs = func(current string, path RoutePath) {
		steps++
		if steps > maxRouteSearchSteps {
			exhausted = true
			return
		}
		if len(results) >= MaxCandidateRoutesPerQuery {
			return
		}
		if current == destZone {
			found := make(RoutePath, len(path))
			copy(found, path)
			results = append(results, found)
			return
		}
		if len(path)-1 >= maxHops {
			return
		}
		for _, next := range adj[current] {
			if visited[next] {
				continue
			}
			visited[next] = true
			dfs(next, append(path, next))
			visited[next] = false
			if steps > maxRouteSearchSteps || len(results) >= MaxCandidateRoutesPerQuery {
				return
			}
		}
	}
	dfs(sourceZone, RoutePath{sourceZone})
	return results, exhausted, nil
}

// buildAdjacency turns edges into an adjacency list. An undirected edge
// (Directed=false) is added in both directions; a directed edge only
// FromZone -> ToZone.
func buildAdjacency(edges []RouteEdge) map[string][]string {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.FromZone] = append(adj[e.FromZone], e.ToZone)
		if !e.Directed {
			adj[e.ToZone] = append(adj[e.ToZone], e.FromZone)
		}
	}
	return adj
}
