package remoteaccess

import (
	"fmt"

	"github.com/audspect/bas/internal/networktopology"
)

// maxRouteSearchSteps is the same defensive bound on total DFS work
// every prior phase's route search carries, independent of the
// tunnel/transit caps above. Unexported: not a caller-tunable safety
// knob.
const maxRouteSearchSteps = 20000

// MaxHopsPerPathQuery and MaxCandidateRoutesPerQuery mirror
// networktopology's own ceilings exactly (networktopology/routes.go).
const (
	MaxHopsPerPathQuery        = 10
	MaxCandidateRoutesPerQuery = 20
)

// RoutePath is an ordered sequence of zone names from source to
// destination, inclusive of both endpoints -- same shape as
// networktopology.RoutePath.
type RoutePath []string

// FindCandidateRemoteAccessRoutes returns up to
// MaxCandidateRoutesPerQuery simple paths (no repeated zone) from
// sourceZone to destZone across the UNION of topo's declared
// RouteEdges and remote's VPN tunnels in State == TunnelUp -- a Down
// or Unknown tunnel is never a usable edge, mirroring exactly how
// cloudtopology.FindCandidateCloudRoutes treats only PeeringActive as
// usable. This is a new bounded DFS (not a reuse of
// networktopology.FindCandidateRoutes, which is hardcoded to
// topo.Edges alone), modeled directly on that function's own
// implementation. sourceZone == destZone always returns exactly one
// trivial two-element route. maxHops is clamped to
// MaxHopsPerPathQuery if it exceeds that ceiling, or if zero/negative.
func FindCandidateRemoteAccessRoutes(topo *networktopology.TopologyImport, remote *RemoteAccessImport, sourceZone, destZone string, maxHops int) ([]RoutePath, bool, error) {
	if len(remote.Tunnels) > MaxTunnelsPerImport {
		return nil, false, fmt.Errorf("remoteaccess: import has too many tunnels -- got %d, max %d", len(remote.Tunnels), MaxTunnelsPerImport)
	}
	if sourceZone == destZone {
		return []RoutePath{{sourceZone, destZone}}, false, nil
	}
	if maxHops > MaxHopsPerPathQuery || maxHops <= 0 {
		maxHops = MaxHopsPerPathQuery
	}

	adj := buildCombinedAdjacency(topo.Edges, remote.Tunnels)

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

// buildCombinedAdjacency unions topo's declared physical RouteEdges
// with remote's VPN tunnels filtered to State == TunnelUp. A Down or
// Unknown tunnel contributes no edge at all. Directed semantics match
// networktopology.RouteEdge's own convention for both edge kinds.
func buildCombinedAdjacency(edges []networktopology.RouteEdge, tunnels []VPNTunnel) map[string][]string {
	adj := map[string][]string{}
	for _, e := range edges {
		adj[e.FromZone] = append(adj[e.FromZone], e.ToZone)
		if !e.Directed {
			adj[e.ToZone] = append(adj[e.ToZone], e.FromZone)
		}
	}
	for _, tun := range tunnels {
		if tun.State != TunnelUp {
			continue
		}
		adj[tun.FromZone] = append(adj[tun.FromZone], tun.ToZone)
		if !tun.Directed {
			adj[tun.ToZone] = append(adj[tun.ToZone], tun.FromZone)
		}
	}
	return adj
}
