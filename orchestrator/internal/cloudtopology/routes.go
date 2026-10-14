package cloudtopology

import (
	"fmt"
	"net"
)

// CloudRoutePath is an ordered sequence of subnet CanonicalIDs from
// source to destination, inclusive of both endpoints -- same shape as
// networktopology.RoutePath.
type CloudRoutePath []string

// FindCandidateCloudRoutes returns up to MaxCandidateRoutesPerQuery
// simple paths (no repeated subnet) from sourceSubnetID to
// destSubnetID, each at most maxHops edges long (clamped to
// MaxHopsPerPathQuery, or defaulted to it when zero/negative). A
// same-network local route (a TargetLocal RouteTableEntry on the
// current subnet covering the destination's CIDR) connects two
// subnets in one network; a cross-network hop requires a TargetPeering
// RouteTableEntry referencing a PeeringConnection whose State ==
// PeeringActive -- a pending/rejected peering is real evidence of no
// route via that specific connection, never proof no other path
// exists. sourceSubnetID == destSubnetID always returns one trivial
// single-element route. Zero routes is a valid result, not an error.
//
// exhausted is true when the defensive maxRouteSearchSteps budget was
// hit before the search could either find MaxCandidateRoutesPerQuery
// routes or exhaustively rule out more. A zero-route result with
// exhausted=true means "search was truncated, absence is not
// proven"; exhausted=false means "search space was fully explored, no
// route exists" -- callers must not conflate the two.
func FindCandidateCloudRoutes(imp *CloudTopologyImport, sourceSubnetID, destSubnetID string, maxHops int) ([]CloudRoutePath, bool, error) {
	if len(imp.Subnets) > MaxSubnetsPerImport {
		return nil, false, fmt.Errorf("cloudtopology: topology has too many subnets -- got %d, max %d", len(imp.Subnets), MaxSubnetsPerImport)
	}
	if len(imp.Routes) > MaxRoutesPerImport {
		return nil, false, fmt.Errorf("cloudtopology: topology has too many routes -- got %d, max %d", len(imp.Routes), MaxRoutesPerImport)
	}
	if maxHops <= 0 || maxHops > MaxHopsPerPathQuery {
		maxHops = MaxHopsPerPathQuery
	}

	subnetByID := make(map[string]*CloudSubnet, len(imp.Subnets))
	for i := range imp.Subnets {
		subnetByID[imp.Subnets[i].CanonicalID] = &imp.Subnets[i]
	}
	if _, ok := subnetByID[sourceSubnetID]; !ok {
		return nil, false, fmt.Errorf("cloudtopology: subnet %q not found in this import", sourceSubnetID)
	}
	if _, ok := subnetByID[destSubnetID]; !ok {
		return nil, false, fmt.Errorf("cloudtopology: subnet %q not found in this import", destSubnetID)
	}
	if sourceSubnetID == destSubnetID {
		return []CloudRoutePath{{sourceSubnetID}}, false, nil
	}

	peeringByID := make(map[string]*PeeringConnection, len(imp.Peerings))
	for i := range imp.Peerings {
		peeringByID[imp.Peerings[i].CanonicalID] = &imp.Peerings[i]
	}
	adjacency := buildCloudAdjacency(imp, subnetByID, peeringByID)

	var routes []CloudRoutePath
	exhausted := false
	steps := 0
	visited := map[string]bool{sourceSubnetID: true}

	var dfs func(path []string) bool // returns true to stop the whole search
	dfs = func(path []string) bool {
		steps++
		if steps > maxRouteSearchSteps {
			exhausted = true
			return true
		}
		if len(routes) >= MaxCandidateRoutesPerQuery {
			return true
		}
		current := path[len(path)-1]
		if current == destSubnetID {
			routes = append(routes, append(CloudRoutePath{}, path...))
			return false
		}
		if len(path)-1 >= maxHops {
			return false
		}
		for _, next := range adjacency[current] {
			if visited[next] {
				continue
			}
			visited[next] = true
			stop := dfs(append(append([]string{}, path...), next))
			visited[next] = false
			if stop {
				return true
			}
		}
		return false
	}
	dfs([]string{sourceSubnetID})

	return routes, exhausted, nil
}

// buildCloudAdjacency returns, for each subnet, the subnets it has a
// usable route to.
func buildCloudAdjacency(imp *CloudTopologyImport, subnetByID map[string]*CloudSubnet, peeringByID map[string]*PeeringConnection) map[string][]string {
	adjacency := make(map[string][]string)
	for _, route := range imp.Routes {
		from, ok := subnetByID[route.SubnetID]
		if !ok {
			continue
		}
		switch route.Target {
		case TargetLocal:
			for _, s := range imp.Subnets {
				if s.NetworkID == from.NetworkID && s.CanonicalID != from.CanonicalID && cidrCovers(route.DestinationCIDR, s.CIDRBlock) {
					adjacency[from.CanonicalID] = append(adjacency[from.CanonicalID], s.CanonicalID)
				}
			}
		case TargetPeering:
			peer, ok := peeringByID[route.TargetRef]
			if !ok || peer.State != PeeringActive {
				continue
			}
			var peerNetworkID string
			switch {
			case peer.NetworkAID == from.NetworkID:
				peerNetworkID = peer.NetworkBID
			case peer.NetworkBID == from.NetworkID:
				peerNetworkID = peer.NetworkAID
			default:
				continue
			}
			for _, s := range imp.Subnets {
				if s.NetworkID == peerNetworkID && cidrCovers(route.DestinationCIDR, s.CIDRBlock) {
					adjacency[from.CanonicalID] = append(adjacency[from.CanonicalID], s.CanonicalID)
				}
			}
		}
	}
	return adjacency
}

func cidrCovers(destinationCIDR, subnetCIDR string) bool {
	_, destNet, err := net.ParseCIDR(destinationCIDR)
	if err != nil {
		return false
	}
	ip, _, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return false
	}
	return destNet.Contains(ip)
}
