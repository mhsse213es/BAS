package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/cloudpath"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
)

const maxCloudPathRequestBytes = 1 << 16

type cloudPathRequest struct {
	TopologyImportID string `json:"topologyImportId"`
	DiscoveryRunID   string `json:"discoveryRunId,omitempty"`
	SourceHost       string `json:"sourceHost"`
	DestHost         string `json:"destHost"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol,omitempty"`
	MaxHops          int    `json:"maxHops,omitempty"`
}

// cloudPathResponse mirrors networkPathResponse's shape exactly,
// including the omitempty on SearchExhausted (see
// internal/api/networkpath_handlers.go).
type cloudPathResponse struct {
	Results         []cloudpath.CloudPathResult `json:"results"`
	SearchExhausted bool                        `json:"searchExhausted,omitempty"`
}

// FindCloudPaths -- POST /api/cloud-paths. Resolves sourceHost/
// destHost to subnets in the named topology import, finds candidate
// routes, evaluates security groups (both the source's outbound rules
// and the destination's inbound rules -- real security groups
// enforce both independently) per hop, and composes+aggregates each
// one's evidence. Not persisted -- computed fresh on every call from
// already-persisted evidence sources, exactly as FindNetworkPaths
// does for the on-premises domain.
func (h *Handler) FindCloudPaths(w http.ResponseWriter, r *http.Request) {
	var req cloudPathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCloudPathRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TopologyImportID == "" || req.SourceHost == "" || req.DestHost == "" || req.Port == 0 {
		jsonError(w, "topologyImportId, sourceHost, destHost, and port are all required", http.StatusBadRequest)
		return
	}

	topo, err := db.GetCloudTopologyImport(r.Context(), h.db, req.TopologyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "cloud topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sourceSubnet, err := cloudtopology.SubnetForHost(req.SourceHost, topo.Subnets)
	if err != nil {
		jsonError(w, "sourceHost: "+err.Error(), http.StatusBadRequest)
		return
	}
	destSubnet, err := cloudtopology.SubnetForHost(req.DestHost, topo.Subnets)
	if err != nil {
		jsonError(w, "destHost: "+err.Error(), http.StatusBadRequest)
		return
	}

	var observations []networkgraph.NetworkObservation
	if req.DiscoveryRunID != "" {
		if _, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, req.DiscoveryRunID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "network discovery run not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		observations, err = db.ListNetworkObservationsByRun(r.Context(), h.db, req.DiscoveryRunID)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	routes, exhausted, err := cloudtopology.FindCandidateCloudRoutes(topo, sourceSubnet, destSubnet, req.MaxHops)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var results []cloudpath.CloudPathResult
	if len(routes) == 0 {
		hop := h.composeCloudPathHop(topo, sourceSubnet, destSubnet, false, req, observations, true, true)
		results = append(results, cloudpath.AggregateCloudPath([]cloudpath.CloudHopResult{hop}))
	} else {
		for _, route := range routes {
			var hops []cloudpath.CloudHopResult
			if len(route) == 1 {
				// Trivial same-subnet route (sourceHost and destHost
				// resolve to the same subnet): there is no inter-subnet
				// hop, but real security groups still enforce
				// intra-subnet traffic at the instance/ENI level, so
				// this is evaluated as one self-referential hop rather
				// than silently returning nothing.
				hop := h.composeCloudPathHop(topo, route[0], route[0], true, req, observations, true, true)
				hops = []cloudpath.CloudHopResult{hop}
			} else {
				hops = make([]cloudpath.CloudHopResult, 0, len(route)-1)
				for i := 0; i < len(route)-1; i++ {
					isFirstHop := i == 0
					isLastHop := i == len(route)-2
					hop := h.composeCloudPathHop(topo, route[i], route[i+1], true, req, observations, isFirstHop, isLastHop)
					hops = append(hops, hop)
				}
			}
			results = append(results, cloudpath.AggregateCloudPath(hops))
		}
	}

	respond(w, cloudPathResponse{Results: results, SearchExhausted: exhausted})
}

// composeCloudPathHop evaluates security-group policy for one
// fromSubnet->toSubnet hop from BOTH sides -- the source's own
// outbound (egress) rules and the destination's own inbound
// (ingress) rules, since real security groups enforce each
// independently -- and composes the evidence. isFirstHop/isLastHop
// gate both CIDR resolution and observation correlation:
//
//   - Phase 1 only ever observes "vantage point -> destination host"
//     directly, never an arbitrary intermediate hop, so observation
//     correlation is only ever eligible when the entire candidate
//     route is exactly one hop (isFirstHop && isLastHop) -- mirroring
//     internal/api/networkpath_handlers.go's composeNetworkPathHop
//     exactly.
//   - When isFirstHop is false, the flow's source CIDR is the current
//     fromSubnet's own CIDR block, not the literal sourceHost -- an
//     intermediate hop's traffic originates from the upstream subnet,
//     not necessarily the original caller-supplied host. Symmetrically
//     for isLastHop and the destination CIDR.
func (h *Handler) composeCloudPathHop(topo *cloudtopology.CloudTopologyImport, fromSubnet, toSubnet string, routeFound bool, req cloudPathRequest, observations []networkgraph.NetworkObservation, isFirstHop, isLastHop bool) cloudpath.CloudHopResult {
	flow := cloudtopology.CloudFlow{Port: req.Port, Protocol: req.Protocol}
	if isFirstHop {
		flow.SourceCIDR = req.SourceHost + "/32"
	} else if cidr, ok := subnetCIDRByID(topo, fromSubnet); ok {
		flow.SourceCIDR = cidr
	} else {
		flow.SourceCIDR = req.SourceHost + "/32"
	}
	if isLastHop {
		flow.DestCIDR = req.DestHost + "/32"
	} else if cidr, ok := subnetCIDRByID(topo, toSubnet); ok {
		flow.DestCIDR = cidr
	} else {
		flow.DestCIDR = req.DestHost + "/32"
	}

	sourceEval, srcErr := cloudtopology.EvaluateSecurityGroupRules(topo, fromSubnet, cloudtopology.DirectionOutbound, flow)
	destEval, dstErr := cloudtopology.EvaluateSecurityGroupRules(topo, toSubnet, cloudtopology.DirectionInbound, flow)
	var sourceEvalPtr, destEvalPtr *cloudtopology.SecurityGroupEvaluation
	if srcErr == nil {
		sourceEvalPtr = &sourceEval
	}
	if dstErr == nil {
		destEvalPtr = &destEval
	}

	attachObservation := isFirstHop && isLastHop
	var hopObservations []networkgraph.NetworkObservation
	if attachObservation {
		hopObservations = observations
	}
	hop := cloudpath.ComposeCloudHop(fromSubnet, toSubnet, routeFound, sourceEvalPtr, destEvalPtr, hopObservations)
	if !attachObservation && len(observations) > 0 {
		note := "a discovery run was supplied, but Phase 1 only observes the vantage point's direct probe to the final destination host -- this intermediate hop has no real observation evidence available"
		if hop.Limitations == "" {
			hop.Limitations = note
		} else {
			hop.Limitations = hop.Limitations + "; " + note
		}
	}
	return hop
}

func subnetCIDRByID(topo *cloudtopology.CloudTopologyImport, subnetID string) (string, bool) {
	for _, s := range topo.Subnets {
		if s.CanonicalID == subnetID {
			return s.CIDRBlock, true
		}
	}
	return "", false
}
