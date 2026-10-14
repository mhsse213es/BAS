package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/attackpath"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpath"
	"github.com/audspect/bas/internal/networkpolicy"
	"github.com/audspect/bas/internal/networktopology"
	"github.com/audspect/bas/internal/remoteaccess"
)

const maxRemoteAccessPathRequestBytes = 1 << 16

type remoteAccessPathRequest struct {
	TopologyImportID     string `json:"topologyImportId"`
	RemoteAccessImportID string `json:"remoteAccessImportId"`
	PolicyImportID       string `json:"policyImportId,omitempty"`
	DiscoveryRunID       string `json:"discoveryRunId,omitempty"`
	SourceHost           string `json:"sourceHost"`
	DestHost             string `json:"destHost"`
	Port                 int    `json:"port"`
	Protocol             string `json:"protocol,omitempty"`
	MaxHops              int    `json:"maxHops,omitempty"`
}

// remoteAccessPathResponse mirrors networkPathResponse's shape, with
// TransitViolations attached additively -- never altering a result's
// State.
type remoteAccessPathResponse struct {
	Results           []networkpath.PathResult       `json:"results"`
	SearchExhausted   bool                            `json:"searchExhausted,omitempty"`
	TransitViolations []remoteaccess.TransitViolation `json:"transitViolations,omitempty"`
}

// FindRemoteAccessPaths -- POST /api/remote-access-paths. Resolves
// sourceHost/destHost to zones in the named network-topology import,
// finds candidate routes over the combined physical-edge/VPN-tunnel
// graph, composes+aggregates each one's evidence by reusing
// networkpath.ComposeHop/AggregatePath directly (unmodified -- spec
// §5), and separately validates every found route against the named
// remote-access import's MandatoryTransit rules.
func (h *Handler) FindRemoteAccessPaths(w http.ResponseWriter, r *http.Request) {
	var req remoteAccessPathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRemoteAccessPathRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TopologyImportID == "" || req.RemoteAccessImportID == "" || req.SourceHost == "" || req.DestHost == "" || req.Port == 0 {
		jsonError(w, "topologyImportId, remoteAccessImportId, sourceHost, destHost, and port are all required", http.StatusBadRequest)
		return
	}

	topo, err := db.GetNetworkTopologyImport(r.Context(), h.db, req.TopologyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	remote, err := db.GetRemoteAccessImport(r.Context(), h.db, req.RemoteAccessImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "remote access import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sourceZone, err := networktopology.ZoneForHost(req.SourceHost, topo.Zones)
	if err != nil {
		jsonError(w, "sourceHost: "+err.Error(), http.StatusBadRequest)
		return
	}
	destZone, err := networktopology.ZoneForHost(req.DestHost, topo.Zones)
	if err != nil {
		jsonError(w, "destHost: "+err.Error(), http.StatusBadRequest)
		return
	}

	var policyImport *networkpolicy.PolicyImport
	if req.PolicyImportID != "" {
		policyImport, err = db.GetNetworkPolicyImport(r.Context(), h.db, req.PolicyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "network policy import not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
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

	g := attackpath.BuildGraph(h.loadAttackPathCollections(r)...)

	routes, exhausted, err := remoteaccess.FindCandidateRemoteAccessRoutes(topo, remote, sourceZone, destZone, req.MaxHops)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var results []networkpath.PathResult
	if len(routes) == 0 {
		hop := h.composeRemoteAccessPathHop(sourceZone, destZone, false, policyImport, req, observations, g, true)
		results = append(results, networkpath.AggregatePath([]networkpath.HopResult{hop}))
	} else {
		for _, route := range routes {
			singleHop := len(route) == 2
			hops := make([]networkpath.HopResult, 0, len(route)-1)
			for i := 0; i < len(route)-1; i++ {
				hop := h.composeRemoteAccessPathHop(route[i], route[i+1], true, policyImport, req, observations, g, singleHop)
				hops = append(hops, hop)
			}
			results = append(results, networkpath.AggregatePath(hops))
		}
	}

	violations := remoteaccess.ValidateMandatoryTransit(routes, remote.Transits)

	respond(w, remoteAccessPathResponse{Results: results, SearchExhausted: exhausted, TransitViolations: violations})
}

// composeRemoteAccessPathHop mirrors internal/api/networkpath_handlers.go's
// composeNetworkPathHop exactly -- the policy/observation/corroboration
// composition logic is identical regardless of whether routeDeclared
// came from a physical RouteEdge or a VPN tunnel, since
// networkpath.ComposeHop does not distinguish the two.
func (h *Handler) composeRemoteAccessPathHop(fromZone, toZone string, routeDeclared bool, policyImport *networkpolicy.PolicyImport, req remoteAccessPathRequest, observations []networkgraph.NetworkObservation, g *attackpath.Graph, attachObservation bool) networkpath.HopResult {
	query := networkpolicy.PolicyQuery{SourceZone: fromZone, DestZone: toZone, Port: req.Port, Protocol: req.Protocol}
	if attachObservation {
		query.DestCIDR = req.DestHost + "/32"
		query.DestZone = ""
	}
	var policyEval *networkpolicy.PolicyEvaluation
	if policyImport != nil {
		evals, err := networkpolicy.EvaluatePolicyMatrix(policyImport, []networkpolicy.PolicyQuery{query})
		if err == nil && len(evals) == 1 {
			policyEval = &evals[0]
		}
	}

	var hopObservations []networkgraph.NetworkObservation
	if attachObservation {
		hopObservations = observations
	}

	hop := networkpath.ComposeHop(fromZone, toZone, routeDeclared, policyEval, hopObservations)
	if !attachObservation && len(observations) > 0 {
		note := "a discovery run was supplied, but Phase 1 only observes the vantage point's direct probe to the final destination host -- this intermediate hop has no real observation evidence available"
		if hop.Limitations == "" {
			hop.Limitations = note
		} else {
			hop.Limitations = hop.Limitations + "; " + note
		}
	}
	hop.Corroboration = networkpath.CorroborateSegmentation(g, fromZone, toZone)
	if attachObservation {
		hop.Corroboration = append(hop.Corroboration, networkpath.CorroborateHop(g, req.SourceHost, req.DestHost)...)
	}
	return hop
}
