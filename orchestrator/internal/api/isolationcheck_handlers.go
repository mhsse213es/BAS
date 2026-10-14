package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpath"
	"github.com/audspect/bas/internal/networkpolicy"
	"github.com/audspect/bas/internal/networktopology"
	"github.com/audspect/bas/internal/remoteaccess"
	"github.com/audspect/bas/internal/zoneisolation"
)

const maxIsolationCheckRequestBytes = 1 << 16

type isolationCheckRequest struct {
	TopologyImportID     string `json:"topologyImportId"`
	IsolationImportID    string `json:"isolationImportId"`
	PolicyImportID       string `json:"policyImportId,omitempty"`
	DiscoveryRunID       string `json:"discoveryRunId,omitempty"`
	RemoteAccessImportID string `json:"remoteAccessImportId,omitempty"`
	Port                 int    `json:"port,omitempty"`
	Protocol             string `json:"protocol,omitempty"`
	MaxHops              int    `json:"maxHops,omitempty"`
}

type isolationCheckResponse struct {
	Results         []zoneisolation.IsolationCheckResult `json:"results"`
	SearchExhausted bool                                  `json:"searchExhausted,omitempty"`
}

// FindIsolationChecks -- POST /api/isolation-checks. Checks every
// declared ZonePairIsolation in the named isolation import against
// Phase 3's existing routing/policy/observation evidence (and
// Phase 6B's remote-access tunnels, when supplied), classifying each
// pair via zoneisolation.ClassifyIsolation. Not persisted -- computed
// fresh on every call from already-persisted evidence sources, same
// as FindNetworkPaths.
func (h *Handler) FindIsolationChecks(w http.ResponseWriter, r *http.Request) {
	var req isolationCheckRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxIsolationCheckRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TopologyImportID == "" || req.IsolationImportID == "" {
		jsonError(w, "topologyImportId and isolationImportId are both required", http.StatusBadRequest)
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

	isolationImport, err := db.GetZoneIsolationImport(r.Context(), h.db, req.IsolationImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "zone isolation import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
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

	var remote *remoteaccess.RemoteAccessImport
	if req.RemoteAccessImportID != "" {
		remote, err = db.GetRemoteAccessImport(r.Context(), h.db, req.RemoteAccessImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "remote access import not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	var results []zoneisolation.IsolationCheckResult
	var exhausted bool
	for _, pair := range isolationImport.ZonePairIsolations {
		var routes [][]string
		var pairExhausted bool
		if remote != nil {
			raRoutes, ex, err := remoteaccess.FindCandidateRemoteAccessRoutes(topo, remote, pair.ZoneA, pair.ZoneB, req.MaxHops)
			if err != nil {
				jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
			pairExhausted = ex
			for _, route := range raRoutes {
				routes = append(routes, []string(route))
			}
		} else {
			topoRoutes, ex, err := networktopology.FindCandidateRoutes(topo, pair.ZoneA, pair.ZoneB, req.MaxHops)
			if err != nil {
				jsonError(w, err.Error(), http.StatusBadRequest)
				return
			}
			pairExhausted = ex
			for _, route := range topoRoutes {
				routes = append(routes, []string(route))
			}
		}
		if pairExhausted {
			exhausted = true
		}

		var pathResult networkpath.PathResult
		if len(routes) == 0 {
			hop := composeIsolationHop(pair.ZoneA, pair.ZoneB, false, false, policyImport, req, observations, topo.Zones)
			pathResult = networkpath.AggregatePath([]networkpath.HopResult{hop})
		} else {
			var routeResults []networkpath.PathResult
			for _, route := range routes {
				singleHop := len(route) == 2
				hops := make([]networkpath.HopResult, 0, len(route)-1)
				for i := 0; i < len(route)-1; i++ {
					isLastHop := i == len(route)-2
					hop := composeIsolationHop(route[i], route[i+1], true, singleHop && isLastHop, policyImport, req, observations, topo.Zones)
					hops = append(hops, hop)
				}
				routeResults = append(routeResults, networkpath.AggregatePath(hops))
			}
			// Multiple candidate routes for the same pair: pick the
			// worst (most severe) one, same ranking AggregatePathState
			// already implements -- mirrors how a single route's own
			// hops are aggregated, one level up.
			worstState := networkpath.AggregatePathState(flattenHops(routeResults))
			for _, rr := range routeResults {
				if rr.State == worstState {
					pathResult = rr
					break
				}
			}
		}

		results = append(results, zoneisolation.ClassifyIsolation(pair, pathResult))
	}

	respond(w, isolationCheckResponse{Results: results, SearchExhausted: exhausted})
}

// flattenHops collects every hop across several already-aggregated
// PathResults, so their states can be ranked together via the same
// AggregatePathState worst-state logic multiple candidate routes
// already use within one route's own hops.
func flattenHops(results []networkpath.PathResult) []networkpath.HopResult {
	var hops []networkpath.HopResult
	for _, r := range results {
		hops = append(hops, networkpath.HopResult{State: r.State})
	}
	return hops
}

// composeIsolationHop composes one hop's evidence for the isolation
// check. attachObservation is only ever true for a single-hop route's
// one hop (mirrors composeNetworkPathHop's own identical boundary --
// Phase 1 observations are vantage-point-to-single-host, never
// zone-wide, so correlation is only attempted when the candidate route
// is exactly one hop). zones is the topology import's own declared
// zones, threaded explicitly from the caller's already-loaded topo.Zones
// -- the same "pass what's needed as a parameter" pattern
// composeNetworkPathHop itself uses for g *attackpath.Graph, rather than
// reaching for Handler state that doesn't exist for this purpose.
func composeIsolationHop(fromZone, toZone string, routeDeclared, attachObservation bool, policyImport *networkpolicy.PolicyImport, req isolationCheckRequest, observations []networkgraph.NetworkObservation, zones []networktopology.Zone) networkpath.HopResult {
	if !attachObservation || len(observations) == 0 {
		query := networkpolicy.PolicyQuery{SourceZone: fromZone, DestZone: toZone, Port: req.Port, Protocol: req.Protocol}
		var policyEval *networkpolicy.PolicyEvaluation
		if policyImport != nil {
			evals, err := networkpolicy.EvaluatePolicyMatrix(policyImport, []networkpolicy.PolicyQuery{query})
			if err == nil && len(evals) == 1 {
				policyEval = &evals[0]
			}
		}
		return networkpath.ComposeHop(fromZone, toZone, routeDeclared, policyEval, nil)
	}

	cidrs := zoneCIDRs(zones, toZone)
	if len(cidrs) == 0 {
		query := networkpolicy.PolicyQuery{SourceZone: fromZone, DestZone: toZone, Port: req.Port, Protocol: req.Protocol}
		var policyEval *networkpolicy.PolicyEvaluation
		if policyImport != nil {
			evals, err := networkpolicy.EvaluatePolicyMatrix(policyImport, []networkpolicy.PolicyQuery{query})
			if err == nil && len(evals) == 1 {
				policyEval = &evals[0]
			}
		}
		return networkpath.ComposeHop(fromZone, toZone, routeDeclared, policyEval, nil)
	}

	perCIDRHops := make([]networkpath.HopResult, 0, len(cidrs))
	for _, cidr := range cidrs {
		query := networkpolicy.PolicyQuery{SourceZone: fromZone, DestCIDR: cidr, Port: req.Port, Protocol: req.Protocol}
		var policyEval *networkpolicy.PolicyEvaluation
		if policyImport != nil {
			evals, err := networkpolicy.EvaluatePolicyMatrix(policyImport, []networkpolicy.PolicyQuery{query})
			if err == nil && len(evals) == 1 {
				policyEval = &evals[0]
			}
		}
		perCIDRHops = append(perCIDRHops, networkpath.ComposeHop(fromZone, toZone, routeDeclared, policyEval, observations))
	}
	worstState := networkpath.AggregatePathState(perCIDRHops)
	for _, hop := range perCIDRHops {
		if hop.State == worstState {
			return hop
		}
	}
	return perCIDRHops[0]
}

// zoneCIDRs returns the declared CIDRs for the named zone within
// zones, or nil if the zone isn't found or declares none.
func zoneCIDRs(zones []networktopology.Zone, name string) []string {
	for _, z := range zones {
		if z.Name == name {
			return z.CIDRs
		}
	}
	return nil
}
