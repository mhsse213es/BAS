package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/cloudgraph"
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
		routes, pairExhausted, err := findCandidateRoutesBothDirections(topo, remote, pair.ZoneA, pair.ZoneB, req.MaxHops)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
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
			// Multiple candidate routes for the same pair are
			// INDEPENDENT alternatives, not sequential hops of one
			// path -- isolation is violated if ANY of them is
			// reachable, so the most severe alternative must win.
			// Deliberately NOT networkpath.AggregatePathState here:
			// that function's Blocked-short-circuit is correct only
			// for weakest-link aggregation across the sequential hops
			// of a SINGLE path, and would let an unrelated route's
			// confirmed denial hide a different route's demonstrated
			// breach.
			states := make([]cloudgraph.PathState, len(routeResults))
			for i, rr := range routeResults {
				states[i] = rr.State
			}
			worstState := worstAcrossAlternatives(states)
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

// findCandidateRoutesBothDirections finds candidate routes in both the
// zoneA->zoneB and zoneB->zoneA orientations and returns their union.
// ZonePairIsolation's own contract ("no network path between them at
// all, in either direction") requires this: networktopology.RouteEdge
// and remoteaccess.Tunnel can both be Directed, so a one-way leak (for
// example an outbound-only path out of a clinical zone) is only ever
// visible from one of the two query directions and must never be
// silently missed by only ever querying one.
func findCandidateRoutesBothDirections(topo *networktopology.TopologyImport, remote *remoteaccess.RemoteAccessImport, zoneA, zoneB string, maxHops int) ([][]string, bool, error) {
	var routes [][]string
	var exhausted bool
	for _, dir := range [2][2]string{{zoneA, zoneB}, {zoneB, zoneA}} {
		var oneDir [][]string
		var ex bool
		var err error
		if remote != nil {
			var raRoutes []remoteaccess.RoutePath
			raRoutes, ex, err = remoteaccess.FindCandidateRemoteAccessRoutes(topo, remote, dir[0], dir[1], maxHops)
			for _, route := range raRoutes {
				oneDir = append(oneDir, []string(route))
			}
		} else {
			var topoRoutes []networktopology.RoutePath
			topoRoutes, ex, err = networktopology.FindCandidateRoutes(topo, dir[0], dir[1], maxHops)
			for _, route := range topoRoutes {
				oneDir = append(oneDir, []string(route))
			}
		}
		if err != nil {
			return nil, false, err
		}
		if ex {
			exhausted = true
		}
		routes = append(routes, oneDir...)
	}
	return routes, exhausted, nil
}

// severityRank orders cloudgraph.PathState by how severe a confirmed
// isolation violation it would represent, for picking the worst among
// several independent alternative routes or CIDRs for the same zone
// pair. Unknown outranks Blocked because an unresolved alternative is
// not proof of isolation either -- "missing evidence is not evidence
// of isolation" applies here exactly as it does to a single route.
func severityRank(state cloudgraph.PathState) int {
	switch state {
	case cloudgraph.Observed:
		return 4
	case cloudgraph.PolicySupported, cloudgraph.Candidate, cloudgraph.ConditionallyReachable:
		return 3
	case cloudgraph.Unknown:
		return 2
	case cloudgraph.Blocked:
		return 1
	default:
		return 2
	}
}

// worstAcrossAlternatives returns the single most severe state among
// several independent alternatives, per severityRank.
func worstAcrossAlternatives(states []cloudgraph.PathState) cloudgraph.PathState {
	worst := cloudgraph.Unknown
	worstRank := -1
	for _, s := range states {
		if r := severityRank(s); r > worstRank {
			worstRank = r
			worst = s
		}
	}
	return worst
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
	// Multiple declared CIDRs for the same destination zone are also
	// independent alternatives -- same worst-across-alternatives
	// reasoning as the multi-route picker above, not
	// networkpath.AggregatePathState's single-path ranking.
	states := make([]cloudgraph.PathState, len(perCIDRHops))
	for i, hop := range perCIDRHops {
		states[i] = hop.State
	}
	worstState := worstAcrossAlternatives(states)
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
