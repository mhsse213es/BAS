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
	"github.com/audspect/bas/internal/otsafety"
)

const maxNetworkPathRequestBytes = 1 << 16

type networkPathRequest struct {
	TopologyImportID string `json:"topologyImportId"`
	PolicyImportID   string `json:"policyImportId,omitempty"`
	DiscoveryRunID   string `json:"discoveryRunId,omitempty"`
	OTSafetyImportID string `json:"otSafetyImportId,omitempty"`
	SourceHost       string `json:"sourceHost"`
	DestHost         string `json:"destHost"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol,omitempty"`
	MaxHops          int    `json:"maxHops,omitempty"`
}

// FindNetworkPaths -- POST /api/network-paths. Resolves sourceHost/
// destHost to zones in the named topology import, finds candidate
// routes, and composes+aggregates each one's evidence. Not persisted --
// computed fresh on every call from already-persisted evidence sources.
func (h *Handler) FindNetworkPaths(w http.ResponseWriter, r *http.Request) {
	var req networkPathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkPathRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TopologyImportID == "" || req.SourceHost == "" || req.DestHost == "" || req.Port == 0 {
		jsonError(w, "topologyImportId, sourceHost, destHost, and port are all required", http.StatusBadRequest)
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

	routes, exhausted, err := networktopology.FindCandidateRoutes(topo, sourceZone, destZone, req.MaxHops)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var transitViolations []otsafety.TransitViolation
	if req.OTSafetyImportID != "" {
		safety, err := db.GetOTSafetyImport(r.Context(), h.db, req.OTSafetyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "ot safety import not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		transitViolations = otsafety.ValidateRequiredTransits(routes, safety.RequiredTransits)
	}

	var results []networkpath.PathResult
	if len(routes) == 0 {
		// No declared route at all: still evaluate policy directly for
		// the source/dest zone pair (per the spec's own table -- "policy
		// permits it, but the route is unproven or absent" is still a
		// meaningful, distinct result from silence).
		hop := h.composeNetworkPathHop(sourceZone, destZone, false, policyImport, req, observations, g, true)
		results = append(results, networkpath.AggregatePath([]networkpath.HopResult{hop}))
	} else {
		for _, route := range routes {
			singleHop := len(route) == 2
			hops := make([]networkpath.HopResult, 0, len(route)-1)
			for i := 0; i < len(route)-1; i++ {
				hop := h.composeNetworkPathHop(route[i], route[i+1], true, policyImport, req, observations, g, singleHop)
				hops = append(hops, hop)
			}
			results = append(results, networkpath.AggregatePath(hops))
		}
	}

	respond(w, networkPathResponse{Results: results, SearchExhausted: exhausted, TransitViolations: transitViolations})
}

// networkPathResponse is the body of POST /api/network-paths.
// SearchExhausted is true when the candidate-route search hit its
// defensive step budget before it could either find the capped number
// of routes or exhaustively rule out more -- a zero-route Results with
// SearchExhausted=true means "truncated search, absence not proven",
// never the same finding as a zero-route Results with it false (search
// space fully explored, no route exists). Omitted when false, since
// that is the overwhelmingly common case.
type networkPathResponse struct {
	Results           []networkpath.PathResult    `json:"results"`
	SearchExhausted   bool                        `json:"searchExhausted,omitempty"`
	TransitViolations []otsafety.TransitViolation `json:"transitViolations,omitempty"`
}

// composeNetworkPathHop evaluates policy for one fromZone->toZone hop
// (if a policy import was supplied) and composes its evidence.
// attachObservation gates both observation correlation and host-based
// attackpath corroboration: Phase 1 only ever observes "vantage point ->
// destination host" directly, never an arbitrary intermediate hop, so
// both are only ever eligible when the entire candidate route is
// exactly one hop (the literal sourceHost/destHost the caller supplied).
// Zone-name segmentation corroboration has no such constraint and is
// attempted for every hop. When the caller supplied observations but
// this hop structurally cannot use them (a multi-hop route's hop), the
// hop's Limitations says so explicitly rather than silently omitting
// the observation -- a caller who asked for live-evidence correlation
// should never have to guess why a hop has none.
func (h *Handler) composeNetworkPathHop(fromZone, toZone string, routeDeclared bool, policyImport *networkpolicy.PolicyImport, req networkPathRequest, observations []networkgraph.NetworkObservation, g *attackpath.Graph, attachObservation bool) networkpath.HopResult {
	// The single-hop case's destination is the caller's own literal
	// destHost -- querying by its concrete /32 CIDR (rather than the
	// zone name) is what lets networkcorrelation's host/port matching
	// inside ComposeHop actually find the real observation.
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
