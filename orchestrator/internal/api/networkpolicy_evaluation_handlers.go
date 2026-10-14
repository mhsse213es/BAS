package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkcorrelation"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

const maxNetworkPolicyEvaluationRequestBytes = 1 << 20

// EvaluateNetworkPolicy -- POST /api/network-policy-evaluations. Loads an
// already-persisted policy import and evaluates a caller-supplied query
// batch against it. Computed fresh on every call -- nothing here is
// persisted.
func (h *Handler) EvaluateNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PolicyImportID string                      `json:"policyImportId"`
		Queries        []networkpolicy.PolicyQuery `json:"queries"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkPolicyEvaluationRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PolicyImportID == "" {
		jsonError(w, "policyImportId is required", http.StatusBadRequest)
		return
	}
	imp, err := db.GetNetworkPolicyImport(r.Context(), h.db, req.PolicyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network policy import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	evaluations, err := networkpolicy.EvaluatePolicyMatrix(imp, req.Queries)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	respond(w, evaluations)
}

// GetNetworkReachabilityComparison -- GET /api/network-reachability-comparisons.
// Derives one PolicyQuery per observation in the named discovery run (its
// Target.Host as a /32 destination, keeping the comparison apples-to-
// apples with exactly what Phase 1 actually probed, never a caller-
// supplied, possibly-mismatched query list), evaluates them against the
// named policy import, and correlates. Not persisted -- recomputed fresh
// on every call from the two already-persisted evidence sources.
func (h *Handler) GetNetworkReachabilityComparison(w http.ResponseWriter, r *http.Request) {
	policyImportID := r.URL.Query().Get("policyImportId")
	discoveryRunID := r.URL.Query().Get("discoveryRunId")
	if policyImportID == "" || discoveryRunID == "" {
		jsonError(w, "policyImportId and discoveryRunId are both required", http.StatusBadRequest)
		return
	}

	imp, err := db.GetNetworkPolicyImport(r.Context(), h.db, policyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network policy import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, discoveryRunID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network discovery run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	observations, err := db.ListNetworkObservationsByRun(r.Context(), h.db, discoveryRunID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(observations) == 0 {
		respond(w, []networkcorrelation.ReachabilityComparison{})
		return
	}

	queries := queriesFromObservations(observations)
	evaluations, err := networkpolicy.EvaluatePolicyMatrix(imp, queries)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	comparisons := networkcorrelation.CorrelateReachability(evaluations, observations)
	respond(w, comparisons)
}

// queriesFromObservations turns each observation's target into a direct
// /32-CIDR destination query. A non-IP Target.Host produces an invalid
// CIDR string here, which EvaluatePolicyMatrix's own resolution will
// reject into an Unknown result for that one query -- not a crash --
// since Phase 2A performs no DNS resolution (see networkcorrelation's
// own doc comment for the matching half of this same honesty rule).
//
// SourceCIDR is set to the wildcard "0.0.0.0/0": Phase 1's evidence model
// records where a probe landed, never where it was launched from as a
// CIDR, so there is no real source CIDR to carry over. Treating the
// source as unconstrained means the comparison is driven by the
// destination/port match a real vendor policy would key on, rather than
// forcing every comparison to Unknown for a dimension this evidence
// source cannot supply.
func queriesFromObservations(observations []networkgraph.NetworkObservation) []networkpolicy.PolicyQuery {
	out := make([]networkpolicy.PolicyQuery, len(observations))
	for i, o := range observations {
		out[i] = networkpolicy.PolicyQuery{SourceCIDR: "0.0.0.0/0", DestCIDR: o.Target.Host + "/32", Port: o.Target.Port, Protocol: o.Target.Protocol}
	}
	return out
}
