package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/cloudgraph"
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
	evaluations = discardSourcelessMatches(evaluations, imp.Zones)
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
// SourceCIDR is set to the wildcard "0.0.0.0/0" purely so
// EvaluatePolicyMatrix has something resolvable to run against -- Phase
// 1's evidence model records where a probe landed, never where it was
// launched from as a CIDR. This wildcard is NOT real evidence that the
// probe's source was actually unconstrained: discardSourcelessMatches,
// below, strips out any match this synthesized value produced against a
// genuinely source-restricted rule, so a narrow "allow from the admin
// subnet" rule can never be satisfied by a source we never observed.
func queriesFromObservations(observations []networkgraph.NetworkObservation) []networkpolicy.PolicyQuery {
	out := make([]networkpolicy.PolicyQuery, len(observations))
	for i, o := range observations {
		out[i] = networkpolicy.PolicyQuery{SourceCIDR: "0.0.0.0/0", DestCIDR: o.Target.Host + "/32", Port: o.Target.Port, Protocol: o.Target.Protocol}
	}
	return out
}

// discardSourcelessMatches overrides any evaluation whose MatchedRule
// genuinely restricts its source side (a named zone, or a CIDR narrower
// than the full address space) to Unknown. queriesFromObservations' own
// query source is a synthetic "0.0.0.0/0" wildcard, not real evidence --
// without this, EvaluatePolicyMatrix's ordinary CIDR-overlap containment
// check (which treats "0.0.0.0/0" as overlapping everything) lets that
// wildcard satisfy any source-restricted rule regardless of how narrow
// it is, silently discarding exactly the information a real segmented
// policy uses to differentiate traffic. A rule whose source is itself
// declared unconstrained (a literal "0.0.0.0/0" CIDR, or a zone whose
// CIDRs include one) is real policy evidence and is left untouched, as
// is the default-policy fallback (no MatchedRule), which never depended
// on source in the first place.
func discardSourcelessMatches(evaluations []networkpolicy.PolicyEvaluation, zones []networkpolicy.Zone) []networkpolicy.PolicyEvaluation {
	out := make([]networkpolicy.PolicyEvaluation, len(evaluations))
	for i, ev := range evaluations {
		if ev.MatchedRule != nil && !ruleSourceIsUnrestricted(ev.MatchedRule, zones) {
			ev.State = cloudgraph.Unknown
			ev.Limitations = "matched rule's source side is restricted, but this comparison has no real evidence of the probe's actual source zone or CIDR -- cannot confirm or refute that this rule applies"
		}
		out[i] = ev
	}
	return out
}

// ruleSourceIsUnrestricted reports whether rule's source side is itself
// declared as "from anywhere" by the policy author -- a literal
// "0.0.0.0/0" CIDR, or a named zone whose CIDRs include one. Anything
// else (a named zone whose CIDRs don't, or a narrower CIDR) is
// source-restricted. Fails safe: an unresolvable zone reference or an
// unparseable CIDR is treated as restricted, never as unrestricted.
func ruleSourceIsUnrestricted(rule *networkpolicy.Rule, zones []networkpolicy.Zone) bool {
	if rule.SourceCIDR != "" {
		return cidrIsUnrestricted(rule.SourceCIDR)
	}
	if rule.SourceZone != "" {
		for _, z := range zones {
			if z.Name != rule.SourceZone {
				continue
			}
			for _, c := range z.CIDRs {
				if cidrIsUnrestricted(c) {
					return true
				}
			}
		}
	}
	return false
}

func cidrIsUnrestricted(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ones, _ := ipNet.Mask.Size()
	return ones == 0
}
