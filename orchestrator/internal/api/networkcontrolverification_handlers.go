package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkefficacy"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// maxNetworkControlVerificationRequestBytes is larger than Phase 3's
// 64KiB path-query cap, since this body also carries inline firewall/
// IDS evidence arrays, not just a flow query.
const maxNetworkControlVerificationRequestBytes = 1 << 20

const (
	maxFirewallEvidencePerVerification = 2000
	maxIDSEvidencePerVerification      = 2000
)

// observationEvidenceCorrelationWindow bounds how far a piece of
// control-product evidence's own timestamp may fall from the
// NetworkObservation's ObservedAt and still count as evidence for the
// same test. A single bounded probe and the control's own log/alert
// for that same flow should be essentially simultaneous; this is
// generous enough to tolerate log-collection and clock skew in a lab
// run without being unbounded.
const observationEvidenceCorrelationWindow = time.Hour

// windowForObservation anchors the evidence-correlation window to when
// the test actually happened (obs.Provenance.ObservedAt), never to
// wall-clock time at request-processing time. A recorded-fixture's
// evidence carries its own historical timestamp near the observation,
// not near whenever POST /api/network-control-verifications happens to
// be called -- anchoring to time.Now() instead would silently fail to
// match genuinely corresponding evidence for any verify call more than
// observationEvidenceCorrelationWindow after the observation was taken.
func windowForObservation(obs networkgraph.NetworkObservation) networkefficacy.TimeWindow {
	return networkefficacy.TimeWindow{
		Start: obs.Provenance.ObservedAt.Add(-observationEvidenceCorrelationWindow),
		End:   obs.Provenance.ObservedAt.Add(observationEvidenceCorrelationWindow),
	}
}

type networkControlVerificationRequest struct {
	ExpectationImportID string                             `json:"expectationImportId"`
	DiscoveryRunID      string                             `json:"discoveryRunId"`
	PolicyImportID      string                             `json:"policyImportId,omitempty"`
	FirewallEvidence    []networkefficacy.FirewallEvidence `json:"firewallEvidence,omitempty"`
	IDSEvidence         []networkefficacy.IDSEvidence      `json:"idsEvidence,omitempty"`
}

// VerifyNetworkControlExpectations -- POST /api/network-control-verifications.
// Correlates every expectation in the named import against inline-
// supplied, normalized firewall/IDS evidence and Network BAS's own
// Phase 1 observations (+ optional Phase 2A policy evaluation). Not
// persisted -- computed fresh on every call, same pattern as
// FindNetworkPaths.
func (h *Handler) VerifyNetworkControlExpectations(w http.ResponseWriter, r *http.Request) {
	var req networkControlVerificationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkControlVerificationRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.ExpectationImportID == "" || req.DiscoveryRunID == "" {
		jsonError(w, "expectationImportId and discoveryRunId are required", http.StatusBadRequest)
		return
	}
	if len(req.FirewallEvidence) > maxFirewallEvidencePerVerification {
		jsonError(w, "too many firewallEvidence entries", http.StatusBadRequest)
		return
	}
	if len(req.IDSEvidence) > maxIDSEvidencePerVerification {
		jsonError(w, "too many idsEvidence entries", http.StatusBadRequest)
		return
	}

	expImport, err := db.GetNetworkControlExpectationImport(r.Context(), h.db, req.ExpectationImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network control expectation import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, req.DiscoveryRunID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network discovery run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	observations, err := db.ListNetworkObservationsByRun(r.Context(), h.db, req.DiscoveryRunID)
	if err != nil {
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

	firewallProvider := networkefficacy.NewSyntheticFirewallProvider(req.FirewallEvidence)
	idsProvider := networkefficacy.NewFixtureIDSProvider(req.IDSEvidence)

	results := make([]networkefficacy.EfficacyResult, 0, len(expImport.Expectations))
	for _, exp := range expImport.Expectations {
		obs, found := selectMatchingObservation(exp, observations)
		if !found {
			results = append(results, networkefficacy.EfficacyResult{
				Expectation: exp,
				Verdict:     networkefficacy.VerdictInconclusive,
				Reason:      "no corresponding Network BAS observation found for this flow in the specified discovery run",
			})
			continue
		}
		window := windowForObservation(obs)

		var policyEval *networkpolicy.PolicyEvaluation
		if policyImport != nil {
			evals, err := networkpolicy.EvaluatePolicyMatrix(policyImport, []networkpolicy.PolicyQuery{{SourceCIDR: exp.FlowSourceCIDR, DestCIDR: exp.FlowDestCIDR, Port: exp.FlowPort, Protocol: exp.FlowProtocol}})
			if err == nil && len(evals) == 1 {
				policyEval = &evals[0]
			}
		}

		results = append(results, networkefficacy.VerifyControlExpectation(exp, obs, policyEval, firewallProvider, idsProvider, window))
	}

	respond(w, results)
}

// selectMatchingObservation finds the NetworkObservation whose Target
// falls within exp's declared flow (dest-CIDR containment, exact port,
// case-insensitive protocol). When more than one matches, the one with
// the most recent Provenance.ObservedAt wins -- same "latest wins" rule
// orchestration.go applies to evidence selection, for the same reason.
// Duplicates the small CIDR-containment check already duplicated
// independently in internal/networktopology and
// internal/networkpolicy; this package has no dependency on either.
func selectMatchingObservation(exp networkefficacy.ControlExpectation, observations []networkgraph.NetworkObservation) (networkgraph.NetworkObservation, bool) {
	var best networkgraph.NetworkObservation
	found := false
	for _, obs := range observations {
		if obs.Target.Port != exp.FlowPort {
			continue
		}
		if !destCIDRContains(exp.FlowDestCIDR, obs.Target.Host) {
			continue
		}
		if !found || obs.Provenance.ObservedAt.After(best.Provenance.ObservedAt) {
			best = obs
			found = true
		}
	}
	return best, found
}

func destCIDRContains(cidr, host string) bool {
	if cidr == "" || host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}
