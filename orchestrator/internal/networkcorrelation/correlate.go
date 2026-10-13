// Package networkcorrelation is the one place Network BAS policy evidence
// (internal/networkpolicy) and reachability evidence (internal/networkgraph)
// are allowed to meet. Both evidence packages import only cloudgraph;
// neither imports the other or this package -- correlation is a
// reporting-layer join, never an inference baked into either evidence
// domain.
package networkcorrelation

import (
	"net"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// ComparisonLabel never implies a security verdict stronger than "these
// two independently-collected pieces of evidence agree" or "disagree" --
// DiscrepancyUnenforcedDeny in particular means "the parsed policy and
// the live test disagree," never "confirmed vulnerability": the policy
// input may itself be a stale or imperfect translation.
type ComparisonLabel string

const (
	ConsistentAllow            ComparisonLabel = "consistent-allow"
	DiscrepancyUnexpectedBlock ComparisonLabel = "discrepancy-unexpected-block"
	DiscrepancyUnenforcedDeny  ComparisonLabel = "discrepancy-unenforced-deny"
	ConsistentDeny             ComparisonLabel = "consistent-deny"
	Untested                   ComparisonLabel = "untested"
	PolicyInconclusive         ComparisonLabel = "policy-inconclusive"
)

// ReachabilityComparison pairs one PolicyEvaluation with the
// NetworkObservation (if any) that corroborates or contradicts it.
type ReachabilityComparison struct {
	Evaluation  networkpolicy.PolicyEvaluation    `json:"evaluation"`
	Observation *networkgraph.NetworkObservation `json:"observation,omitempty"`
	Label       ComparisonLabel                   `json:"label"`
}

// CorrelateReachability joins each evaluation to the observation (if any)
// whose Target falls inside the evaluation's destination CIDR on the same
// port, and labels the pair. Neither evaluations' nor observations' own
// States are re-derived here -- only compared.
func CorrelateReachability(evaluations []networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) []ReachabilityComparison {
	out := make([]ReachabilityComparison, len(evaluations))
	for i, ev := range evaluations {
		o := findMatchingObservation(ev, observations)
		out[i] = ReachabilityComparison{Evaluation: ev, Observation: o, Label: labelFor(ev.State, o)}
	}
	return out
}

// findMatchingObservation only correlates against a query's direct
// DestCIDR -- a zone-named destination has no single host to match
// against an observation's Target.Host. A non-IP Target.Host (Phase 1
// never requires a literal IP) fails net.ParseIP and is treated as no
// match, honestly: Phase 2A performs no DNS resolution.
func findMatchingObservation(ev networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) *networkgraph.NetworkObservation {
	if ev.Query.DestCIDR == "" {
		return nil
	}
	_, destNet, err := net.ParseCIDR(ev.Query.DestCIDR)
	if err != nil {
		return nil
	}
	for i := range observations {
		o := &observations[i]
		if o.Target.Port != ev.Query.Port {
			continue
		}
		ip := net.ParseIP(o.Target.Host)
		if ip == nil || !destNet.Contains(ip) {
			continue
		}
		return o
	}
	return nil
}

func labelFor(policyState cloudgraph.PathState, obs *networkgraph.NetworkObservation) ComparisonLabel {
	if policyState == cloudgraph.Unknown {
		return PolicyInconclusive
	}
	if obs == nil || obs.State == cloudgraph.Unknown {
		return Untested
	}
	switch {
	case policyState == cloudgraph.PolicySupported && obs.State == cloudgraph.Observed:
		return ConsistentAllow
	case policyState == cloudgraph.PolicySupported && obs.State == cloudgraph.Blocked:
		return DiscrepancyUnexpectedBlock
	case policyState == cloudgraph.Blocked && obs.State == cloudgraph.Observed:
		return DiscrepancyUnenforcedDeny
	case policyState == cloudgraph.Blocked && obs.State == cloudgraph.Blocked:
		return ConsistentDeny
	default:
		return Untested
	}
}
