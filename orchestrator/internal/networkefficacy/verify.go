package networkefficacy

import (
	"fmt"
	"sort"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// VerifyControlExpectation checks one declared expectation against the
// real control product's own evidence, correlating it with Network
// BAS's own flow evidence for the same flow. Independent of
// detectverify.VerifyRun by design -- no shared code path. Every
// failure mode resolves to Verdict: VerdictInconclusive with a Reason;
// this function never returns an error, matching ComposeHop's exact
// precedent (internal/networkpath/compose.go).
func VerifyControlExpectation(
	exp ControlExpectation,
	observation networkgraph.NetworkObservation,
	policyEval *networkpolicy.PolicyEvaluation,
	firewallProvider FirewallEvidenceProvider,
	idsProvider IDSEvidenceProvider,
	window TimeWindow,
) EfficacyResult {
	result := EfficacyResult{Expectation: exp, PolicyEval: policyEval, Observation: observation}
	flow := Flow{SourceCIDR: exp.FlowSourceCIDR, DestCIDR: exp.FlowDestCIDR, Port: exp.FlowPort, Protocol: exp.FlowProtocol}

	switch exp.ExpectedAction {
	case ExpectedBlock:
		records, err := firewallProvider.FirewallEvidenceFor(flow, window)
		if err != nil {
			result.Verdict = VerdictInconclusive
			result.Reason = fmt.Sprintf("firewall evidence collection failed: %v", err)
			return result
		}
		if len(records) == 0 {
			result.Verdict = VerdictInconclusive
			result.Reason = "no firewall log entry found for this flow; absence of a log entry is not proof of a permitted connection, since not every flow is guaranteed to be logged"
			return result
		}
		latest := latestFirewallEvidence(records)
		result.FirewallEvidence = &latest
		if latest.Action == "block" {
			result.Verdict = VerdictMet
		} else {
			result.Verdict = VerdictNotMet
			result.Reason = "firewall evidence shows this flow was permitted, expected block"
		}
		result.Contradiction = detectContradiction(result.FirewallEvidence, observation)
		return result

	case ExpectedAlert:
		records, err := idsProvider.IDSEvidenceFor(flow, window)
		if err != nil {
			result.Verdict = VerdictInconclusive
			result.Reason = fmt.Sprintf("IDS evidence collection/parsing failed: %v", err)
			return result
		}
		if len(records) == 0 {
			result.Verdict = VerdictNotMet
			result.Reason = "no IDS alert found for this flow in the window; expected an alert to be raised"
			return result
		}
		latest := latestIDSEvidence(records)
		result.IDSEvidence = &latest
		result.Verdict = VerdictMet
		return result

	default:
		result.Verdict = VerdictInconclusive
		result.Reason = fmt.Sprintf("unknown expected control action %q", exp.ExpectedAction)
		return result
	}
}

// latestFirewallEvidence returns the record with the latest Timestamp
// -- a later event reflects the control's final state for a flow more
// faithfully than an earlier one (retries, duplicate log lines, a
// state change mid-test).
func latestFirewallEvidence(records []FirewallEvidence) FirewallEvidence {
	sorted := make([]FirewallEvidence, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	return sorted[len(sorted)-1]
}

func latestIDSEvidence(records []IDSEvidence) IDSEvidence {
	sorted := make([]IDSEvidence, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Timestamp.Before(sorted[j].Timestamp) })
	return sorted[len(sorted)-1]
}

// detectContradiction flags a disagreement between the firewall's own
// claimed action and our independently-observed reachability for the
// same flow. It is additive context, never a verdict override, and
// only ever applies to the block path with a firewall match -- an IDS
// alerting on a payload and a connection succeeding are not mutually
// exclusive, so this is never computed for alert expectations.
func detectContradiction(fw *FirewallEvidence, obs networkgraph.NetworkObservation) string {
	if fw == nil {
		return ""
	}
	switch fw.Action {
	case "block":
		if obs.State == cloudgraph.Observed {
			return "firewall evidence claims this flow was blocked, but our own connectivity probe observed it as reachable"
		}
	case "permit":
		if obs.State == cloudgraph.Blocked {
			return "firewall evidence claims this flow was permitted, but our own connectivity probe observed it as blocked"
		}
	}
	return ""
}
