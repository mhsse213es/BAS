package waforigin

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// ConsistencyScenario is a Kind-C (cross-node-consistency) scenario: the
// claim that an existing, already-catalogued attack's evidence, collected
// independently from two or more deployment nodes, resolves to the same
// verdict on every node.
type ConsistencyScenario struct {
	ID             string
	AttackVectorID string
	Provenance     string
}

// NewConsistencyScenario validates at construction time, never at render
// time.
func NewConsistencyScenario(id string, attackVectorID string, provenance string) (ConsistencyScenario, error) {
	if id == "" {
		return ConsistencyScenario{}, fmt.Errorf("id must not be empty")
	}
	if attackVectorID == "" {
		return ConsistencyScenario{}, fmt.Errorf("attackVectorID must not be empty")
	}
	if provenance == "" {
		return ConsistencyScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return ConsistencyScenario{ID: id, AttackVectorID: attackVectorID, Provenance: provenance}, nil
}

// NodeEvidence is one deployment node's independently-collected evidence
// for the same correlation key's request.
type NodeEvidence struct {
	NodeID   string
	Evidence []wafval.CollectionResult
	Key      wafval.CorrelationKey
}

// ConsistencyVerdict is the outcome of comparing two or more nodes'
// independently-derived wafval.Result verdicts.
type ConsistencyVerdict string

const (
	ConsistencyConfirmed    ConsistencyVerdict = "confirmed"
	ConsistencyDrift        ConsistencyVerdict = "drift_detected"
	ConsistencyInconclusive ConsistencyVerdict = "inconclusive"
)

// trustworthyResult is Kind C's own filter: Confidence-only, regardless of
// Verdict, since a trustworthy Allowed result is just as comparable as a
// trustworthy Blocked one -- unlike Task 3's trustworthyBlocked, which also
// requires VerdictBlocked specifically.
func trustworthyResult(r wafval.Result) bool {
	return r.Confidence == wafval.ConfidenceHigh || r.Confidence == wafval.ConfidenceMedium
}

// EvaluateConfigurationConsistency evaluates scenario's referenced vector's
// malicious leg independently against each node's evidence, then compares
// the trustworthy results' verdicts. This adds zero new wafval
// verdict-derivation logic -- it only compares Verdict values
// wafval.EvaluateClaim already derived.
func EvaluateConfigurationConsistency(
	scenario ConsistencyScenario,
	vector wafcatalog.AttackVector,
	policyBasis string,
	nodes []NodeEvidence,
) (ConsistencyVerdict, string, error) {
	if vector.ID != scenario.AttackVectorID {
		return "", "", fmt.Errorf("vector.ID %q does not match scenario.AttackVectorID %q", vector.ID, scenario.AttackVectorID)
	}
	maliciousExpectation := vector.Expectations(policyBasis)[0].Expectation

	type trustworthyNode struct {
		nodeID string
		result wafval.Result
	}
	var trustworthy []trustworthyNode
	for _, n := range nodes {
		result := wafval.EvaluateClaim(maliciousExpectation, n.Evidence, n.Key)
		if trustworthyResult(result) {
			trustworthy = append(trustworthy, trustworthyNode{nodeID: n.NodeID, result: result})
		}
	}

	if len(trustworthy) < 2 {
		return ConsistencyInconclusive, fmt.Sprintf("only %d of %d nodes produced trustworthy evidence; at least 2 are required to assess consistency", len(trustworthy), len(nodes)), nil
	}
	first := trustworthy[0]
	for _, other := range trustworthy[1:] {
		if other.result.Verdict != first.result.Verdict {
			return ConsistencyDrift, fmt.Sprintf("node %q produced verdict %q while node %q produced verdict %q", first.nodeID, first.result.Verdict, other.nodeID, other.result.Verdict), nil
		}
	}
	return ConsistencyConfirmed, fmt.Sprintf("%d nodes agree on verdict %q", len(trustworthy), first.result.Verdict), nil
}
