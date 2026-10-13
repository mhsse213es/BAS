package networkpolicy

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func testImport(defaultPolicy DefaultPolicy, zones []Zone, rules []Rule) *PolicyImport {
	return &PolicyImport{ID: "imp-1", SourceType: "manual-normalized", DefaultPolicy: defaultPolicy, Zones: zones, Rules: rules}
}

func TestEvaluatePolicyMatrix_ZoneToZoneAllowMatch(t *testing.T) {
	imp := testImport(DefaultDeny,
		[]Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}, {Name: "internal", CIDRs: []string{"10.0.2.0/24"}}},
		[]Rule{{ID: "r1", Order: 1, SourceZone: "dmz", DestZone: "internal", Protocol: "tcp", PortRange: "443", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceZone: "dmz", DestZone: "internal", Protocol: "tcp", Port: 443}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported", results[0].State)
	}
	if results[0].MatchedRule == nil || results[0].MatchedRule.ID != "r1" {
		t.Fatalf("MatchedRule = %+v, want rule r1", results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_CIDRToCIDRDenyMatch(t *testing.T) {
	imp := testImport(DefaultAllow, nil,
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "192.168.1.0/24", Protocol: "tcp", PortRange: "22", Action: ActionDeny}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.5.5/32", DestCIDR: "192.168.1.10/32", Protocol: "tcp", Port: 22}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_MixedZoneAndCIDRMatch(t *testing.T) {
	imp := testImport(DefaultDeny,
		[]Zone{{Name: "web-tier", CIDRs: []string{"10.0.1.0/24"}}},
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "0.0.0.0/0", DestZone: "web-tier", Protocol: "tcp", PortRange: "443", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "203.0.113.5/32", DestCIDR: "10.0.1.50/32", Protocol: "tcp", Port: 443}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_FirstMatchWinsOverLaterConflictingRule(t *testing.T) {
	imp := testImport(DefaultDeny, nil,
		[]Rule{
			{ID: "allow-first", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", PortRange: "443", Action: ActionAllow},
			{ID: "deny-second", Order: 2, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", PortRange: "443", Action: ActionDeny},
		},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 443}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported || results[0].MatchedRule.ID != "allow-first" {
		t.Fatalf("got state=%q matchedRule=%+v, want policy_supported via allow-first (order matters)", results[0].State, results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_UnresolvedActionIsUnknownWithNote(t *testing.T) {
	imp := testImport(DefaultDeny, nil,
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", PortRange: "", Action: ActionUnresolved, Note: "NAT rule, cannot translate losslessly"}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown", results[0].State)
	}
	if results[0].Limitations != "NAT rule, cannot translate losslessly" {
		t.Fatalf("Limitations = %q, want the rule's own Note carried through", results[0].Limitations)
	}
}

func TestEvaluatePolicyMatrix_AmbiguousZoneNameIsUnknown(t *testing.T) {
	imp := testImport(DefaultDeny,
		[]Zone{{Name: "dup", CIDRs: []string{"10.0.1.0/24"}}, {Name: "dup", CIDRs: []string{"10.0.9.0/24"}}},
		[]Rule{{ID: "r1", Order: 1, SourceZone: "dup", DestCIDR: "10.0.0.0/8", PortRange: "", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceZone: "dup", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- two zones sharing a name must never be silently resolved to one of them", results[0].State)
	}
	if results[0].Limitations == "" {
		t.Fatal("want a non-empty limitation note explaining the ambiguity")
	}
}

func TestEvaluatePolicyMatrix_UnknownZoneNameIsUnknown(t *testing.T) {
	imp := testImport(DefaultAllow, []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}, nil)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceZone: "does-not-exist", DestCIDR: "10.0.1.5/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown for a zone name absent from this import", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_NoRuleMatchesDefaultAllow(t *testing.T) {
	imp := testImport(DefaultAllow, nil, nil)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported || results[0].MatchedRule != nil {
		t.Fatalf("got state=%q matchedRule=%+v, want policy_supported via default policy, no matched rule", results[0].State, results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_NoRuleMatchesDefaultDeny(t *testing.T) {
	imp := testImport(DefaultDeny, nil, nil)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Blocked || results[0].MatchedRule != nil {
		t.Fatalf("got state=%q matchedRule=%+v, want blocked via default policy, no matched rule", results[0].State, results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_ProtocolMismatchDoesNotMatch(t *testing.T) {
	imp := testImport(DefaultDeny, nil,
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", Protocol: "udp", PortRange: "53", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Protocol: "tcp", Port: 53}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked via default policy -- the udp-only rule must not match a tcp query", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_RejectsEmptyQueries(t *testing.T) {
	imp := testImport(DefaultAllow, nil, nil)
	if _, err := EvaluatePolicyMatrix(imp, nil); err == nil {
		t.Fatal("want error for zero queries")
	}
}

func TestEvaluatePolicyMatrix_RejectsTooManyQueries(t *testing.T) {
	imp := testImport(DefaultAllow, nil, nil)
	queries := make([]PolicyQuery, MaxPolicyQueriesPerEvaluation+1)
	if _, err := EvaluatePolicyMatrix(imp, queries); err == nil {
		t.Fatal("want error for too many queries")
	}
}

func TestEvaluatePolicyMatrix_RejectsImportOverRuleCap(t *testing.T) {
	rules := make([]Rule, MaxRulesPerImport+1)
	imp := testImport(DefaultAllow, nil, rules)
	if _, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{Port: 80}}); err == nil {
		t.Fatal("want error for an import with too many rules")
	}
}

func TestEvaluatePolicyMatrix_RejectsImportOverZoneCap(t *testing.T) {
	zones := make([]Zone, MaxZonesPerImport+1)
	imp := testImport(DefaultAllow, zones, nil)
	if _, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{Port: 80}}); err == nil {
		t.Fatal("want error for an import with too many zones")
	}
}
