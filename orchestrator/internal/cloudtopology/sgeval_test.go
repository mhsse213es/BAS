package cloudtopology

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func testImport() *CloudTopologyImport {
	return &CloudTopologyImport{
		Networks: []CloudNetwork{{CanonicalID: "vpc-1", CIDRBlocks: []string{"10.0.0.0/16"}}},
		Subnets: []CloudSubnet{
			{CanonicalID: "subnet-1", NetworkID: "vpc-1", CIDRBlock: "10.0.1.0/24"},
		},
		Groups: []SecurityGroup{
			{CanonicalID: "sg-1", NetworkID: "vpc-1", Scope: ScopeSubnet, SubnetID: "subnet-1"},
		},
		Rules: []SecurityGroupRule{
			{ID: "r1", GroupID: "sg-1", Order: 10, Direction: DirectionOutbound, Action: ActionAllow, Protocol: "tcp", PortRange: "443", CIDR: "10.0.2.0/24"},
		},
	}
}

func TestEvaluateSecurityGroupRules_AllowMatch_PolicySupported(t *testing.T) {
	imp := testImport()
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", DirectionOutbound, CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q", eval.State, cloudgraph.PolicySupported)
	}
	if eval.MatchedRule == nil || eval.MatchedRule.ID != "r1" {
		t.Fatalf("MatchedRule = %v, want rule r1", eval.MatchedRule)
	}
}

func TestEvaluateSecurityGroupRules_NoMatch_ImplicitDeny(t *testing.T) {
	imp := testImport()
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", DirectionOutbound, CloudFlow{DestCIDR: "10.0.9.0/24", Protocol: "tcp", Port: 22})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q (implicit deny)", eval.State, cloudgraph.Blocked)
	}
}

// TestEvaluateSecurityGroupRules_OrderDecides pins Review Focus #2: two
// rules both match the flow, at different Order values -- the lower
// Order (evaluated first) must decide the outcome regardless of slice
// position.
func TestEvaluateSecurityGroupRules_OrderDecides(t *testing.T) {
	imp := testImport()
	imp.Rules = []SecurityGroupRule{
		{ID: "deny-later", GroupID: "sg-1", Order: 20, Direction: DirectionOutbound, Action: ActionDeny, Protocol: "tcp", PortRange: "443", CIDR: "10.0.2.0/24"},
		{ID: "allow-first", GroupID: "sg-1", Order: 10, Direction: DirectionOutbound, Action: ActionAllow, Protocol: "tcp", PortRange: "443", CIDR: "10.0.2.0/24"},
	}
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", DirectionOutbound, CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q -- the lower-Order allow rule must win, not slice position", eval.State, cloudgraph.PolicySupported)
	}
	if eval.MatchedRule == nil || eval.MatchedRule.ID != "allow-first" {
		t.Fatalf("MatchedRule = %v, want allow-first", eval.MatchedRule)
	}
}

// TestEvaluateSecurityGroupRules_UnresolvedGroupAttached_ForcesUnknown
// pins Review Focus #1: a ScopeUnresolved group attached to the subnet
// must force Unknown even though the resolved group's own rule would
// otherwise allow the flow -- its rules might apply and might deny
// traffic the resolved rules appear to allow.
func TestEvaluateSecurityGroupRules_UnresolvedGroupAttached_ForcesUnknown(t *testing.T) {
	imp := testImport()
	imp.Groups = append(imp.Groups, SecurityGroup{CanonicalID: "sg-unresolved", NetworkID: "vpc-1", Scope: ScopeUnresolved, SubnetID: "subnet-1"})
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", DirectionOutbound, CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- an unresolved-attachment group must force Unknown", eval.State, cloudgraph.Unknown)
	}
	if eval.Limitations == "" {
		t.Fatal("want a non-empty Limitations explaining the unresolved group")
	}
}

// TestEvaluateSecurityGroupRules_DirectionFiltersOutRulesOfOtherDirection
// pins the root cause behind the Critical cloudpath finding: an
// outbound-allow rule on an applicable group must never satisfy an
// inbound evaluation (and vice versa) just because it matches on
// CIDR/protocol/port -- real security groups enforce each direction
// independently, so a rule declared for the other direction is not
// even a candidate.
func TestEvaluateSecurityGroupRules_DirectionFiltersOutRulesOfOtherDirection(t *testing.T) {
	imp := testImport()
	imp.Rules = []SecurityGroupRule{
		{ID: "egress-allow", GroupID: "sg-1", Order: 10, Direction: DirectionOutbound, Action: ActionAllow, Protocol: "tcp", PortRange: "443", CIDR: "10.0.2.0/24"},
	}
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", DirectionInbound, CloudFlow{SourceCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- an outbound-only rule must not satisfy an inbound evaluation, falling through to implicit deny", eval.State, cloudgraph.Blocked)
	}
}

func TestEvaluateSecurityGroupRules_NoGroupsAtAll_Unknown(t *testing.T) {
	imp := testImport()
	imp.Groups = nil
	imp.Rules = nil
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", DirectionOutbound, CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- zero declared groups is missing evidence, never a confirmed deny", eval.State, cloudgraph.Unknown)
	}
}

// TestEvaluateSecurityGroupRules_ReferencedGroupRule_MatchesOnPortOnly
// pins the SG-to-SG reference handling: a rule with ReferencedGroupID
// (no CIDR) matches on protocol/port alone, since this schema cannot
// resolve group membership -- callers must mark such rules
// ActionUnresolved at import time (enforced in Task 7's validation),
// so a match here always yields Unknown.
func TestEvaluateSecurityGroupRules_ReferencedGroupRule_MatchesOnPortOnly(t *testing.T) {
	imp := testImport()
	imp.Rules = []SecurityGroupRule{
		{ID: "sg-ref", GroupID: "sg-1", Order: 10, Direction: DirectionOutbound, Action: ActionUnresolved, Protocol: "tcp", PortRange: "443", ReferencedGroupID: "sg-other", Note: "SG-to-SG reference, group membership not resolvable by this schema"},
	}
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", DirectionOutbound, CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q", eval.State, cloudgraph.Unknown)
	}
	if eval.Limitations == "" {
		t.Fatal("want the rule's Note carried into Limitations")
	}
}
