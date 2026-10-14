package cloudtopology

import (
	"fmt"
	"net"
	"sort"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// CloudFlow is a candidate flow to evaluate -- mirrors
// networkpolicy.PolicyQuery, but keyed to a resolved subnet rather
// than a zone (subnet resolution from a caller-supplied host happens
// one level up, at the API handler -- Task 8).
type CloudFlow struct {
	SourceCIDR string
	DestCIDR   string
	Protocol   string
	Port       int
}

// SecurityGroupEvaluation is EvaluateSecurityGroupRules's result.
type SecurityGroupEvaluation struct {
	Flow        CloudFlow
	State       cloudgraph.PathState
	MatchedRule *SecurityGroupRule // nil when implicit-deny applied, or when no groups/rules were evaluable
	Provenance  cloudgraph.Provenance
	Limitations string
}

// MatchesPort reports whether port falls within r.PortRange, reusing
// networkpolicy.ParsePortRange's parsing rather than duplicating it.
func (r SecurityGroupRule) MatchesPort(port int) (bool, error) {
	matchAny, low, high, err := networkpolicy.ParsePortRange(r.PortRange)
	if err != nil {
		return false, err
	}
	if matchAny {
		return true, nil
	}
	return port >= low && port <= high, nil
}

// EvaluateSecurityGroupRules evaluates every rule of the given
// direction from every security group applicable to subnetID against
// flow, in Order, first match wins. direction selects which question
// is being asked: DirectionOutbound evaluates subnetID's own egress
// rules (is traffic leaving subnetID permitted to reach flow), and
// DirectionInbound evaluates subnetID's own ingress rules (is traffic
// from flow permitted to enter subnetID) -- real security groups
// enforce each direction independently, so a rule of the other
// direction on the same group is never considered here, even though
// it is declared on an applicable group. Applicable groups are every
// ScopeNetwork group on the subnet's network, plus every ScopeSubnet
// group attached to subnetID. If any ScopeUnresolved group is also
// attached, the result is forced to Unknown regardless of what the
// resolved groups' rules would otherwise decide. Zero applicable
// groups at all is likewise Unknown (missing evidence, never a
// confirmed deny). No rule matching any applicable group falls
// through to implicit deny, which is safe to assume uniformly across
// providers.
func EvaluateSecurityGroupRules(imp *CloudTopologyImport, subnetID string, direction string, flow CloudFlow) (SecurityGroupEvaluation, error) {
	result := SecurityGroupEvaluation{Flow: flow}

	var subnet *CloudSubnet
	for i := range imp.Subnets {
		if imp.Subnets[i].CanonicalID == subnetID {
			subnet = &imp.Subnets[i]
			break
		}
	}
	if subnet == nil {
		return result, fmt.Errorf("cloudtopology: subnet %q not found in this import", subnetID)
	}

	var applicable []SecurityGroup
	unresolvedAttached := false
	for _, g := range imp.Groups {
		switch g.Scope {
		case ScopeNetwork:
			if g.NetworkID == subnet.NetworkID {
				applicable = append(applicable, g)
			}
		case ScopeSubnet:
			if g.SubnetID == subnetID {
				applicable = append(applicable, g)
			}
		case ScopeUnresolved:
			if g.NetworkID == subnet.NetworkID || g.SubnetID == subnetID {
				unresolvedAttached = true
			}
		}
	}

	if unresolvedAttached {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "an unresolved-attachment security group applies to this subnet; its rules might apply and might deny traffic the resolved groups' rules appear to allow"
		return result, nil
	}

	if len(applicable) == 0 {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no security groups declared for this subnet in the import; cannot determine policy"
		return result, nil
	}

	groupIDs := make(map[string]bool, len(applicable))
	for _, g := range applicable {
		groupIDs[g.CanonicalID] = true
	}
	var rules []SecurityGroupRule
	for _, r := range imp.Rules {
		if groupIDs[r.GroupID] && r.Direction == direction {
			rules = append(rules, r)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Order < rules[j].Order })

	for i := range rules {
		matched, err := matchesFlow(rules[i], direction, flow)
		if err != nil {
			return result, err
		}
		if !matched {
			continue
		}
		switch rules[i].Action {
		case ActionAllow:
			result.State = cloudgraph.PolicySupported
			result.Provenance = cloudgraph.Provenance{Confidence: "medium"}
		case ActionDeny:
			result.State = cloudgraph.Blocked
			result.Provenance = cloudgraph.Provenance{Confidence: "medium"}
		case ActionUnresolved:
			result.State = cloudgraph.Unknown
			result.Provenance = cloudgraph.Provenance{Confidence: "none"}
			result.Limitations = rules[i].Note
		default:
			return result, fmt.Errorf("cloudtopology: rule %q has unknown action %q", rules[i].ID, rules[i].Action)
		}
		matchedRule := rules[i]
		result.MatchedRule = &matchedRule
		return result, nil
	}

	result.State = cloudgraph.Blocked
	result.Provenance = cloudgraph.Provenance{Confidence: "low"}
	return result, nil
}

// matchesFlow reports whether rule applies to flow, given the
// direction under evaluation (already filtered to rule.Direction ==
// direction by the caller). A rule with no CIDR (a
// ReferencedGroupID-only, SG-to-SG rule) matches on protocol/port
// alone, since this schema cannot resolve group membership -- import
// validation (Task 7) requires such rules to carry
// Action == ActionUnresolved, so a match here is never read as a real
// allow/deny.
func matchesFlow(rule SecurityGroupRule, direction string, flow CloudFlow) (bool, error) {
	if rule.Protocol != "" && flow.Protocol != "" && rule.Protocol != flow.Protocol {
		return false, nil
	}
	portOK, err := rule.MatchesPort(flow.Port)
	if err != nil {
		return false, err
	}
	if !portOK {
		return false, nil
	}
	if rule.CIDR == "" {
		return true, nil
	}
	var targetCIDR string
	if direction == DirectionInbound {
		targetCIDR = flow.SourceCIDR
	} else {
		targetCIDR = flow.DestCIDR
	}
	if targetCIDR == "" {
		return false, nil
	}
	return cidrsOverlap(rule.CIDR, targetCIDR)
}

// cidrsOverlap treats two CIDRs as overlapping when either contains
// the other's network address -- the same deliberate simplification
// networkpolicy.cidrsOverlap uses, re-implemented locally rather than
// imported (cloudtopology and networkpolicy stay independent packages).
func cidrsOverlap(a, b string) (bool, error) {
	_, aNet, err := net.ParseCIDR(a)
	if err != nil {
		return false, fmt.Errorf("cloudtopology: invalid CIDR %q: %w", a, err)
	}
	_, bNet, err := net.ParseCIDR(b)
	if err != nil {
		return false, fmt.Errorf("cloudtopology: invalid CIDR %q: %w", b, err)
	}
	return aNet.Contains(bNet.IP) || bNet.Contains(aNet.IP), nil
}
