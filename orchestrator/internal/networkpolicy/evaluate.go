package networkpolicy

import (
	"fmt"
	"net"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

const (
	MaxRulesPerImport             = 5000
	MaxZonesPerImport             = 500
	MaxPolicyQueriesPerEvaluation = 500
)

// PolicyQuery is one row of a policy test matrix. Exactly one of
// SourceZone/SourceCIDR, and exactly one of DestZone/DestCIDR, should be
// set per side.
type PolicyQuery struct {
	SourceZone, SourceCIDR string
	DestZone, DestCIDR     string
	Protocol               string
	Port                   int
}

// PolicyEvaluation is EvaluatePolicyMatrix's per-query result.
type PolicyEvaluation struct {
	Query       PolicyQuery
	State       cloudgraph.PathState
	MatchedRule *Rule // nil when the default policy applied, or when resolution failed before any rule was checked
	Provenance  cloudgraph.Provenance
	Limitations string
}

// resolvedRule caches one rule's source/dest CIDR resolution so it is
// computed once per EvaluatePolicyMatrix call, not once per query --
// otherwise worst-case cost is O(queries x rules x zones) instead of
// O(rules x zones + queries x rules).
type resolvedRule struct {
	rule       *Rule
	srcCIDRs   []string
	dstCIDRs   []string
	resolveErr error
}

// EvaluatePolicyMatrix evaluates every query against imp's rules (walked
// in Order, first match wins) and default policy, producing one
// PolicyEvaluation per query in the same order as queries.
func EvaluatePolicyMatrix(imp *PolicyImport, queries []PolicyQuery) ([]PolicyEvaluation, error) {
	if len(queries) == 0 {
		return nil, fmt.Errorf("networkpolicy: EvaluatePolicyMatrix requires at least one query")
	}
	if len(queries) > MaxPolicyQueriesPerEvaluation {
		return nil, fmt.Errorf("networkpolicy: too many queries -- got %d, max %d", len(queries), MaxPolicyQueriesPerEvaluation)
	}
	if len(imp.Rules) > MaxRulesPerImport {
		return nil, fmt.Errorf("networkpolicy: import has too many rules -- got %d, max %d", len(imp.Rules), MaxRulesPerImport)
	}
	if len(imp.Zones) > MaxZonesPerImport {
		return nil, fmt.Errorf("networkpolicy: import has too many zones -- got %d, max %d", len(imp.Zones), MaxZonesPerImport)
	}

	resolved := make([]resolvedRule, len(imp.Rules))
	for i := range imp.Rules {
		r := &imp.Rules[i]
		src, srcErr := resolveSide(r.SourceZone, r.SourceCIDR, imp.Zones)
		dst, dstErr := resolveSide(r.DestZone, r.DestCIDR, imp.Zones)
		rr := resolvedRule{rule: r, srcCIDRs: src, dstCIDRs: dst}
		if srcErr != nil {
			rr.resolveErr = srcErr
		} else if dstErr != nil {
			rr.resolveErr = dstErr
		}
		resolved[i] = rr
	}

	results := make([]PolicyEvaluation, len(queries))
	for i, q := range queries {
		results[i] = evaluateOne(imp, q, resolved)
	}
	return results, nil
}

func evaluateOne(imp *PolicyImport, q PolicyQuery, resolved []resolvedRule) PolicyEvaluation {
	querySrc, srcErr := resolveSide(q.SourceZone, q.SourceCIDR, imp.Zones)
	queryDst, dstErr := resolveSide(q.DestZone, q.DestCIDR, imp.Zones)
	if srcErr != nil || dstErr != nil {
		note := srcErr
		if note == nil {
			note = dstErr
		}
		return PolicyEvaluation{Query: q, State: cloudgraph.Unknown, Limitations: note.Error(), Provenance: provenanceFor(imp, "none")}
	}

	for _, rr := range resolved {
		if rr.resolveErr != nil {
			continue // this rule's own zone reference couldn't be resolved -- skip it defensively, never abort the whole evaluation
		}
		matched, err := matchResolved(rr.rule, q, querySrc, queryDst, rr.srcCIDRs, rr.dstCIDRs)
		if err != nil || !matched {
			continue
		}
		switch rr.rule.Action {
		case ActionAllow:
			return PolicyEvaluation{Query: q, State: cloudgraph.PolicySupported, MatchedRule: rr.rule, Provenance: provenanceFor(imp, "medium")}
		case ActionDeny:
			return PolicyEvaluation{Query: q, State: cloudgraph.Blocked, MatchedRule: rr.rule, Provenance: provenanceFor(imp, "medium")}
		default: // ActionUnresolved
			return PolicyEvaluation{Query: q, State: cloudgraph.Unknown, MatchedRule: rr.rule, Limitations: rr.rule.Note, Provenance: provenanceFor(imp, "none")}
		}
	}

	if imp.DefaultPolicy == DefaultAllow {
		return PolicyEvaluation{Query: q, State: cloudgraph.PolicySupported, Provenance: provenanceFor(imp, "low")}
	}
	return PolicyEvaluation{Query: q, State: cloudgraph.Blocked, Provenance: provenanceFor(imp, "low")}
}

func matchResolved(rule *Rule, q PolicyQuery, querySrc, queryDst, ruleSrc, ruleDst []string) (bool, error) {
	if rule.Protocol != "" && q.Protocol != "" && rule.Protocol != q.Protocol {
		return false, nil
	}
	portOK, err := rule.MatchesPort(q.Port)
	if err != nil {
		return false, err
	}
	if !portOK {
		return false, nil
	}
	if !cidrSetsOverlap(ruleSrc, querySrc) {
		return false, nil
	}
	if !cidrSetsOverlap(ruleDst, queryDst) {
		return false, nil
	}
	return true, nil
}

// resolveSide resolves one side (source or dest) of a query or rule to
// the CIDR(s) it represents. A direct CIDR is used as-is. A zone-name
// reference must match exactly one entry in zones by Name -- zero or
// more than one match is unresolvable and returned as an error so the
// caller classifies Unknown rather than guessing which zone was meant.
func resolveSide(zoneName, cidr string, zones []Zone) ([]string, error) {
	if cidr != "" {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("networkpolicy: invalid CIDR %q: %w", cidr, err)
		}
		return []string{cidr}, nil
	}
	if zoneName == "" {
		return nil, fmt.Errorf("networkpolicy: neither a zone nor a CIDR was given for this side")
	}
	var found []Zone
	for _, z := range zones {
		if z.Name == zoneName {
			found = append(found, z)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("networkpolicy: zone %q not found in this import", zoneName)
	}
	if len(found) > 1 {
		return nil, fmt.Errorf("networkpolicy: zone name %q is ambiguous -- %d zones share this name", zoneName, len(found))
	}
	return found[0].CIDRs, nil
}

func cidrSetsOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if overlap, err := cidrsOverlap(x, y); err == nil && overlap {
				return true
			}
		}
	}
	return false
}

// cidrsOverlap treats two CIDRs as overlapping when either contains the
// other's network address -- correct for the common nested-subnet case
// (a zone's CIDR containing a query's CIDR, or vice versa), not a full
// arbitrary-range-intersection algorithm. A deliberate, documented
// simplification for Phase 2A's scope.
func cidrsOverlap(a, b string) (bool, error) {
	_, aNet, err := net.ParseCIDR(a)
	if err != nil {
		return false, fmt.Errorf("networkpolicy: invalid CIDR %q: %w", a, err)
	}
	_, bNet, err := net.ParseCIDR(b)
	if err != nil {
		return false, fmt.Errorf("networkpolicy: invalid CIDR %q: %w", b, err)
	}
	return aNet.Contains(bNet.IP) || bNet.Contains(aNet.IP), nil
}

func provenanceFor(imp *PolicyImport, confidence string) cloudgraph.Provenance {
	return cloudgraph.Provenance{Source: "policy-import:" + imp.ID, ObservedAt: time.Now(), Confidence: confidence}
}
