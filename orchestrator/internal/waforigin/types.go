// Package waforigin is a vendor-neutral, I/O-free evaluator covering
// waf.txt Phase 7's deployment-topology and resilience items: routing
// coverage, direct-origin reachability, fail-open conditions, TLS/proxy
// behavior, and configuration consistency. It depends on internal/wafval
// and internal/wafcatalog (read-only cross-reference to existing attack
// vectors -- this package contributes no new attack payloads, only new
// evaluation logic over existing ones under topology-weakening
// conditions). It does not depend on wafpolicygap, wafevasion,
// wafapiflow, or wafbotabuse, and none of those depend on it either.
// Fixture-backed only; real topology discovery and multi-node collection
// are deferred.
package waforigin

// WeaknessKind is one of the three evaluation shapes this package covers.
type WeaknessKind string

const (
	KindBypassPair           WeaknessKind = "bypass_pair"
	KindProtocolClaim        WeaknessKind = "protocol_claim"
	KindCrossNodeConsistency WeaknessKind = "cross_node_consistency"
)

// WeaknessType is one of the five named items from waf.txt Phase 7.
type WeaknessType string

const (
	WeaknessRoutingCoverageGap       WeaknessType = "routing_coverage_gap"
	WeaknessDirectOriginReachability WeaknessType = "direct_origin_reachability"
	WeaknessFailOpenOnUnavailability WeaknessType = "fail_open_on_waf_unavailability"
	WeaknessTLSProxyBehavior         WeaknessType = "tls_proxy_behavior"
	WeaknessConfigurationConsistency WeaknessType = "configuration_consistency"
)

// Kind maps a WeaknessType to the evaluation shape it is evaluated under.
// An unknown WeaknessType returns "" -- callers must treat that as invalid,
// never as a fourth kind.
func (w WeaknessType) Kind() WeaknessKind {
	switch w {
	case WeaknessRoutingCoverageGap, WeaknessDirectOriginReachability, WeaknessFailOpenOnUnavailability:
		return KindBypassPair
	case WeaknessTLSProxyBehavior:
		return KindProtocolClaim
	case WeaknessConfigurationConsistency:
		return KindCrossNodeConsistency
	default:
		return ""
	}
}
