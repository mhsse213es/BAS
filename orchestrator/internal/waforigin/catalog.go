package waforigin

import "fmt"

// AudspectWAFOriginCatalog returns Audspect's real, current seed origin/
// deployment/resilience scenario set: one scenario per named item from
// waf.txt Phase 7, split across the three evaluation shapes.
func AudspectWAFOriginCatalog() (bypass []BypassScenario, protocol []ProtocolBehaviorVector, consistency []ConsistencyScenario, err error) {
	s1, err := NewBypassScenario("WAFORIGIN-001", WeaknessRoutingCoverageGap, "SQLI-001",
		"https://app.example.com/search via the production CDN/WAF edge",
		"the same SQLi payload sent to an undocumented secondary vhost/subpath never registered with the WAF",
		"manually authored from waf.txt Phase 7's named routing-coverage item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	s2, err := NewBypassScenario("WAFORIGIN-002", WeaknessDirectOriginReachability, "XSS-001",
		"https://app.example.com/search via the production CDN/WAF edge",
		"the same reflected-XSS payload sent directly to the origin's own IP/hostname, bypassing the CDN/WAF edge entirely",
		"manually authored from waf.txt Phase 7's named direct-origin-reachability item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	s3, err := NewBypassScenario("WAFORIGIN-003", WeaknessFailOpenOnUnavailability, "SSRF-001",
		"https://app.example.com/webhook via the production WAF while the WAF is healthy",
		"the same SSRF payload sent while the WAF reports an internal error/timeout/unavailable state",
		"manually authored from waf.txt Phase 7's named fail-open-conditions item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	protocolBenign := RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header",
		Payload:     "TLS 1.2+ handshake with a correctly-set X-Forwarded-Proto header matching the actual connection",
		Description: "declared-minimum TLS version with correctly-set proxy headers"}
	p1, err := NewProtocolBehaviorVector("WAFORIGIN-004", 1, "TLS Downgrade with Forged Proxy Header",
		"origin trusts X-Forwarded-Proto without independently verifying the actual TLS version negotiated at the edge",
		RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "tls+header",
			Payload:     "TLS 1.0 handshake with a forged X-Forwarded-Proto: https header while the connection actually arrived over plaintext",
			Description: "deprecated TLS version combined with a forged proxy-trust header, testing whether the origin independently verifies transport security rather than trusting a client-settable header"},
		&protocolBenign, "", StandardsMapping{CWEIDs: []string{"CWE-319"}},
		"manually authored from waf.txt Phase 7's named TLS/proxy-behavior item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	s5, err := NewConsistencyScenario("WAFORIGIN-005", "PATHTRAV-001",
		"manually authored from waf.txt Phase 7's named configuration-consistency item")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading seed origin catalog: %w", err)
	}

	return []BypassScenario{s1, s2, s3}, []ProtocolBehaviorVector{p1}, []ConsistencyScenario{s5}, nil
}
