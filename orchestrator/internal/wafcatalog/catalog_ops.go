package wafcatalog

func rateLimitVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/api/quote", Description: "a single request at normal cadence"}
	v1, err := NewAttackVector("RATE-001", 1, FamilyRateLimit, "Burst beyond the declared rate limit on a public pricing endpoint", SeverityMedium,
		"target publishes a documented per-client rate limit on a public API endpoint",
		RequestTemplate{Method: "GET", Path: "/api/quote", Description: "bounded burst of N requests within a short window, exceeding the documented rate limit, attempting to confirm whether the limit is actually enforced"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-799"}, Top10Category: "A04:2021-Insecure Design"},
		"manually authored from CWE-799")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/api/account/transfer", Description: "a single request from one session at normal cadence"}
	v2, err := NewAttackVector("RATE-002", 1, FamilyRateLimit, "Distributed low-and-slow pattern exceeding an account-level aggregate limit", SeverityMedium,
		"target enforces a per-IP rate limit but not an aggregate per-account limit across sessions/source addresses",
		RequestTemplate{Method: "POST", Path: "/api/account/transfer", Description: "requests spread across multiple source addresses/sessions targeting the same account resource, each individually under the per-IP threshold but together exceeding a reasonable account-level limit"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-799"}, Top10Category: "A04:2021-Insecure Design"},
		"manually authored from CWE-799")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func cacheWeaknessVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/", Description: "ordinary request with no host-override header"}
	v1, err := NewAttackVector("CACHE-001", 1, FamilyCacheWeakness, "Web-cache poisoning via an unkeyed X-Forwarded-Host header", SeverityHigh,
		"target reflects the X-Forwarded-Host header into the response and a shared cache does not include that header in its cache key",
		RequestTemplate{Method: "GET", Path: "/", PayloadLocation: "header:X-Forwarded-Host", Payload: "evil.example.com", Description: "cache-poisoning attempt via an unkeyed X-Forwarded-Host header, aiming for the poisoned response to be cached and served to subsequent users"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-20"}},
		"manually authored from CWE-20")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/account/profile", Description: "ordinary authenticated request to the dynamic profile page"}
	v2, err := NewAttackVector("CACHE-002", 1, FamilyCacheWeakness, "Cache deception via a static-looking extension on a dynamic authenticated endpoint", SeverityHigh,
		"target's shared cache keys on file-extension-like URL suffixes regardless of the endpoint's actual dynamic/authenticated nature",
		RequestTemplate{Method: "GET", Path: "/account/profile.css", Description: "cache-deception attempt appending a static-looking extension to a dynamic authenticated endpoint, aiming for a shared cache to store and leak a private response"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-20"}},
		"manually authored from CWE-20")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func policyMisconfigVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "weather forecast", Description: "ordinary search term"}
	v1, err := NewAttackVector("POLICY-001", 1, FamilyPolicyMisconfig, "Known-malicious request against a rule configured detection-only", SeverityHigh,
		"the matching rule for this payload is declared to be running in detection-only (log, not block) mode",
		RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "<script>alert(1)</script>", Description: "known-malicious XSS payload sent against an endpoint whose matching rule is configured detection-only, expecting a DetectedButAllowed verdict if the misconfiguration is real"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-16"}},
		"manually authored from CWE-16")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/api/legacy/import", PayloadLocation: "body:json:data", Payload: "<ordinary import data>", Description: "ordinary legacy-import request"}
	v2, err := NewAttackVector("POLICY-002", 1, FamilyPolicyMisconfig, "Known-malicious request against a route excluded by an overly broad legacy-compatibility exception", SeverityCritical,
		"the target route is covered by a policy exclusion/allowlist that exempts an entire legacy API path prefix from inspection",
		RequestTemplate{Method: "POST", Path: "/api/legacy/import", PayloadLocation: "body:json:data", Payload: "' UNION SELECT NULL,NULL,NULL--", Description: "known-malicious SQLi payload sent against a route excluded from WAF inspection by an overly broad legacy-compatibility policy exception"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-16"}},
		"manually authored from CWE-16")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
