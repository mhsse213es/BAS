package wafcatalog

func apiAbuseVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/api/orders/{own_order_id}", Description: "requesting one's own order by ID"}
	v1, err := NewAttackVector("API-001", 1, FamilyAPIAbuse, "Broken Object Level Authorization (BOLA/IDOR) on an orders endpoint", SeverityCritical,
		"target's order-detail endpoint does not verify the authenticated user owns the requested order ID",
		RequestTemplate{Method: "GET", Path: "/api/orders/{other_user_order_id}", PayloadLocation: "path:order_id", Description: "requesting another user's order by ID while authenticated as a different user, attempting object-level authorization bypass"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-639"}, APITop10Category: "API1:2023-Broken Object Level Authorization"},
		"manually authored from CWE-639 / OWASP API Security Top 10 API1:2023")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "PUT", Path: "/api/users/me", PayloadLocation: "body:json", Payload: `{"name":"Jane"}`, Description: "ordinary profile update containing only the name field"}
	v2, err := NewAttackVector("API-002", 1, FamilyAPIAbuse, "Mass assignment via an undocumented isAdmin field", SeverityHigh,
		"target's profile-update endpoint binds the request body directly onto an internal object without an allowlist of settable fields",
		RequestTemplate{Method: "PUT", Path: "/api/users/me", PayloadLocation: "body:json", Payload: `{"name":"Jane","isAdmin":true}`, Description: "mass-assignment attempt adding an undocumented isAdmin field to a profile-update request to attempt privilege escalation"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-915"}, APITop10Category: "API3:2023-Broken Object Property Level Authorization"},
		"manually authored from CWE-915 / OWASP API Security Top 10 API3:2023")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/api/users/42", Description: "ordinary user-detail request returning the default field set"}
	v3, err := NewAttackVector("API-003", 1, FamilyAPIAbuse, "Excessive data exposure via a verbose-fields query parameter", SeverityMedium,
		"target's user-detail endpoint supports a fields-selection parameter that is not restricted to a safe allowlist",
		RequestTemplate{Method: "GET", Path: "/api/users/42", PayloadLocation: "query:fields", Payload: "*", Description: "requests every field via a wildcard fields parameter, attempting to retrieve internal fields (e.g. password hash) not normally serialized"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-200"}, APITop10Category: "API3:2023-Broken Object Property Level Authorization"},
		"manually authored from CWE-200 / OWASP API Security Top 10 API3:2023")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}

func authAbuseVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:password", Payload: "<correct password>", Description: "a single normal login attempt with correct credentials"}
	v1, err := NewAttackVector("AUTH-001", 1, FamilyAuthAbuse, "Credential-stuffing burst against a login endpoint", SeverityHigh,
		"target's login endpoint has no (or a very high) lockout/rate threshold on repeated failed attempts for one username",
		RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:password", Payload: "<bounded burst of N differing password guesses against one username within the test window>", Description: "credential-stuffing burst attempting to brute-force a single account's password via rapid sequential login attempts"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-307"}, WSTGCategory: "WSTG-ATHN-03"},
		"manually authored from CWE-307 / OWASP WSTG-ATHN-03")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "<valid username, incorrect password>", Description: "a login attempt with a valid username and an incorrect password, for comparing the returned error message"}
	v2, err := NewAttackVector("AUTH-002", 1, FamilyAuthAbuse, "Account enumeration via differing login error messages", SeverityMedium,
		"target's login endpoint returns a different error message for an unknown username than for a known username with a wrong password",
		RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "<known-invalid username>", Description: "submits a known-invalid username to observe whether the error message differs from the valid-username/wrong-password case, attempting account enumeration"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-204"}, WSTGCategory: "WSTG-IDNT-04"},
		"manually authored from CWE-204 / OWASP WSTG-IDNT-04")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/api/profile", PayloadLocation: "header:Authorization", Payload: "<normal, correctly-signed JWT>", Description: "ordinary authenticated request with a correctly-signed JWT"}
	v3, err := NewAttackVector("AUTH-003", 1, FamilyAuthAbuse, "JWT algorithm-confusion (alg=none) tampering", SeverityCritical,
		"target's JWT verification accepts the alg header value from the token itself rather than pinning an expected algorithm",
		RequestTemplate{Method: "GET", Path: "/api/profile", PayloadLocation: "header:Authorization", Payload: "<JWT with alg header changed to \"none\" and signature stripped>", Description: "JWT algorithm-confusion attempt rewriting the token's alg header to none and removing the signature, attempting authentication bypass"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-347"}, Top10Category: "A02:2021-Cryptographic Failures"},
		"manually authored from CWE-347")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}
