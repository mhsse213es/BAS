package wafcatalog

func sqlInjectionVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "laptop stand", Description: "ordinary search term a legitimate user would submit"}
	v1, err := NewAttackVector("SQLI-001", 1, FamilySQLInjection, "UNION-based SQL injection in a search parameter", SeverityCritical,
		"target exposes a search endpoint backed by a SQL database",
		RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "' UNION SELECT NULL,NULL,NULL--", Description: "UNION-based injection attempting column enumeration via a search query parameter"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-89"}, WSTGCategory: "WSTG-INPV-05", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-89 / OWASP WSTG-INPV-05")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "jane.doe", Description: "ordinary login username"}
	v2, err := NewAttackVector("SQLI-002", 1, FamilySQLInjection, "Boolean-based blind SQL injection in a login form", SeverityCritical,
		"target has a username/password login form backed by a SQL database",
		RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "admin' OR '1'='1", Description: "boolean-based blind SQLi attempting authentication bypass via an OR-tautology in the username field"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-89"}, WSTGCategory: "WSTG-INPV-05", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-89 / OWASP WSTG-INPV-05")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/products", PayloadLocation: "query:id", Payload: "1", Description: "ordinary numeric product ID"}
	v3, err := NewAttackVector("SQLI-003", 1, FamilySQLInjection, "Error-based SQL injection via a numeric ID parameter", SeverityHigh,
		"target exposes a product-detail endpoint keyed by a numeric ID, backed by a SQL database",
		RequestTemplate{Method: "GET", Path: "/products", PayloadLocation: "query:id", Payload: "1' AND 1=CONVERT(int,(SELECT @@version))--", Description: "error-based injection attempting to leak the database version via a type-conversion error"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-89"}, WSTGCategory: "WSTG-INPV-05", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-89 / OWASP WSTG-INPV-05")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}

func xssVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "running shoes", Description: "ordinary search term"}
	v1, err := NewAttackVector("XSS-001", 1, FamilyXSS, "Reflected XSS via a search query parameter", SeverityHigh,
		"target reflects the search query parameter back into the response HTML without encoding",
		RequestTemplate{Method: "GET", Path: "/search", PayloadLocation: "query:q", Payload: "<script>alert(document.cookie)</script>", Description: "reflected XSS attempting script execution via an unencoded search query reflection"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-79"}, WSTGCategory: "WSTG-INPV-01", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-79 / OWASP WSTG-INPV-01")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/comments", PayloadLocation: "body:json:body", Payload: "Great article, thanks for sharing!", Description: "ordinary comment text"}
	v2, err := NewAttackVector("XSS-002", 1, FamilyXSS, "Stored XSS via a comment field", SeverityHigh,
		"target stores and later renders a comment body without encoding",
		RequestTemplate{Method: "POST", Path: "/comments", PayloadLocation: "body:json:body", Payload: "<img src=x onerror=alert(1)>", Description: "stored XSS attempting script execution via an unencoded comment body rendered to later viewers"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-79"}, WSTGCategory: "WSTG-INPV-02", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-79 / OWASP WSTG-INPV-02")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	benign3 := RequestTemplate{Method: "GET", Path: "/profile", PayloadLocation: "fragment", Payload: "#section-bio", Description: "ordinary URL fragment navigating to a profile section"}
	v3, err := NewAttackVector("XSS-003", 1, FamilyXSS, "DOM-based XSS via a URL fragment reflected into innerHTML", SeverityMedium,
		"target's client-side script reads location.hash and writes it into the DOM via innerHTML without sanitization",
		RequestTemplate{Method: "GET", Path: "/profile", PayloadLocation: "fragment", Payload: "#<svg/onload=alert(1)>", Description: "DOM-based XSS attempting script execution via a URL fragment written unsanitized into innerHTML"},
		&benign3, "", StandardsMapping{CWEIDs: []string{"CWE-79"}, WSTGCategory: "WSTG-CLNT-01", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-79 / OWASP WSTG-CLNT-01")
	if err != nil {
		return nil, err
	}
	out = append(out, v3)

	return out, nil
}

func pathTraversalVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/download", PayloadLocation: "query:file", Payload: "invoice-2026-09.pdf", Description: "ordinary filename within the intended download directory"}
	v1, err := NewAttackVector("PATHTRAV-001", 1, FamilyPathTraversal, "Classic directory traversal via a file-download parameter", SeverityCritical,
		"target exposes a file-download endpoint that builds a filesystem path from a user-supplied filename",
		RequestTemplate{Method: "GET", Path: "/download", PayloadLocation: "query:file", Payload: "../../../../etc/passwd", Description: "directory traversal attempting to read a file outside the intended download directory"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-22"}, WSTGCategory: "WSTG-INPV-11", Top10Category: "A01:2021-Broken Access Control"},
		"manually authored from CWE-22 / OWASP WSTG-INPV-11")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/assets/logo.png", Description: "ordinary static asset request"}
	v2, err := NewAttackVector("PATHTRAV-002", 1, FamilyPathTraversal, "Double-URL-encoded directory traversal against a static-asset route", SeverityHigh,
		"target serves static assets from a route that decodes the path twice before filesystem access",
		RequestTemplate{Method: "GET", Path: "/assets/%252e%252e%252fconfig/app.yaml", Description: "double-URL-encoded traversal attempting to bypass a single-decode path-normalization filter"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-22"}, WSTGCategory: "WSTG-INPV-11", Top10Category: "A01:2021-Broken Access Control"},
		"manually authored from CWE-22 / OWASP WSTG-INPV-11")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
