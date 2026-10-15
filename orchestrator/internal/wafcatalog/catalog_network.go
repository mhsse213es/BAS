package wafcatalog

func ssrfVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/api/webhooks", PayloadLocation: "body:json:callbackUrl", Payload: "https://partner.example.com/webhook", Description: "ordinary external partner webhook URL"}
	v1, err := NewAttackVector("SSRF-001", 1, FamilySSRF, "SSRF via a webhook callback URL targeting an internal service", SeverityCritical,
		"target accepts a user-supplied callback URL and fetches it server-side",
		RequestTemplate{Method: "POST", Path: "/api/webhooks", PayloadLocation: "body:json:callbackUrl", Payload: "http://127.0.0.1:8080/admin/internal-status", Description: "SSRF attempting to reach an internal admin service via a user-controlled webhook callback URL"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-918"}, WSTGCategory: "WSTG-INPV-19", Top10Category: "A10:2021-Server-Side Request Forgery"},
		"manually authored from CWE-918 / OWASP WSTG-INPV-19")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	v2, err := NewAttackVector("SSRF-002", 1, FamilySSRF, "Cloud metadata endpoint SSRF via a URL-fetch parameter", SeverityCritical,
		"target exposes a URL-fetch/webhook/import feature that accepts a user-supplied URL",
		RequestTemplate{Method: "POST", Path: "/api/fetch-url", PayloadLocation: "body:json:url", Payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", Description: "attempts to reach cloud-provider instance metadata via a user-controlled URL-fetch feature"},
		nil, "no legitimate client request targets the cloud metadata address range; there is no meaningful benign lookalike for this vector",
		StandardsMapping{CWEIDs: []string{"CWE-918"}, WSTGCategory: "WSTG-INPV-19", Top10Category: "A10:2021-Server-Side Request Forgery"},
		"manually authored from CWE-918 / OWASP WSTG-INPV-19")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func fileUploadVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/upload", PayloadLocation: "body:multipart:file", Payload: "<jpeg bytes>", Description: "ordinary JPEG image upload named vacation.jpg"}
	v1, err := NewAttackVector("FILEUP-001", 1, FamilyFileUpload, "Web-shell upload via a double file extension", SeverityCritical,
		"target accepts file uploads and serves the upload directory via a web-accessible path",
		RequestTemplate{Method: "POST", Path: "/upload", PayloadLocation: "body:multipart:file", Payload: "<?php system($_GET['cmd']); ?>", Description: "uploads a PHP web shell disguised with a double extension (shell.php.jpg) attempting remote code execution if the server executes it as PHP"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-434"}, Top10Category: "A08:2021-Software and Data Integrity Failures"},
		"manually authored from CWE-434")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "POST", Path: "/upload/archive", PayloadLocation: "body:multipart:file", Payload: "<normal zip bytes>", Description: "ordinary project-files.zip archive of modest size"}
	v2, err := NewAttackVector("FILEUP-002", 1, FamilyFileUpload, "Decompression-bomb archive upload", SeverityHigh,
		"target accepts archive uploads and extracts them server-side",
		RequestTemplate{Method: "POST", Path: "/upload/archive", PayloadLocation: "body:multipart:file", Payload: "<highly compressed archive engineered to expand to many GB on extraction>", Description: "uploads a decompression bomb attempting resource exhaustion via server-side archive extraction"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-434"}, Top10Category: "A08:2021-Software and Data Integrity Failures"},
		"manually authored from CWE-434")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func httpParserVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/checkout", PayloadLocation: "header:Content-Length", Payload: "well-formed single Content-Length", Description: "ordinary checkout request with one well-formed Content-Length header"}
	v1, err := NewAttackVector("HTTPPARSE-001", 1, FamilyHTTPParser, "HTTP request smuggling via conflicting Content-Length and Transfer-Encoding headers", SeverityCritical,
		"target sits behind a front-end proxy and an origin server that disagree on which header takes precedence (CL.TE desync)",
		RequestTemplate{Method: "POST", Path: "/checkout", PayloadLocation: "header:Transfer-Encoding+body", Payload: "Content-Length: 4\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n1\\r\\nA\\r\\n0\\r\\n\\r\\nSMUGGLED", Description: "CL.TE request smuggling attempting to desynchronize the front-end proxy and origin server's framing of the request boundary"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-444"}}, "manually authored from CWE-444")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/admin/settings", Description: "ordinary GET request using the permitted verb"}
	v2, err := NewAttackVector("HTTPPARSE-002", 1, FamilyHTTPParser, "HTTP verb tampering against a method-based access control", SeverityHigh,
		"target enforces an access-control rule keyed on HTTP method (e.g. blocks POST but not other verbs) on an administrative route",
		RequestTemplate{Method: "TRACE", Path: "/admin/settings", Description: "verb-tampering attempt using an unexpected HTTP method to bypass a method-specific access-control rule"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-650"}}, "manually authored from CWE-650")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}
