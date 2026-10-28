package wafcatalog

import "fmt"

// Payload depth for the four injection-style families. The first catalog had one to six entries each, which says a WAF
// "covers" SQL injection after a single UNION string. These add the variants a real WAF has to recognise: other
// database engines, time-based and stacked queries, comment and case obfuscation, other locations (JSON body, header),
// Windows and Unix paths with several encodings, and the operators of both shells.
//
// Every payload is a harmless probe. It reads, sleeps or echoes; none of them changes or deletes data, fetches code or
// opens a shell (catalog_depth_test.go enforces that with a deny-list). Each vector has a benign twin on the same
// endpoint and location, so a WAF that blocks the whole route shows up as a false positive.

// depthSpec is one vector of a depth family: the attack request, its benign twin's payload, and the references.
type depthSpec struct {
	id, name, preconditions                 string
	severity                                Severity
	method, path, location, payload, attack string // attack = description of what the request attempts
	benignPayload, benignDescription        string
	wstg, top10, source                     string
}

func buildDepth(family AttackFamily, cwe string, specs []depthSpec) ([]AttackVector, error) {
	out := make([]AttackVector, 0, len(specs))
	for _, s := range specs {
		benign := RequestTemplate{Method: s.method, Path: s.path, PayloadLocation: s.location, Payload: s.benignPayload, Description: s.benignDescription}
		v, err := NewAttackVector(s.id, 1, family, s.name, s.severity, s.preconditions,
			RequestTemplate{Method: s.method, Path: s.path, PayloadLocation: s.location, Payload: s.payload, Description: s.attack},
			&benign, "", StandardsMapping{CWEIDs: []string{cwe}, WSTGCategory: s.wstg, Top10Category: s.top10}, s.source)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", s.id, err)
		}
		out = append(out, v)
	}
	return out, nil
}

const (
	top10Injection = "A03:2021-Injection"
	top10Access    = "A01:2021-Broken Access Control"
)

func sqlInjectionDepthVectors() ([]AttackVector, error) {
	const src = "manually authored from CWE-89 / OWASP WSTG-INPV-05"
	const wstg = "WSTG-INPV-05"
	return buildDepth(FamilySQLInjection, "CWE-89", []depthSpec{
		{id: "SQLI-004", name: "Time-based blind SQL injection (MySQL SLEEP) in a product ID", severity: SeverityHigh,
			preconditions: "target exposes a product-detail endpoint keyed by an ID, backed by MySQL, with no visible error or content difference",
			method:        "GET", path: "/products", location: "query:id", payload: "1' AND SLEEP(5)-- -", attack: "time-based blind injection that makes the database pause five seconds when the condition is true",
			benignPayload: "2", benignDescription: "ordinary numeric product ID", wstg: wstg, top10: top10Injection, source: src},
		{id: "SQLI-005", name: "Stacked-queries SQL injection (MSSQL WAITFOR) in an order lookup", severity: SeverityCritical,
			preconditions: "target's order lookup runs on SQL Server through a driver that allows several statements in one call",
			method:        "GET", path: "/orders", location: "query:id", payload: "1; WAITFOR DELAY '0:0:5'--", attack: "stacked statement that only pauses the connection, proving a second statement can be appended",
			benignPayload: "1001", benignDescription: "ordinary order number", wstg: wstg, top10: top10Injection, source: src},
		{id: "SQLI-006", name: "Oracle error-based SQL injection in a report filter", severity: SeverityHigh,
			preconditions: "target's report endpoint filters by department using an Oracle database and returns database errors",
			method:        "GET", path: "/reports", location: "query:dept", payload: "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--", attack: "Oracle-specific error-based injection that leaks the current database user in an error message",
			benignPayload: "finance", benignDescription: "ordinary department name", wstg: wstg, top10: top10Injection, source: src},
		{id: "SQLI-007", name: "Inline-comment obfuscated UNION injection (keyword-filter bypass)", severity: SeverityHigh,
			preconditions: "target sits behind a filter that matches the literal words UNION and SELECT with ordinary whitespace",
			method:        "GET", path: "/search", location: "query:q", payload: "'/**/UNION/**/SELECT/**/NULL,NULL--", attack: "UNION injection with SQL comments in place of spaces, trying to slip past a whitespace-based keyword rule",
			benignPayload: "laptop stand", benignDescription: "ordinary search term", wstg: wstg, top10: top10Injection, source: src},
		{id: "SQLI-008", name: "Case-mixed keyword SQL injection (signature bypass)", severity: SeverityMedium,
			preconditions: "target sits behind a case-sensitive signature that only matches upper-case or lower-case SQL keywords",
			method:        "GET", path: "/search", location: "query:q", payload: "' uNiOn SeLeCt NULL,NULL--", attack: "UNION injection written in alternating case, trying to slip past a case-sensitive signature",
			benignPayload: "wireless mouse", benignDescription: "ordinary search term", wstg: wstg, top10: top10Injection, source: src},
		{id: "SQLI-009", name: "SQL injection in a JSON request body numeric field", severity: SeverityHigh,
			preconditions: "target's JSON API builds a SQL query from a numeric field without a parameterised statement",
			method:        "POST", path: "/api/items", location: "body:json:id", payload: "1 OR 1=1", attack: "boolean condition appended to a JSON numeric field, a location many WAF rules do not inspect",
			benignPayload: "7", benignDescription: "ordinary item ID in a JSON body", wstg: wstg, top10: top10Injection, source: src},
		{id: "SQLI-010", name: "SQL injection through an HTTP header logged to a database", severity: SeverityHigh,
			preconditions: "target stores the X-Forwarded-For header in a database with a concatenated query",
			method:        "GET", path: "/", location: "header:X-Forwarded-For", payload: "127.0.0.1' OR '1'='1", attack: "boolean injection delivered in a header rather than a parameter, a location most scanners and many rules skip",
			benignPayload: "203.0.113.7", benignDescription: "ordinary client address in X-Forwarded-For", wstg: wstg, top10: top10Injection, source: src},
	})
}

func xssDepthVectors() ([]AttackVector, error) {
	return buildDepth(FamilyXSS, "CWE-79", []depthSpec{
		{id: "XSS-007", name: "Polyglot XSS payload that breaks out of several HTML contexts", severity: SeverityHigh,
			preconditions: "target reflects a parameter into a page where the surrounding context (text, attribute, style or script) is not known",
			method:        "GET", path: "/search", location: "query:q", payload: `'"--></style></script><svg onload=alert(1)>`, attack: "one string that closes quotes, comments, style and script elements and then opens an event handler",
			benignPayload: "summer dresses", benignDescription: "ordinary search term", wstg: "WSTG-INPV-01", top10: top10Injection, source: "manually authored from CWE-79 / OWASP WSTG-INPV-01"},
		{id: "XSS-008", name: "SVG-based XSS in a profile field", severity: SeverityHigh,
			preconditions: "target allows inline SVG in a profile biography and renders it into the page",
			method:        "POST", path: "/profile/bio", location: "body:json:bio", payload: "<svg><script>alert(1)</script></svg>", attack: "script element nested in an SVG, a container that some HTML sanitisers allow",
			benignPayload: "Product designer based in Pune.", benignDescription: "ordinary biography text", wstg: "WSTG-INPV-02", top10: top10Injection, source: "manually authored from CWE-79 / OWASP WSTG-INPV-02"},
		{id: "XSS-009", name: "iframe srcdoc XSS that avoids the literal script tag", severity: SeverityMedium,
			preconditions: "target blocks the literal <script> tag in comments but allows iframe elements and their srcdoc attribute",
			method:        "POST", path: "/comments", location: "body:json:body", payload: `<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>`, attack: "script supplied through an iframe's srcdoc attribute using character references, so no raw script tag appears in the request",
			benignPayload: "Thanks, this helped a lot.", benignDescription: "ordinary comment text", wstg: "WSTG-INPV-02", top10: top10Injection, source: "manually authored from CWE-79 / OWASP WSTG-INPV-02"},
		{id: "XSS-010", name: "XSS in a JSON suggestion response written into the page", severity: SeverityMedium,
			preconditions: "target's search-suggestion endpoint echoes the term inside a JSON response that client script writes into the page or a script block",
			method:        "GET", path: "/api/suggest", location: "query:term", payload: "</script><script>alert(1)</script>", attack: "script-block breakout attempting to run script when the JSON is embedded in a page",
			benignPayload: "blue jeans", benignDescription: "ordinary suggestion term", wstg: "WSTG-CLNT-01", top10: top10Injection, source: "manually authored from CWE-79 / OWASP WSTG-CLNT-01"},
		{id: "XSS-011", name: "Client-side template expression XSS", severity: SeverityMedium,
			preconditions: "target renders a name parameter through a client-side template engine that evaluates double-brace expressions",
			method:        "GET", path: "/greet", location: "query:name", payload: "{{constructor.constructor('alert(1)')()}}", attack: "template expression that reaches the function constructor and runs script",
			benignPayload: "Priya", benignDescription: "ordinary first name", wstg: "WSTG-CLNT-01", top10: top10Injection, source: "manually authored from CWE-79 / OWASP WSTG-CLNT-01"},
		{id: "XSS-012", name: "Double-URL-encoded XSS against a single-decode filter", severity: SeverityMedium,
			preconditions: "target's filter decodes the query string once and inspects it, but the application decodes it a second time before rendering",
			method:        "GET", path: "/search", location: "query:q", payload: "%253Cscript%253Ealert(1)%253C%252Fscript%253E", attack: "script tag encoded twice so the filter sees only percent sequences",
			benignPayload: "garden%20chairs", benignDescription: "ordinary search term with one encoded space", wstg: "WSTG-INPV-01", top10: top10Injection, source: "manually authored from CWE-79 / OWASP WSTG-INPV-01"},
	})
}

func pathTraversalDepthVectors() ([]AttackVector, error) {
	const src = "manually authored from CWE-22 / OWASP WSTG-INPV-11"
	const wstg = "WSTG-INPV-11"
	const pre = "target exposes a file-download endpoint that builds a filesystem path from a user-supplied filename"
	benign := "invoice-2026-09.pdf"
	return buildDepth(FamilyPathTraversal, "CWE-22", []depthSpec{
		{id: "PATHTRAV-003", name: "Windows backslash traversal reading win.ini", severity: SeverityHigh, preconditions: pre + ", on a Windows host",
			method: "GET", path: "/download", location: "query:file", payload: `..\..\..\..\windows\win.ini`, attack: "backslash traversal to a world-readable Windows configuration file, for filters that only look for forward slashes",
			benignPayload: benign, benignDescription: "ordinary filename within the intended download directory", wstg: wstg, top10: top10Access, source: src},
		{id: "PATHTRAV-004", name: "Single-URL-encoded traversal sequence", severity: SeverityHigh, preconditions: pre,
			method: "GET", path: "/download", location: "query:file", payload: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", attack: "dot-dot-slash written as percent sequences, for filters that match the literal characters before decoding",
			benignPayload: benign, benignDescription: "ordinary filename within the intended download directory", wstg: wstg, top10: top10Access, source: src},
		{id: "PATHTRAV-005", name: "Overlong UTF-8 encoded slash traversal", severity: SeverityMedium, preconditions: pre + ", through a decoder that accepts overlong UTF-8 sequences",
			method: "GET", path: "/download", location: "query:file", payload: "..%c0%af..%c0%af..%c0%afetc/passwd", attack: "slash written as the overlong two-byte sequence %c0%af, which some decoders turn back into a slash after the filter has run",
			benignPayload: benign, benignDescription: "ordinary filename within the intended download directory", wstg: wstg, top10: top10Access, source: src},
		{id: "PATHTRAV-006", name: "Null-byte extension bypass on an image route", severity: SeverityMedium, preconditions: "target appends or checks a .png extension on a name parameter and runs on a stack where a null byte ends the path",
			method: "GET", path: "/images", location: "query:name", payload: "../../../../etc/passwd%00.png", attack: "null byte placed before an allowed extension so the extension check passes but the file opened is a different one",
			benignPayload: "photo.png", benignDescription: "ordinary image name", wstg: wstg, top10: top10Access, source: src},
		{id: "PATHTRAV-007", name: "Absolute path supplied directly", severity: SeverityHigh, preconditions: pre + ", without checking that the result stays inside the download directory",
			method: "GET", path: "/download", location: "query:file", payload: "/etc/passwd", attack: "an absolute path in place of a filename, which needs no dot-dot sequence at all",
			benignPayload: benign, benignDescription: "ordinary filename within the intended download directory", wstg: wstg, top10: top10Access, source: src},
		{id: "PATHTRAV-008", name: "Nested dot-dot sequence that survives one-pass stripping", severity: SeverityMedium, preconditions: pre + ", behind a filter that removes ../ once instead of rejecting it",
			method: "GET", path: "/download", location: "query:file", payload: "....//....//....//etc/passwd", attack: "doubled sequence that becomes ../ again after a filter strips the inner one",
			benignPayload: benign, benignDescription: "ordinary filename within the intended download directory", wstg: wstg, top10: top10Access, source: src},
	})
}

func commandInjectionDepthVectors() ([]AttackVector, error) {
	const src = "manually authored from CWE-78 / OWASP WSTG-INPV-12"
	const wstg = "WSTG-INPV-12"
	const ping = "target exposes a network-diagnostic endpoint that shells out to the OS ping command with a user-supplied host"
	return buildDepth(FamilyCommandInjection, "CWE-78", []depthSpec{
		{id: "CMDI-003", name: "Pipe operator injection in a diagnostic endpoint", severity: SeverityCritical, preconditions: ping,
			method: "POST", path: "/ping", location: "body:json:host", payload: "8.8.8.8 | id", attack: "pipe sending the ping output into a second harmless command",
			benignPayload: "8.8.8.8", benignDescription: "ordinary host to ping", wstg: wstg, top10: top10Injection, source: src},
		{id: "CMDI-004", name: "AND and OR list operators (&& and ||) in a diagnostic endpoint", severity: SeverityCritical, preconditions: ping,
			method: "POST", path: "/ping", location: "body:json:host", payload: "8.8.8.8 && id || id", attack: "conditional command lists that run a second command whether or not the ping succeeds",
			benignPayload: "1.1.1.1", benignDescription: "ordinary host to ping", wstg: wstg, top10: top10Injection, source: src},
		{id: "CMDI-005", name: "Command substitution with $() in a conversion filename", severity: SeverityCritical,
			preconditions: "target passes a user-supplied filename to a document converter through a shell",
			method:        "GET", path: "/convert", location: "query:file", payload: "report.docx$(id)", attack: "dollar-parenthesis substitution, the modern form of backticks, embedded in a filename",
			benignPayload: "report.docx", benignDescription: "ordinary filename for a document-conversion request", wstg: wstg, top10: top10Injection, source: src},
		{id: "CMDI-006", name: "URL-encoded newline (%0a) command injection", severity: SeverityHigh, preconditions: ping + ", with input decoded before it reaches the shell",
			method: "POST", path: "/ping", location: "body:json:host", payload: "8.8.8.8%0aid", attack: "encoded newline that ends the ping line and starts a second command, for filters that block ; and | but not line breaks",
			benignPayload: "9.9.9.9", benignDescription: "ordinary host to ping", wstg: wstg, top10: top10Injection, source: src},
		{id: "CMDI-007", name: "Windows cmd.exe single-ampersand chaining", severity: SeverityCritical, preconditions: ping + ", running on a Windows host",
			method: "POST", path: "/ping", location: "body:json:host", payload: "8.8.8.8 & whoami", attack: "single ampersand, the Windows command separator, followed by a harmless identity command",
			benignPayload: "8.8.4.4", benignDescription: "ordinary host to ping", wstg: wstg, top10: top10Injection, source: src},
		{id: "CMDI-008", name: "Time-based blind command injection (sleep)", severity: SeverityHigh, preconditions: ping + ", with no command output returned to the client",
			method: "POST", path: "/ping", location: "body:json:host", payload: "8.8.8.8; sleep 5", attack: "delay that proves command execution when nothing is echoed back",
			benignPayload: "208.67.222.222", benignDescription: "ordinary host to ping", wstg: wstg, top10: top10Injection, source: src},
	})
}
