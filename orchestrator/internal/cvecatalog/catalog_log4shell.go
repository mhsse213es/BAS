package cvecatalog

import "github.com/audspect/bas/internal/cveval"

// log4ShellEntry is CVE-2021-44228 ("Log4Shell"): unauthenticated remote
// code execution in Apache Log4j2, via JNDI lookups the Lookup feature
// performs on attacker-influenced strings written to a log message. This
// entry is fixture-only for now -- ExecutionProfile is set to
// ProfileLabCapable because a controlled runtime check is architecturally
// possible, but internal/cvelab ships no real network-sending prober yet
// (see that package's own doc comment). Declaring the profile here is a
// statement about what kind of check this CVE supports in principle, never
// a claim that live execution is wired up today.
func log4ShellEntry() (CVEEntry, error) {
	return NewCVEEntry(
		"CVE-2021-44228",
		[]string{"CWE-502", "CWE-20"},
		SeverityCritical,
		AffectedProduct{
			Name:   "org.apache.logging.log4j:log4j-core",
			Ranges: []VersionRange{{Introduced: "2.0-beta9", Fixed: "2.15.0"}},
		},
		"Log4Shell: unauthenticated remote code execution in Apache Log4j2. "+
			"The Lookup feature resolves ${jndi:...} patterns found inside a "+
			"logged message, so attacker-controlled input written to a log "+
			"(e.g. a request header) can direct the JVM to perform a JNDI "+
			"lookup against an attacker-controlled directory server, leading "+
			"to remote class loading and code execution.",
		"target application logs attacker-influenced input using an affected "+
			"log4j-core version, with JNDI message-lookup substitution not "+
			"disabled and no compensating mitigation (e.g. formatMsgNoLookups, "+
			"removing JndiLookup.class, or an upgraded log4j2 release) applied",
		cveval.ProfileLabCapable,
		[]Reference{
			{Source: "NVD", URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			{Source: "Apache Log4j Security Advisories", URL: "https://logging.apache.org/log4j/2.x/security.html"},
		},
		"2026-10-24",
		ConfigFixture{
			Description: "log4j-core 2.14.1, JNDI message-lookup substitution enabled, no mitigation flag set",
			Indicator:   "log4j-core:2.14.1;formatMsgNoLookups=false;JndiLookup.class=present",
			Implies:     cveval.VerdictVulnerable,
		},
		ConfigFixture{
			Description: "log4j-core 2.17.1 (post-fix release line, message-lookup substitution removed by default)",
			Indicator:   "log4j-core:2.17.1;formatMsgNoLookups=true;JndiLookup.class=absent",
			Implies:     cveval.VerdictNotVulnerable,
		},
		"manually authored from NVD CVE-2021-44228 and the Apache Log4j security advisories",
	)
}
