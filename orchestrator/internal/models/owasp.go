package models

import "strings"

// OWASPRisk is an OWASP Top 10 category.
type OWASPRisk struct {
	ID      string `json:"id"`      // e.g. "A01:2021"
	Version string `json:"version"` // e.g. "2021"
	Name    string `json:"name"`    // e.g. "Broken Access Control"
	Order   int    `json:"order"`   // 1..10
}

// OWASP2021 is the canonical OWASP Top 10 (2021) list — the single source of
// truth used to seed the knowledge-graph owasp_risks table.
var OWASP2021 = []OWASPRisk{
	{ID: "A01:2021", Version: "2021", Name: "Broken Access Control", Order: 1},
	{ID: "A02:2021", Version: "2021", Name: "Cryptographic Failures", Order: 2},
	{ID: "A03:2021", Version: "2021", Name: "Injection", Order: 3},
	{ID: "A04:2021", Version: "2021", Name: "Insecure Design", Order: 4},
	{ID: "A05:2021", Version: "2021", Name: "Security Misconfiguration", Order: 5},
	{ID: "A06:2021", Version: "2021", Name: "Vulnerable and Outdated Components", Order: 6},
	{ID: "A07:2021", Version: "2021", Name: "Identification and Authentication Failures", Order: 7},
	{ID: "A08:2021", Version: "2021", Name: "Software and Data Integrity Failures", Order: 8},
	{ID: "A09:2021", Version: "2021", Name: "Security Logging and Monitoring Failures", Order: 9},
	{ID: "A10:2021", Version: "2021", Name: "Server-Side Request Forgery (SSRF)", Order: 10},
}

// owaspByTechnique maps a base ATT&CK technique to the OWASP 2021 categories it
// relates to. OWASP is web-application-risk-centric and ATT&CK is adversary-
// behaviour-centric, so this is intentionally CONSERVATIVE: only defensible
// links are included, a technique may map to several categories, and many
// host-centric techniques map to none. A04 (Insecure Design) is architectural
// and has no clean atomic-technique mapping, so it is left without links.
var owaspByTechnique = map[string][]string{
	// A01 Broken Access Control / A05 Security Misconfiguration / A07 AuthN
	"T1078": {"A01:2021", "A05:2021", "A07:2021"}, // Valid Accounts (default/over-privileged accounts)
	"T1098": {"A01:2021"},                         // Account Manipulation
	"T1134": {"A01:2021"},                         // Access Token Manipulation
	"T1199": {"A01:2021"},                         // Trusted Relationship
	"T1222": {"A01:2021"},                         // File and Directory Permissions Modification
	"T1484": {"A01:2021"},                         // Domain Policy Modification
	"T1530": {"A01:2021"},                         // Data from Cloud Storage (broken bucket ACLs)
	"T1548": {"A01:2021"},                         // Abuse Elevation Control Mechanism
	"T1611": {"A01:2021", "A05:2021"},             // Escape to Host (container misconfig)

	// A02 Cryptographic Failures / A07 Identification & Authentication Failures
	"T1003": {"A02:2021"},             // OS Credential Dumping
	"T1040": {"A02:2021"},             // Network Sniffing (cleartext)
	"T1555": {"A02:2021"},             // Credentials from Password Stores
	"T1552": {"A02:2021", "A07:2021"}, // Unsecured Credentials
	"T1557": {"A02:2021", "A07:2021"}, // Adversary-in-the-Middle
	"T1558": {"A02:2021", "A07:2021"}, // Steal or Forge Kerberos Tickets
	"T1550": {"A02:2021", "A07:2021"}, // Use Alternate Authentication Material
	"T1606": {"A02:2021", "A07:2021"}, // Forge Web Credentials
	"T1528": {"A02:2021", "A07:2021"}, // Steal Application Access Token
	"T1539": {"A02:2021", "A07:2021"}, // Steal Web Session Cookie
	"T1649": {"A02:2021", "A07:2021"}, // Steal or Forge Authentication Certificates

	// A03 Injection / A05 / A06 / A10 (Exploit Public-Facing Application is broad)
	"T1190": {"A03:2021", "A05:2021", "A06:2021", "A10:2021"}, // Exploit Public-Facing Application
	"T1059": {"A03:2021"},                                     // Command and Scripting Interpreter
	"T1221": {"A03:2021"},                                     // Template Injection
	"T1505": {"A03:2021", "A05:2021", "A08:2021"},             // Server Software Component (web shell)

	// A05 Security Misconfiguration
	"T1046": {"A05:2021"}, // Network Service Discovery (exposed services)
	"T1213": {"A05:2021"}, // Data from Information Repositories
	"T1610": {"A05:2021"}, // Deploy Container

	// A06 Vulnerable and Outdated Components / A07 / A08
	"T1068": {"A06:2021"},             // Exploitation for Privilege Escalation
	"T1203": {"A06:2021"},             // Exploitation for Client Execution
	"T1210": {"A06:2021"},             // Exploitation of Remote Services
	"T1211": {"A06:2021"},             // Exploitation for Defense Evasion
	"T1212": {"A06:2021", "A07:2021"}, // Exploitation for Credential Access
	"T1195": {"A06:2021", "A08:2021"}, // Supply Chain Compromise

	// A07 Identification and Authentication Failures
	"T1110": {"A07:2021"}, // Brute Force
	"T1111": {"A07:2021"}, // Multi-Factor Authentication Interception
	"T1185": {"A07:2021"}, // Browser Session Hijacking
	"T1556": {"A07:2021"}, // Modify Authentication Process
	"T1621": {"A07:2021"}, // Multi-Factor Authentication Request Generation

	// A08 Software and Data Integrity Failures
	"T1072": {"A08:2021"}, // Software Deployment Tools
	"T1553": {"A08:2021"}, // Subvert Trust Controls
	"T1554": {"A08:2021"}, // Compromise Host Software Binary
	"T1574": {"A08:2021"}, // Hijack Execution Flow
	"T1608": {"A08:2021"}, // Stage Capabilities

	// A09 Security Logging and Monitoring Failures
	"T1070": {"A09:2021"},             // Indicator Removal (log clearing)
	"T1489": {"A09:2021"},             // Service Stop (stop logging services)
	"T1564": {"A09:2021"},             // Hide Artifacts
	"T1562": {"A05:2021", "A09:2021"}, // Impair Defenses

	// A10 Server-Side Request Forgery
	"T1090": {"A10:2021"}, // Proxy
}

// LookupOWASP returns the OWASP 2021 categories a technique relates to, resolving
// sub-techniques (T1078.001 → T1078). Returns nil when there is no mapping.
func LookupOWASP(techID string) []string {
	base, _, _ := strings.Cut(techID, ".")
	return owaspByTechnique[strings.ToUpper(base)]
}
