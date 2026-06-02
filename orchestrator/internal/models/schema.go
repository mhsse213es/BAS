// Package models defines the Common Result Schema — the normalised ATT&CK-aligned
// data structures shared between orchestrator, agents, and the Python API.
package models

import (
	"strings"
	"time"
)

// CheckResult is the outcome of a single simulation check.
type CheckResult string

const (
	ResultPass    CheckResult = "pass"
	ResultFail    CheckResult = "fail"
	ResultSkipped CheckResult = "skipped"
	ResultBlocked CheckResult = "blocked"
)

// AttackTechnique is a MITRE ATT&CK technique reference.
type AttackTechnique struct {
	ID          string `json:"id"`     // T1059.001
	Name        string `json:"name"`   // PowerShell
	Tactic      string `json:"tactic"` // execution
	Description string `json:"description,omitempty"`
}

// SimulationResult is the normalised output of a single technique execution.
// Every framework (ART, Caldera, Sigma, custom) produces this format.
type SimulationResult struct {
	ID           string          `json:"id"`
	Technique    AttackTechnique `json:"technique"`
	Result       CheckResult     `json:"result"`
	Severity     string          `json:"severity"`     // Critical | High | Medium | Low
	ThreatImpact string          `json:"threatImpact"` // what an attacker achieves on Fail
	Details      string          `json:"details"`
	Remediation  string          `json:"remediation"`
	RawOutput    string          `json:"rawOutput,omitempty"`
	DurationMs   int64           `json:"durationMs"`
	ExecutedAt   time.Time       `json:"executedAt"`
	Framework    string          `json:"framework"`        // art | caldera | sigma | custom
	Events       []string        `json:"events,omitempty"` // Windows Event IDs observed
}

// ScenarioRun is a complete execution of a named scenario against one agent.
type ScenarioRun struct {
	ID          string             `json:"id"`
	ScenarioID  string             `json:"scenarioId"`
	Name        string             `json:"name"`
	AgentID     string             `json:"agentId"`
	Status      string             `json:"status"` // running | completed | partial | failed
	Results     []SimulationResult `json:"results"`
	Score       *Score             `json:"score,omitempty"`
	StartedAt   time.Time          `json:"startedAt"`
	CompletedAt *time.Time         `json:"completedAt,omitempty"`
}

// TacticScore holds per-tactic pass/fail breakdown.
type TacticScore struct {
	Tactic  string `json:"tactic"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Total   int    `json:"total"`
	PassPct int    `json:"passPct"` // 0–100
}

// CriticalFailure surfaces a high-severity technique that the attacker won.
type CriticalFailure struct {
	TechniqueID string `json:"techniqueId"`
	Name        string `json:"name"`
	Tactic      string `json:"tactic"`
	Severity    string `json:"severity"`
}

// Score is the multi-dimensional risk assessment for a scenario run.
type Score struct {
	// ── Primary dimensions ────────────────────────────────────────────────────
	PreventionScore         float64                `json:"preventionScore"`         // 0–100, higher=better: weighted pass rate
	ExposureScore           float64                `json:"exposureScore"`           // 0–100, higher=worse: tactic-weighted fail rate
	CoverageScore           float64                `json:"coverageScore"`           // 0–100, higher=better: % tactics with zero fails
	KillChainAmplifier      float64                `json:"killChainAmplifier"`      // 1.0–2.5: consecutive kill-chain failures multiplier
	Trend                   string                 `json:"trend"`                   // Improving | Degrading | Stable | Baseline
	PreviousPreventionScore float64                `json:"previousPreventionScore"` // prevention score of prior run (0 if Baseline)
	TacticBreakdown         map[string]TacticScore `json:"tacticBreakdown"`         // per-tactic pass/fail counts
	CriticalFailures        []CriticalFailure      `json:"criticalFailures"`        // Critical/High severity fails, shown prominently

	// ── Aggregate counts ─────────────────────────────────────────────────────
	TotalTechniques  int `json:"totalTechniques"`
	PassedTechniques int `json:"passedTechniques"`
	FailedTechniques int `json:"failedTechniques"`

	// ── Legacy / backward-compat fields ──────────────────────────────────────
	RiskScore               int    `json:"riskScore"`               // = round(ExposureScore * amplifier), clamped 0–100
	Classification          string `json:"classification"`          // Protected | Low Risk | Medium Risk | High Risk | Critical
	Confidence              int    `json:"confidence"`              // % of non-skipped results
	PreventionEffectiveness int    `json:"preventionEffectiveness"` // = round(PreventionScore)
}

// Agent represents a registered endpoint.
type Agent struct {
	AgentID       string    `json:"agentId"`
	Hostname      string    `json:"hostname"`
	IPAddress     string    `json:"ipAddress"`
	OSVersion     string    `json:"osVersion"`
	Username      string    `json:"username"`
	Status        string    `json:"status"` // idle | scanning | offline
	EnvLabel      string    `json:"envLabel"`
	HasReport     bool      `json:"hasReport"`
	BinaryHash    string    `json:"binaryHash,omitempty"`
	BinaryTrusted bool      `json:"binaryTrusted"`
	LastUpdate    time.Time `json:"lastUpdate"`
}

// Heartbeat is sent by agents periodically.
type Heartbeat struct {
	AgentID    string `json:"agentId"`
	Hostname   string `json:"hostname"`
	IPAddr     string `json:"ipAddress"`
	OSVer      string `json:"osVersion"`
	Username   string `json:"username"`
	Status     string `json:"status"`
	EnvLabel   string `json:"envLabel"`
	BinaryHash string `json:"binaryHash,omitempty"`
}

// WSMessage is the envelope for all WebSocket frames.
type WSMessage struct {
	Type    string      `json:"type"`
	AgentID string      `json:"agentId,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// WebSocket message type constants.
const (
	MsgHeartbeat       = "heartbeat"
	MsgAgentUpdate     = "agentUpdate"
	MsgCommandScan     = "command_scan"
	MsgCommandScenario = "command_scenario"
	MsgCommandSimulate = "command_simulate"
	MsgScenarioResult  = "scenario_result"
	MsgReportReady     = "reportReady"
	MsgPatchStatus     = "patch_status_update"
	MsgCommandPatches  = "command_install_patches"
)

// ── ATT&CK Normalisation ──────────────────────────────────────────────────────

// NormalizeID upper-cases and trims an ATT&CK technique ID.
// Non-ATT&CK IDs (local check IDs, empty strings) are returned unchanged.
func NormalizeID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) >= 5 && (id[0] == 'T' || id[0] == 't') {
		return strings.ToUpper(id)
	}
	return id
}

// LookupTechniqueName returns the canonical ATT&CK technique name for an ID.
// Tries full sub-technique first (T1059.001), then base technique (T1059).
// Returns "" for unknown or non-ATT&CK IDs.
func LookupTechniqueName(id string) string {
	upper := strings.ToUpper(strings.TrimSpace(id))
	if name, ok := TechniqueNameMap[upper]; ok {
		return name
	}
	// Strip sub-technique suffix and try parent
	for i := len(upper) - 1; i >= 0; i-- {
		if upper[i] == '.' {
			if name, ok := TechniqueNameMap[upper[:i]]; ok {
				return name
			}
			break
		}
	}
	return ""
}

// TechniqueNameMap maps ATT&CK technique IDs to their canonical names.
// Covers all techniques used in BAS scenarios plus the most common ART/Caldera tests.
var TechniqueNameMap = map[string]string{
	// ── Reconnaissance ────────────────────────────────────────────────────────
	"T1589":     "Gather Victim Identity Information",
	"T1589.001": "Gather Victim Identity Information: Credentials",
	"T1589.002": "Gather Victim Identity Information: Email Addresses",
	"T1592":     "Gather Victim Host Information",
	"T1592.001": "Gather Victim Host Information: Hardware",
	"T1592.002": "Gather Victim Host Information: Software",
	"T1598":     "Phishing for Information",
	"T1598.003": "Phishing for Information: Spearphishing Link",
	"T1596":     "Search Open Technical Databases",

	// ── Initial Access ────────────────────────────────────────────────────────
	"T1566":     "Phishing",
	"T1566.001": "Phishing: Spearphishing Attachment",
	"T1566.002": "Phishing: Spearphishing Link",
	"T1566.003": "Phishing: Spearphishing via Service",
	"T1190":     "Exploit Public-Facing Application",
	"T1078":     "Valid Accounts",
	"T1078.002": "Valid Accounts: Domain Accounts",
	"T1078.003": "Valid Accounts: Local Accounts",
	"T1133":     "External Remote Services",
	"T1195":     "Supply Chain Compromise",
	"T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",

	// ── Execution ─────────────────────────────────────────────────────────────
	"T1059":     "Command and Scripting Interpreter",
	"T1059.001": "Command and Scripting Interpreter: PowerShell",
	"T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
	"T1059.005": "Command and Scripting Interpreter: Visual Basic",
	"T1059.007": "Command and Scripting Interpreter: JavaScript",
	"T1053":     "Scheduled Task/Job",
	"T1053.005": "Scheduled Task/Job: Scheduled Task",
	"T1047":     "Windows Management Instrumentation",
	"T1203":     "Exploitation for Client Execution",
	"T1204":     "User Execution",
	"T1204.001": "User Execution: Malicious Link",
	"T1204.002": "User Execution: Malicious File",
	"T1106":     "Native API",
	"T1129":     "Shared Modules",

	// ── Persistence ───────────────────────────────────────────────────────────
	"T1547":     "Boot or Logon Autostart Execution",
	"T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
	"T1547.004": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
	"T1547.009": "Boot or Logon Autostart Execution: Shortcut Modification",
	"T1543":     "Create or Modify System Process",
	"T1543.003": "Create or Modify System Process: Windows Service",
	"T1136":     "Create Account",
	"T1136.001": "Create Account: Local Account",
	"T1136.002": "Create Account: Domain Account",
	"T1098":     "Account Manipulation",
	"T1505":     "Server Software Component",
	"T1505.003": "Server Software Component: Web Shell",

	// ── Privilege Escalation ──────────────────────────────────────────────────
	"T1134":     "Access Token Manipulation",
	"T1134.001": "Access Token Manipulation: Token Impersonation/Theft",
	"T1134.002": "Access Token Manipulation: Create Process with Token",
	"T1055":     "Process Injection",
	"T1055.001": "Process Injection: Dynamic-link Library Injection",
	"T1055.002": "Process Injection: Portable Executable Injection",
	"T1055.012": "Process Injection: Process Hollowing",
	"T1068":     "Exploitation for Privilege Escalation",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.002": "Abuse Elevation Control Mechanism: Bypass User Account Control",

	// ── Defense Evasion ───────────────────────────────────────────────────────
	"T1562":     "Impair Defenses",
	"T1562.001": "Impair Defenses: Disable or Modify Tools",
	"T1562.002": "Impair Defenses: Disable Windows Event Logging",
	"T1562.004": "Impair Defenses: Disable or Modify System Firewall",
	"T1562.006": "Impair Defenses: Indicator Blocking",
	"T1027":     "Obfuscated Files or Information",
	"T1027.001": "Obfuscated Files or Information: Binary Padding",
	"T1027.002": "Obfuscated Files or Information: Software Packing",
	"T1070":     "Indicator Removal",
	"T1070.001": "Indicator Removal: Clear Windows Event Logs",
	"T1070.003": "Indicator Removal: Clear Command History",
	"T1070.004": "Indicator Removal: File Deletion",
	"T1036":     "Masquerading",
	"T1036.003": "Masquerading: Rename System Utilities",
	"T1036.005": "Masquerading: Match Legitimate Name or Location",
	"T1112":     "Modify Registry",
	"T1218":     "System Binary Proxy Execution",
	"T1218.005": "System Binary Proxy Execution: Mshta",
	"T1218.010": "System Binary Proxy Execution: Regsvr32",
	"T1218.011": "System Binary Proxy Execution: Rundll32",
	"T1140":     "Deobfuscate/Decode Files or Information",

	// ── Credential Access ─────────────────────────────────────────────────────
	"T1003":     "OS Credential Dumping",
	"T1003.001": "OS Credential Dumping: LSASS Memory",
	"T1003.002": "OS Credential Dumping: Security Account Manager",
	"T1003.003": "OS Credential Dumping: NTDS",
	"T1003.004": "OS Credential Dumping: LSA Secrets",
	"T1558":     "Steal or Forge Kerberos Tickets",
	"T1558.001": "Steal or Forge Kerberos Tickets: Golden Ticket",
	"T1558.002": "Steal or Forge Kerberos Tickets: Silver Ticket",
	"T1558.003": "Steal or Forge Kerberos Tickets: Kerberoasting",
	"T1558.004": "Steal or Forge Kerberos Tickets: AS-REP Roasting",
	"T1555":     "Credentials from Password Stores",
	"T1555.003": "Credentials from Password Stores: Credentials from Web Browsers",
	"T1555.004": "Credentials from Password Stores: Windows Credential Manager",
	"T1056":     "Input Capture",
	"T1056.001": "Input Capture: Keylogging",
	"T1056.002": "Input Capture: GUI Input Capture",
	"T1110":     "Brute Force",
	"T1110.001": "Brute Force: Password Guessing",
	"T1110.003": "Brute Force: Password Spraying",
	"T1187":     "Forced Authentication",
	"T1212":     "Exploitation for Credential Access",

	// ── Discovery ─────────────────────────────────────────────────────────────
	"T1087":     "Account Discovery",
	"T1087.001": "Account Discovery: Local Account",
	"T1087.002": "Account Discovery: Domain Account",
	"T1082":     "System Information Discovery",
	"T1083":     "File and Directory Discovery",
	"T1018":     "Remote System Discovery",
	"T1016":     "System Network Configuration Discovery",
	"T1049":     "System Network Connections Discovery",
	"T1069":     "Permission Groups Discovery",
	"T1069.002": "Permission Groups Discovery: Domain Groups",
	"T1518":     "Software Discovery",
	"T1518.001": "Software Discovery: Security Software Discovery",
	"T1033":     "System Owner/User Discovery",
	"T1007":     "System Service Discovery",

	// ── Lateral Movement ──────────────────────────────────────────────────────
	"T1021":     "Remote Services",
	"T1021.001": "Remote Services: Remote Desktop Protocol",
	"T1021.002": "Remote Services: SMB/Windows Admin Shares",
	"T1021.003": "Remote Services: Distributed Component Object Model",
	"T1021.006": "Remote Services: Windows Remote Management",
	"T1550":     "Use Alternate Authentication Material",
	"T1550.002": "Use Alternate Authentication Material: Pass the Hash",
	"T1550.003": "Use Alternate Authentication Material: Pass the Ticket",
	"T1570":     "Lateral Tool Transfer",

	// ── Collection ────────────────────────────────────────────────────────────
	"T1560":     "Archive Collected Data",
	"T1560.001": "Archive Collected Data: Archive via Utility",
	"T1113":     "Screen Capture",
	"T1114":     "Email Collection",
	"T1114.001": "Email Collection: Local Email Collection",
	"T1005":     "Data from Local System",
	"T1039":     "Data from Network Shared Drive",
	"T1025":     "Data from Removable Media",

	// ── Exfiltration ──────────────────────────────────────────────────────────
	"T1041":     "Exfiltration Over C2 Channel",
	"T1048":     "Exfiltration Over Alternative Protocol",
	"T1048.001": "Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
	"T1048.003": "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol",
	"T1567":     "Exfiltration Over Web Service",
	"T1567.002": "Exfiltration Over Web Service: Exfiltration to Cloud Storage",
	"T1020":     "Automated Exfiltration",

	// ── Command and Control ───────────────────────────────────────────────────
	"T1071":     "Application Layer Protocol",
	"T1071.001": "Application Layer Protocol: Web Protocols",
	"T1071.004": "Application Layer Protocol: DNS",
	"T1095":     "Non-Application Layer Protocol",
	"T1572":     "Protocol Tunneling",
	"T1105":     "Ingress Tool Transfer",
	"T1219":     "Remote Access Software",

	// ── Impact ────────────────────────────────────────────────────────────────
	"T1486":     "Data Encrypted for Impact",
	"T1490":     "Inhibit System Recovery",
	"T1491":     "Defacement",
	"T1491.001": "Defacement: Internal Defacement",
	"T1485":     "Data Destruction",
	"T1565":     "Data Manipulation",
	"T1565.001": "Data Manipulation: Stored Data Manipulation",
	"T1489":     "Service Stop",
	"T1529":     "System Shutdown/Reboot",
}

// TacticMap maps MITRE T-IDs to tactic names.
// Only base technique IDs are needed — LookupTactic strips sub-technique suffixes.
var TacticMap = map[string]string{
	// Reconnaissance
	"T1589": "reconnaissance",
	"T1592": "reconnaissance",
	"T1598": "reconnaissance",
	"T1596": "reconnaissance",

	// Initial Access
	"T1566": "initial-access",
	"T1190": "initial-access",
	"T1078": "initial-access",
	"T1133": "initial-access",
	"T1195": "initial-access",

	// Execution
	"T1059": "execution",
	"T1053": "execution",
	"T1047": "execution",
	"T1203": "execution",
	"T1204": "execution",
	"T1106": "execution",
	"T1129": "execution",

	// Persistence
	"T1547": "persistence",
	"T1543": "persistence",
	"T1136": "persistence",
	"T1098": "persistence",
	"T1505": "persistence",

	// Privilege Escalation
	"T1134": "privilege-escalation",
	"T1055": "privilege-escalation",
	"T1068": "privilege-escalation",
	"T1548": "privilege-escalation",

	// Defense Evasion
	"T1562": "defense-evasion",
	"T1027": "defense-evasion",
	"T1070": "defense-evasion",
	"T1036": "defense-evasion",
	"T1112": "defense-evasion",
	"T1218": "defense-evasion",
	"T1140": "defense-evasion",

	// Credential Access
	"T1003": "credential-access",
	"T1558": "credential-access",
	"T1555": "credential-access",
	"T1056": "credential-access",
	"T1110": "credential-access",
	"T1187": "credential-access",
	"T1212": "credential-access",

	// Discovery
	"T1087": "discovery",
	"T1082": "discovery",
	"T1083": "discovery",
	"T1018": "discovery",
	"T1016": "discovery",
	"T1049": "discovery",
	"T1069": "discovery",
	"T1518": "discovery",
	"T1033": "discovery",
	"T1007": "discovery",

	// Lateral Movement
	"T1021": "lateral-movement",
	"T1550": "lateral-movement",
	"T1570": "lateral-movement",

	// Collection
	"T1560": "collection",
	"T1113": "collection",
	"T1114": "collection",
	"T1005": "collection",
	"T1039": "collection",
	"T1025": "collection",

	// Exfiltration
	"T1041": "exfiltration",
	"T1048": "exfiltration",
	"T1567": "exfiltration",
	"T1020": "exfiltration",

	// Command and Control
	"T1071": "command-and-control",
	"T1095": "command-and-control",
	"T1572": "command-and-control",
	"T1105": "command-and-control",
	"T1219": "command-and-control",

	// Impact
	"T1486": "impact",
	"T1490": "impact",
	"T1491": "impact",
	"T1485": "impact",
	"T1565": "impact",
	"T1489": "impact",
	"T1529": "impact",
}

// LookupTactic resolves T1059.001 → "execution" by stripping the sub-technique suffix.
func LookupTactic(techID string) string {
	base := techID
	for i := len(techID) - 1; i >= 0; i-- {
		if techID[i] == '.' {
			base = techID[:i]
			break
		}
	}
	return TacticMap[strings.ToUpper(base)]
}

// Severity maps a tactic to a risk severity label.
func Severity(tactic string) string {
	switch tactic {
	case "credential-access", "lateral-movement", "privilege-escalation":
		return "Critical"
	case "persistence", "defense-evasion", "execution",
		"command-and-control", "impact", "exfiltration", "collection":
		return "High"
	default:
		return "Medium"
	}
}
