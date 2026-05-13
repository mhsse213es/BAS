// Package models defines the Common Result Schema — the normalised ATT&CK-aligned
// data structures shared between orchestrator, agents, and the Python API.
package models

import "time"

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
	ID          string `json:"id"`                    // T1059.001
	Name        string `json:"name"`                  // PowerShell
	Tactic      string `json:"tactic"`                // execution
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
	Framework    string          `json:"framework"` // art | caldera | sigma | custom
}

// ScenarioRun is a complete execution of a named scenario against one agent.
type ScenarioRun struct {
	ID          string             `json:"id"`
	ScenarioID  string             `json:"scenarioId"`
	Name        string             `json:"name"`
	AgentID     string             `json:"agentId"`
	Status      string             `json:"status"` // running | completed | failed
	Results     []SimulationResult `json:"results"`
	Score       *Score             `json:"score,omitempty"`
	StartedAt   time.Time          `json:"startedAt"`
	CompletedAt *time.Time         `json:"completedAt,omitempty"`
}

// Score is the computed risk assessment for a scenario run.
// Formula is identical to the original C# ScoringEngine.
type Score struct {
	RiskScore               int    `json:"riskScore"`
	Classification          string `json:"classification"` // Protected | Low Risk | Medium Risk | High Risk | Critical
	Confidence              int    `json:"confidence"`
	ExecutionReliability    int    `json:"executionReliability"`
	AttackProgression       int    `json:"attackProgression"`
	ObjectiveSuccess        int    `json:"objectiveSuccess"`
	DetectionTiming         int    `json:"detectionTiming"`
	BlastRadius             int    `json:"blastRadius"`
	PreventionEffectiveness int    `json:"preventionEffectiveness"`
}

// Agent represents a registered endpoint.
type Agent struct {
	AgentID    string    `json:"agentId"`
	Hostname   string    `json:"hostname"`
	IPAddress  string    `json:"ipAddress"`
	OSVersion  string    `json:"osVersion"`
	Username   string    `json:"username"`
	Status     string    `json:"status"` // idle | scanning | offline
	EnvLabel   string    `json:"envLabel"`
	HasReport  bool      `json:"hasReport"`
	LastUpdate time.Time `json:"lastUpdate"`
}

// Heartbeat is sent by agents periodically.
type Heartbeat struct {
	AgentID  string `json:"agentId"`
	Hostname string `json:"hostname"`
	IPAddr   string `json:"ipAddress"`
	OSVer    string `json:"osVersion"`
	Username string `json:"username"`
	Status   string `json:"status"`
	EnvLabel string `json:"envLabel"`
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
	MsgScenarioResult  = "scenario_result"
	MsgReportReady     = "reportReady"
	MsgPatchStatus     = "patch_status_update"
	MsgCommandPatches  = "command_install_patches"
)

// TacticMap maps MITRE T-IDs to tactic names.
// Covers the full ATT&CK Enterprise matrix used by BFSI scenarios.
var TacticMap = map[string]string{
	"T1566": "initial-access",
	"T1190": "initial-access",
	"T1078": "initial-access",
	"T1133": "initial-access",
	"T1195": "initial-access",
	"T1059": "execution",
	"T1053": "execution",
	"T1203": "execution",
	"T1204": "execution",
	"T1106": "execution",
	"T1547": "persistence",
	"T1543": "persistence",
	"T1136": "persistence",
	"T1098": "persistence",
	"T1134": "privilege-escalation",
	"T1055": "privilege-escalation",
	"T1068": "privilege-escalation",
	"T1548": "privilege-escalation",
	"T1562": "defense-evasion",
	"T1027": "defense-evasion",
	"T1070": "defense-evasion",
	"T1036": "defense-evasion",
	"T1112": "defense-evasion",
	"T1003": "credential-access",
	"T1558": "credential-access",
	"T1555": "credential-access",
	"T1056": "credential-access",
	"T1110": "credential-access",
	"T1087": "discovery",
	"T1082": "discovery",
	"T1083": "discovery",
	"T1018": "discovery",
	"T1021": "lateral-movement",
	"T1550": "lateral-movement",
	"T1570": "lateral-movement",
	"T1560": "collection",
	"T1113": "collection",
	"T1114": "collection",
	"T1041": "exfiltration",
	"T1048": "exfiltration",
	"T1567": "exfiltration",
	"T1071": "command-and-control",
	"T1095": "command-and-control",
	"T1572": "command-and-control",
	"T1486": "impact",
	"T1490": "impact",
	"T1491": "impact",
	"T1485": "impact",
	"T1565": "impact",
	"T1589": "reconnaissance",
	"T1592": "reconnaissance",
	"T1598": "reconnaissance",
}

// LookupTactic resolves T1059.001 → "execution".
func LookupTactic(techID string) string {
	base := techID
	for i := len(techID) - 1; i >= 0; i-- {
		if techID[i] == '.' {
			base = techID[:i]
			break
		}
	}
	return TacticMap[base]
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
