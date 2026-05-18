package scenario

import "time"

// YAMLPayload defines a file the server should stage on the endpoint before a step runs.
// Content is base64-encoded. Defined in scenario YAML alongside the step.
type YAMLPayload struct {
	Name    string `yaml:"name"    json:"name"`    // filename to write (e.g. "invoke-mimikatz.ps1")
	Content string `yaml:"content" json:"content"` // base64-encoded file content
}

// Step is one ATT&CK technique in a scenario YAML file — server-side definition.
type Step struct {
	Name        string        `yaml:"name"                  json:"name"`
	TechniqueID string        `yaml:"technique_id"          json:"techniqueId"`
	Framework   string        `yaml:"framework"             json:"framework"`
	Command     string        `yaml:"command,omitempty"     json:"command,omitempty"`
	AbilityID   string        `yaml:"ability_id,omitempty"  json:"abilityId,omitempty"`
	TestIndex   int           `yaml:"test_index"            json:"testIndex"`
	Executor    string        `yaml:"executor,omitempty"    json:"executor,omitempty"`
	TimeoutSec  int           `yaml:"timeout_sec,omitempty" json:"timeoutSec,omitempty"`
	Payloads    []YAMLPayload `yaml:"payloads,omitempty"   json:"payloads,omitempty"`
	Cleanup     string        `yaml:"cleanup,omitempty"    json:"cleanup,omitempty"`
}

// Scenario is a replayable named attack chain loaded from a YAML file.
//
// Execution modes — checked in this priority order:
//  1. caldera_all_windows: true  — every Windows ability in the Caldera library
//  2. caldera_abilities: [...]   — specific Caldera ability IDs chosen by the admin
//  3. caldera_adversary_id: "x" — all abilities in a named Caldera adversary profile
//  4. art_all_windows: true      — every Windows technique in the Atomic Red Team index
//  5. art_techniques: [...]      — specific ATT&CK technique IDs run via Invoke-AtomicTest
//  6. steps: [...]               — static YAML steps (custom / fallback)
type Scenario struct {
	ID                 string   `yaml:"id"                             json:"id"`
	Name               string   `yaml:"name"                           json:"name"`
	Description        string   `yaml:"description"                    json:"description"`
	Author             string   `yaml:"author,omitempty"               json:"author,omitempty"`
	Tags               []string `yaml:"tags"                           json:"tags"`
	MITREPhases        []string `yaml:"mitre_phases"                   json:"mitrePhases"`
	Steps              []Step   `yaml:"steps"                          json:"steps"`
	CalderaAllWindows  bool     `yaml:"caldera_all_windows,omitempty"  json:"calderaAllWindows,omitempty"`
	CalderaAbilities   []string `yaml:"caldera_abilities,omitempty"    json:"calderaAbilities,omitempty"`
	CalderaAdversaryID string   `yaml:"caldera_adversary_id,omitempty" json:"calderaAdversaryId,omitempty"`
	ARTAllWindows      bool     `yaml:"art_all_windows,omitempty"      json:"artAllWindows,omitempty"`
	ARTTechniques      []string `yaml:"art_techniques,omitempty"       json:"artTechniques,omitempty"`
}

// Payload is a file the server stages on the endpoint before a step runs.
// Content is base64-encoded. The agent writes it to a per-run temp dir
// and exposes the dir as %BAS_PAYLOAD_DIR% / $env:BAS_PAYLOAD_DIR.
type Payload struct {
	Name    string `json:"name"`    // e.g. "invoke-mimikatz.ps1"
	Content string `json:"content"` // base64-encoded file content
}

// ScenarioStep is the agent-facing step: a fully-resolved, ready-to-execute command.
// The server builds these from Step definitions before sending to the agent.
// The agent has no framework knowledge — it only sees executor + command.
type ScenarioStep struct {
	TaskID      string    `json:"taskId"`               // stable hash for result correlation
	TechniqueID string    `json:"techniqueId"`          // for logging/telemetry on agent
	Name        string    `json:"name"`                 // for logging on agent
	Executor    string    `json:"executor"`             // powershell|cmd|wmi|mshta|rundll32|cscript|wscript|regsvr32|schtasks
	Command     string    `json:"command"`              // concrete command, ready to run
	TimeoutSec  int       `json:"timeoutSec"`
	Payloads    []Payload `json:"payloads,omitempty"` // files to stage before executing
	Cleanup     string    `json:"cleanup,omitempty"`  // cleanup command run after step (pass or fail)
}

// ScenarioCommand is sent to an agent via WebSocket.
// Steps are already resolved — no framework concepts visible to the agent.
type ScenarioCommand struct {
	RunID      string         `json:"runId"`
	ScenarioID string         `json:"scenarioId"`
	Name       string         `json:"name"`
	Steps      []ScenarioStep `json:"steps"`
}

// ExecResult is the raw output returned by the agent per step.
type ExecResult struct {
	TaskID     string    `json:"taskId"`
	ExitCode   int       `json:"exitCode"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	DurationMs int64     `json:"durationMs"`
	ExecutedAt time.Time `json:"executedAt"`
	// Events are Windows Event IDs observed during step execution (e.g. "4688:Security", "1:Microsoft-Windows-Sysmon/Operational").
	Events []string `json:"events,omitempty"`
}

// RawRunResult is the payload the agent POSTs to /api/scenarios/result.
type RawRunResult struct {
	RunID      string       `json:"runId"`
	ScenarioID string       `json:"scenarioId"`
	AgentID    string       `json:"agentId"`
	Results    []ExecResult `json:"results"`
}
