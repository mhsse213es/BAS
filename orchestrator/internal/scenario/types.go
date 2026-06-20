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

	// ── Hybrid/live-mode safety & telemetry metadata (optional) ──────────────
	// These document the risk and expected detection signal of a live step so
	// operators see the blast radius before running and SOC teams know what to
	// look for. Surfaced in the run results; ignored in posture mode.
	Risk        string   `yaml:"risk,omitempty"         json:"risk,omitempty"`         // low | medium | high
	BlastRadius string   `yaml:"blast_radius,omitempty" json:"blastRadius,omitempty"` // short human label, e.g. "spawns benign child process; no persistence"
	Reversible  bool     `yaml:"reversible,omitempty"   json:"reversible,omitempty"`  // true = self-cleaning / no residual change
	Telemetry   []string `yaml:"telemetry,omitempty"    json:"telemetry,omitempty"`   // expected events, e.g. "Security EID 4688", "Sysmon EID 1"
	Detection   []string `yaml:"detection,omitempty"    json:"detection,omitempty"`   // detection objectives, e.g. "EDR: WmiPrvSE child process"

	// Fidelity controls which live tier a step runs in:
	//   "" or "telemetry-safe" → runs in telemetry AND lab modes (zero identity risk)
	//   "lab-only"             → runs ONLY in lab mode (isolated range; higher risk)
	Fidelity       string `yaml:"fidelity,omitempty"        json:"fidelity,omitempty"`
	ProductionSafe bool   `yaml:"production_safe,omitempty" json:"productionSafe,omitempty"`
}

// LivePolicy is the per-scenario guardrail set applied to live (telemetry/lab)
// execution. Zero values mean "no constraint".
type LivePolicy struct {
	BlockOnDomainController bool     `yaml:"block_on_domain_controller,omitempty" json:"blockOnDomainController,omitempty"`
	RequireDCReachable      bool     `yaml:"require_dc_reachable,omitempty"        json:"requireDcReachable,omitempty"`
	MaxSprayAttempts        int      `yaml:"max_spray_attempts,omitempty"          json:"maxSprayAttempts,omitempty"`
	SprayAccountAllowlist   []string `yaml:"spray_account_allowlist,omitempty"     json:"sprayAccountAllowlist,omitempty"`
	ExecutionWindow         string   `yaml:"execution_window,omitempty"            json:"executionWindow,omitempty"` // "HH:MM-HH:MM" local; empty = always
}

// Scenario is a replayable named attack chain loaded from a YAML file.
//
// Execution modes — checked in this priority order:
//  0. local_check: true          — agent runs built-in registry/PS posture checks (no ART/Caldera needed)
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
	LocalCheck         bool     `yaml:"local_check,omitempty"          json:"localCheck,omitempty"`
	CalderaAllWindows  bool     `yaml:"caldera_all_windows,omitempty"  json:"calderaAllWindows,omitempty"`
	CalderaAbilities   []string `yaml:"caldera_abilities,omitempty"    json:"calderaAbilities,omitempty"`
	CalderaAdversaryID string   `yaml:"caldera_adversary_id,omitempty" json:"calderaAdversaryId,omitempty"`
	ARTAllWindows      bool     `yaml:"art_all_windows,omitempty"      json:"artAllWindows,omitempty"`
	ARTTechniques      []string `yaml:"art_techniques,omitempty"       json:"artTechniques,omitempty"`

	// LivePolicy holds the guardrails enforced during live (telemetry/lab) runs.
	LivePolicy *LivePolicy `yaml:"live_policy,omitempty" json:"livePolicy,omitempty"`

	// Executable marks a hybrid scenario that supports opt-in LIVE execution of
	// real (self-cleaning) attack steps in addition to its read-only posture
	// checks. Only scenarios with audited, safe steps set this true. When false,
	// the scenario can only be run in posture mode regardless of requested mode.
	Executable bool `yaml:"executable,omitempty" json:"executable,omitempty"`

	// SupportedOS lists the operating systems on which this scenario has meaningful
	// coverage. When set, live execution (telemetry/lab) against a mismatched agent
	// is rejected by the API. Posture mode is always allowed.
	// Values: "windows", "linux", "darwin". Empty = no restriction.
	SupportedOS []string `yaml:"supported_os,omitempty" json:"supportedOs,omitempty"`

	// Source is set at load time from the file's folder, NOT persisted to YAML.
	// One of: "builtin" (scenarios/*.yaml), "custom" (scenarios/custom/),
	// "intel" (scenarios/intel/). The UI uses it to decide editable vs read-only.
	Source string `yaml:"-" json:"source,omitempty"`

	// Intel fields — populated only on auto-generated threat-intel scenarios.
	IntelSource      string    `yaml:"intel_source,omitempty"       json:"intelSource,omitempty"`
	IntelSourceID    string    `yaml:"intel_source_id,omitempty"    json:"intelSourceId,omitempty"`
	IntelActor       string    `yaml:"intel_actor,omitempty"        json:"intelActor,omitempty"`
	IntelConfidence  string    `yaml:"intel_confidence,omitempty"   json:"intelConfidence,omitempty"`
	IntelGeneratedAt time.Time `yaml:"intel_generated_at,omitempty" json:"intelGeneratedAt,omitempty"`
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
	TaskID      string    `json:"taskId"`      // stable hash for result correlation
	TechniqueID string    `json:"techniqueId"` // for logging/telemetry on agent
	Name        string    `json:"name"`        // for logging on agent
	// Framework is retained server-side only (json:"-" keeps it off the agent
	// wire) so results from dynamically-built steps can be interpreted by the
	// correct framework handler (art|caldera|custom).
	Framework string `json:"-"`
	// Fidelity gates a dynamically-built step to a live tier, mirroring Step.Fidelity:
	//   "" → runs in telemetry AND lab; "lab-only" → runs ONLY in lab mode.
	// Set on Caldera abilities that ship real payloads (e.g. emu APT chains).
	Fidelity string `json:"-"`
	// requiredPayloads lists external payload basenames the command references
	// (e.g. "gsecdump.exe"). Resolved at dispatch: found files are shipped in
	// Payloads, a missing one turns the step into a clean SKIP. Server-internal.
	requiredPayloads []string
	Executor    string    `json:"executor"`    // powershell|cmd|wmi|mshta|rundll32|cscript|wscript|regsvr32|schtasks
	Command     string    `json:"command"`     // concrete command, ready to run
	TimeoutSec  int       `json:"timeoutSec"`
	Payloads    []Payload `json:"payloads,omitempty"` // files to stage before executing
	Cleanup     string    `json:"cleanup,omitempty"`  // cleanup command run after step (pass or fail)
	// Resource is the step's curated lock profile. nil → the agent runs the step
	// serially (always safe). Set centrally by AttachProfiles at dispatch.
	Resource *ResourceProfile `json:"resource,omitempty"`
	// Timeout is the step's curated schedule/execute/grace bounds. nil → the agent
	// uses the step's own timeout / engine default. Set by AttachProfiles.
	Timeout *TimeoutProfile `json:"timeout,omitempty"`
}

// ScenarioCommand is sent to an agent via WebSocket.
// Steps are already resolved — no framework concepts visible to the agent.
type ScenarioCommand struct {
	RunID      string         `json:"runId"`
	ScenarioID string         `json:"scenarioId"`
	Name       string         `json:"name"`
	Steps      []ScenarioStep `json:"steps"`
	Mode       string         `json:"mode,omitempty"`   // telemetry | lab (live runs only)
	Policy     *LivePolicy    `json:"policy,omitempty"` // guardrails the agent enforces
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
	// TimedOut marks a step that exceeded its execute/schedule timeout — an
	// explicit "ran, did not return" verdict, distinct from a clean skip.
	TimedOut bool `json:"timedOut,omitempty"`
	// CleanupVerdict is set by the agent after running the step's cleanup command.
	// "reverted" = exit 0; "partial" = non-zero exit; "leaked" = timeout/start failure.
	CleanupVerdict string `json:"cleanupVerdict,omitempty"`
}

// SimCheckResult carries the pre-interpreted result of a single built-in local check.
// Agents populate RawRunResult.Checks (not Results) for local_check scenarios so
// all technique metadata (tactic, severity, threat impact, remediation) is preserved
// end-to-end without re-derivation from empty step definitions.
type SimCheckResult struct {
	ID            string    `json:"id"`
	TechniqueID   string    `json:"techniqueId"`
	TechniqueName string    `json:"techniqueName"`
	Tactic        string    `json:"tactic"`
	Result        string    `json:"result"` // pass | fail | skipped
	Severity      string    `json:"severity"`
	ThreatImpact  string    `json:"threatImpact"`
	Details       string    `json:"details"`
	Remediation   string    `json:"remediation"`
	Framework     string    `json:"framework"`
	DurationMs    int64     `json:"durationMs"`
	ExecutedAt    time.Time `json:"executedAt"`
}

// RawRunResult is the payload the agent POSTs to /api/scenarios/result.
// Partial=true means the agent was interrupted mid-run; results cover only completed steps.
// For local_check scenarios, Checks is populated instead of Results so full technique
// metadata is preserved — Results will be empty in that case.
type RawRunResult struct {
	RunID      string           `json:"runId"`
	ScenarioID string           `json:"scenarioId"`
	AgentID    string           `json:"agentId"`
	Results    []ExecResult     `json:"results"`
	Checks     []SimCheckResult `json:"checks,omitempty"` // local_check scenarios only
	Partial    bool             `json:"partial,omitempty"`
	Reverted   []string         `json:"reverted,omitempty"` // endpoint changes rolled back post-run
}
