package scenario

import (
	"encoding/json"
	"time"

	"github.com/audspect/bas/internal/models"
)

// PrivSpec declares the privilege tier(s) a scenario step may run under.
//
// Three YAML forms are accepted — all parse into this struct:
//
//	scalar:   requires_priv: admin
//	minimum:  requires_priv: {minimum: user}
//	full:     requires_priv: {minimum: user, preferred: admin}
//
// Minimum is the lowest tier at which the technique is meaningful. Preferred
// is the tier at which it yields the broadest coverage (e.g. T1547.001 works
// as "user" in HKCU but as "admin" in HKLM). When Preferred is set the agent
// uses it for execution; Minimum documents the fallback floor. Both values are
// carried through to the report so analysts see "ran as Admin, minimum: User"
// rather than just the bare effective tier.
//
// Valid tier values: "user" | "admin" | "system". Empty means unannotated
// (legacy step — ran in the agent's own context, no tier recorded).
type PrivSpec struct {
	Minimum   string `yaml:"minimum"            json:"minimum,omitempty"`
	Preferred string `yaml:"preferred,omitempty" json:"preferred,omitempty"`
}

// UnmarshalYAML accepts both scalar and mapping forms of requires_priv.
func (p *PrivSpec) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err == nil {
		p.Minimum = s
		return nil
	}
	type privAlias PrivSpec
	var m privAlias
	if err := unmarshal(&m); err != nil {
		return err
	}
	*p = PrivSpec(m)
	return nil
}

// MarshalJSON outputs the full object form so the scenario API is unambiguous.
func (p PrivSpec) MarshalJSON() ([]byte, error) {
	if p.IsZero() {
		return []byte("null"), nil
	}
	type privAlias PrivSpec
	return json.Marshal(privAlias(p))
}

// UnmarshalJSON accepts both scalar string and object forms for JSON round-trips.
func (p *PrivSpec) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		p.Minimum = s
		return nil
	}
	type privAlias PrivSpec
	var m privAlias
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*p = PrivSpec(m)
	return nil
}

// Effective returns the tier the agent should execute under: Preferred when set,
// otherwise Minimum. Returns empty string for unannotated (legacy) steps.
func (p PrivSpec) Effective() string {
	if p.Preferred != "" {
		return p.Preferred
	}
	return p.Minimum
}

// IsZero reports whether no privilege tier has been declared.
func (p PrivSpec) IsZero() bool { return p.Minimum == "" && p.Preferred == "" }

// privilegeTierRank orders privilege tiers from lowest to highest. Unrecognized
// values (including "" — unannotated/legacy) rank as the lowest tier, "user" —
// an unknown or missing tier is never treated as more privileged than it
// actually is, so a MaxPrivilege ceiling never accidentally excludes it.
var privilegeTierRank = map[string]int{
	"user":   0,
	"admin":  1,
	"system": 2,
}

// PrivilegeExceeds reports whether stepTier is strictly above the maxTier
// ceiling. An empty maxTier means no ceiling (never exceeds). Used to decide
// whether a step must be filtered out of a run under an execution policy's
// MaxPrivilege constraint.
func PrivilegeExceeds(stepTier, maxTier string) bool {
	if maxTier == "" {
		return false
	}
	return privilegeTierRank[stepTier] > privilegeTierRank[maxTier]
}

// ExecutionPolicy carries operator-set execution constraints for a dispatch
// request. Today it has one field; it's the deliberate extension point for
// future constraints (NetworkIsolation, AllowReboot, etc.) without another
// wire-format change.
type ExecutionPolicy struct {
	MaxPrivilege string `json:"maxPrivilege,omitempty"`
}

// YAMLPayload defines a file the server should stage on the endpoint before a step runs.
// Content is base64-encoded. Defined in scenario YAML alongside the step.
type YAMLPayload struct {
	Name    string `yaml:"name"    json:"name"`    // filename to write (e.g. "invoke-mimikatz.ps1")
	Content string `yaml:"content" json:"content"` // base64-encoded file content
}

// Step is one ATT&CK technique in a scenario YAML file — server-side definition.
type Step struct {
	Name        string `yaml:"name"                  json:"name"`
	TechniqueID string `yaml:"technique_id"          json:"techniqueId"`
	// CheckID is a stable, ATT&CK-independent identifier for configuration/
	// posture checks (e.g. "windows-firewall-enabled"). technique_id stays
	// optional metadata for checks that genuinely map to a technique;
	// CheckID is what internal/endpointrisk's taxonomy classifies on, so a
	// check like BitLocker (no honest ATT&CK fit) doesn't need a forced
	// technique_id at all.
	CheckID string `yaml:"check_id,omitempty"    json:"checkId,omitempty"`
	// MaxOutputBytes overrides the default 3000-byte RawOutput truncation
	// limit for checks whose evidence is legitimately large (e.g. a full
	// installed-software inventory). 0 means "use the default".
	MaxOutputBytes int           `yaml:"max_output_bytes,omitempty" json:"maxOutputBytes,omitempty"`
	Framework      string        `yaml:"framework"             json:"framework"`
	Command        string        `yaml:"command,omitempty"     json:"command,omitempty"`
	AbilityID      string        `yaml:"ability_id,omitempty"  json:"abilityId,omitempty"`
	TestIndex      int           `yaml:"test_index"            json:"testIndex"`
	Executor       string        `yaml:"executor,omitempty"    json:"executor,omitempty"`
	TimeoutSec     int           `yaml:"timeout_sec,omitempty" json:"timeoutSec,omitempty"`
	Payloads       []YAMLPayload `yaml:"payloads,omitempty"   json:"payloads,omitempty"`
	Cleanup        string        `yaml:"cleanup,omitempty"    json:"cleanup,omitempty"`

	// ── Hybrid/live-mode safety & telemetry metadata (optional) ──────────────
	// These document the risk and expected detection signal of a live step so
	// operators see the blast radius before running and SOC teams know what to
	// look for. Surfaced in the run results; ignored in posture mode.
	Risk        string   `yaml:"risk,omitempty"         json:"risk,omitempty"`        // low | medium | high
	BlastRadius string   `yaml:"blast_radius,omitempty" json:"blastRadius,omitempty"` // short human label, e.g. "spawns benign child process; no persistence"
	Reversible  bool     `yaml:"reversible,omitempty"   json:"reversible,omitempty"`  // true = self-cleaning / no residual change
	Telemetry   []string `yaml:"telemetry,omitempty"    json:"telemetry,omitempty"`   // expected events, e.g. "Security EID 4688", "Sysmon EID 1"
	Detection   []string `yaml:"detection,omitempty"    json:"detection,omitempty"`   // detection objectives, e.g. "EDR: WmiPrvSE child process"

	// ActionKey selects which catalog entry (execclass.go) classifies this
	// step's destructiveness, alongside TechniqueID. It is a LOOKUP KEY
	// ONLY -- see execclass.go's doc comment. The author cannot make a
	// step safe by choosing a reassuring-sounding key; an unrecognized
	// (technique_id, action_key) pair fails closed to destructive. Needed
	// whenever a technique has more than one materially different
	// behavior (T1490's enumerate vs. vss_delete is the canonical
	// example); omit it for a technique with exactly one behavior, which
	// resolves against that technique's "default" catalog entry.
	ActionKey string `yaml:"action_key,omitempty" json:"actionKey,omitempty"`

	// Fidelity controls which live tier a step runs in:
	//   "" or "telemetry-safe" → runs in telemetry AND lab modes (zero identity risk)
	//   "lab-only"             → runs ONLY in lab mode (isolated range; higher risk)
	Fidelity       string `yaml:"fidelity,omitempty"        json:"fidelity,omitempty"`
	ProductionSafe bool   `yaml:"production_safe,omitempty" json:"productionSafe,omitempty"`

	// RequiresPriv declares the privilege context for this step using PrivSpec.
	// Three YAML forms accepted — see PrivSpec for details.
	// The agent receives only PrivSpec.Effective() (a plain string) so the wire
	// format is unchanged; the full spec is carried server-side for reporting.
	RequiresPriv PrivSpec `yaml:"requires_priv,omitempty" json:"requiresPriv,omitempty"`

	// ── Detection Validation Pack (optional) ─────────────────────────────────
	// DetectionProfiles names reusable behavioral profiles whose expected
	// detections apply to this step (resolved at load; see detection.go).
	// ExpectedDetections are inline expectations that supplement or override the
	// referenced profiles (merged by id — inline wins). A step with neither is
	// unchanged from legacy behavior; both are server-side reporting metadata and
	// are never sent to the agent.
	DetectionProfiles  []string            `yaml:"detection_profiles,omitempty" json:"detectionProfiles,omitempty"`
	ExpectedDetections []ExpectedDetection `yaml:"expected_detection,omitempty" json:"expectedDetections,omitempty"`
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
	// ARTAllPlatform runs every ART technique available for the agent's OS.
	// Used by linux-full / darwin-full sweep scenarios; respects supported_os.
	ARTAllPlatform bool     `yaml:"art_all_platform,omitempty"     json:"artAllPlatform,omitempty"`
	ARTTechniques  []string `yaml:"art_techniques,omitempty"       json:"artTechniques,omitempty"`
	// ARTSelectiveWindows/ARTSelectivePlatform build the exact same full-depth
	// Windows/agent-OS sweep as ARTAllWindows/ARTAllPlatform (same builder,
	// same live coverage, no drift between them) -- the only difference is
	// frontend affordance: these get a real selectable Customize picker
	// instead of the read-only Detailed view, so an operator can narrow the
	// run to a chosen technique subset while still defaulting to full breadth
	// when left alone.
	ARTSelectiveWindows  bool `yaml:"art_selective_windows,omitempty"  json:"artSelectiveWindows,omitempty"`
	ARTSelectivePlatform bool `yaml:"art_selective_platform,omitempty" json:"artSelectivePlatform,omitempty"`

	// LivePolicy holds the guardrails enforced during live (telemetry/lab) runs.
	LivePolicy *LivePolicy `yaml:"live_policy,omitempty" json:"livePolicy,omitempty"`

	// PreventScreenTimeout, when true, signals the agent to hold a
	// SetThreadExecutionState(ES_CONTINUOUS|ES_SYSTEM|ES_DISPLAY) wake lock for
	// the duration of this run. Only set for long-running scenarios where a
	// screensaver or display-off event would abort in-progress steps. Opt-in
	// to respect enterprise idle/timeout policies on standard endpoints.
	PreventScreenTimeout bool `yaml:"prevent_screen_timeout,omitempty" json:"preventScreenTimeout,omitempty"`

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
	TaskID      string `json:"taskId"`      // stable hash for result correlation
	TechniqueID string `json:"techniqueId"` // for logging/telemetry on agent
	Name        string `json:"name"`        // for logging on agent
	// Framework is retained server-side only (json:"-" keeps it off the agent
	// wire) so results from dynamically-built steps can be interpreted by the
	// correct framework handler (art|caldera|custom).
	Framework string `json:"-"`
	// Platform is the OS this step targets ("windows", "linux", "darwin").
	// Server-internal only — not sent to the agent. Used to select the correct
	// ART atomic variant during dispatch.
	Platform string `json:"-"`
	// Fidelity gates a dynamically-built step to a live tier, mirroring Step.Fidelity:
	//   "" → runs in telemetry AND lab; "lab-only" → runs ONLY in lab mode.
	// Set on Caldera abilities that ship real payloads (e.g. emu APT chains).
	Fidelity string `json:"-"`
	// requiredPayloads lists external payload basenames the command references
	// (e.g. "gsecdump.exe"). Resolved at dispatch: found files are shipped in
	// Payloads, a missing one turns the step into a clean SKIP. Server-internal.
	requiredPayloads []string
	Executor         string    `json:"executor"` // powershell|cmd|wmi|mshta|rundll32|cscript|wscript|regsvr32|schtasks
	Command          string    `json:"command"`  // concrete command, ready to run
	TimeoutSec       int       `json:"timeoutSec"`
	Payloads         []Payload `json:"payloads,omitempty"` // files to stage before executing
	Cleanup          string    `json:"cleanup,omitempty"`  // cleanup command run after step (pass or fail)
	// Resource is the step's curated lock profile. nil → the agent runs the step
	// serially (always safe). Set centrally by AttachProfiles at dispatch.
	Resource *ResourceProfile `json:"resource,omitempty"`
	// Timeout is the step's curated schedule/execute/grace bounds. nil → the agent
	// uses the step's own timeout / engine default. Set by AttachProfiles.
	Timeout *TimeoutProfile `json:"timeout,omitempty"`
	// ActionKey/ExecutionClass/DestructiveAction/BlastRadius are set by
	// AttachExecutionClassifications (execclass.go) at compile time.
	// ActionKey is scenario-author-set (a lookup key only -- see
	// execclass.go's doc comment; never a safety assertion). The other
	// three are ALWAYS catalog-resolved, never scenario-author-set, even
	// though ExecutionClass shares a name with nothing else on this
	// struct -- there is no legacy field this could be confused with.
	ActionKey         string         `json:"actionKey,omitempty"`
	ExecutionClass    ExecutionClass `json:"executionClass,omitempty"`
	DestructiveAction string         `json:"destructiveAction,omitempty"`
	BlastRadius       string         `json:"blastRadius,omitempty"`
	// RequiresPriv is the privilege tier required to run this step. Mirrors Step.RequiresPriv.
	// "" and "user" both mean non-elevated user context; "admin" and "system" run in
	// the agent's own elevated context. Serialised to the agent wire.
	RequiresPriv string `json:"requiresPriv,omitempty"`
	// ProxyTechniqueID is the ATT&CK technique exercised by the execution context
	// wrapper when ExecContext is non-direct. Set by ApplyVariant; empty for base steps.
	//   WMI wrapper      → T1047
	//   schtasks wrapper → T1053.005
	//   COM wrapper      → T1559.001
	ProxyTechniqueID string `json:"proxyTechniqueId,omitempty"`
	// BaseTaskID is the TaskID of the base step this variant was derived from.
	// Server-internal — not sent to the agent. Set by ExpandSteps.
	BaseTaskID string `json:"-"`
	// VariantSpecRef holds the spec used to generate this step from its base.
	// Server-internal — not sent to the agent. Set by ExpandSteps/ApplyVariant.
	VariantSpecRef *VariantSpec `json:"-"`
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
	// PreventScreenTimeout mirrors Scenario.PreventScreenTimeout — tells the agent to
	// hold a display/system wake lock for the run. Only set when the scenario author
	// has explicitly opted in; never injected by the dispatcher.
	PreventScreenTimeout bool `json:"preventScreenTimeout,omitempty"`
	// SweepID, SweepName, SweepLabel and SweepFinal are set only when this
	// run is one layer of an EM Full Sweep or Variant Full Sweep, letting
	// the agent's local console show which layer a result belongs to
	// ("Result (EM 01): Evaded") instead of a bare, indistinguishable
	// "Result: Evaded" repeated per layer. SweepID is the em_sweeps/
	// vex_sweeps row id, used only so the agent can tell "still the same
	// sweep" from "a different sweep started" -- never rendered. SweepName
	// is the sweep-type's display name ("EM Full Sweep" / "Variant Full
	// Sweep"); SweepFinal marks the sweep's last layer, telling the agent
	// to also show one rolled-up sweep-wide result ("Result (EM Full
	// Sweep): Evaded") alongside that layer's own. All empty/false for a
	// plain, non-sweep run — no behavior change outside sweeps.
	SweepID    string `json:"sweepId,omitempty"`
	SweepName  string `json:"sweepName,omitempty"`
	SweepLabel string `json:"sweepLabel,omitempty"`
	SweepFinal bool   `json:"sweepFinal,omitempty"`
}

// ExecResult is the raw output returned by the agent per step.
type ExecResult struct {
	TaskID     string    `json:"taskId"`
	PID        int       `json:"pid,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
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
	// CleanupResidual lists the normalized snapshot-diff keys the agent found
	// still present after this step's own cleanup command ran (see
	// agent/executor.go's reconcileCleanupVerdict). Nil when no cleanup was
	// defined or the agent's before/after snapshot pair wasn't captured.
	CleanupResidual []string `json:"cleanupResidual,omitempty"`
	// CleanupError captures the cleanup command's own stderr and exit code
	// when CleanupVerdict is "partial" or "leaked" -- see
	// agent/protocol.ExecResult.CleanupError for why this exists.
	CleanupError string `json:"cleanupError,omitempty"`
	// RequestedPriv mirrors the step's requires_priv declaration. Empty for
	// unannotated (legacy) steps.
	RequestedPriv string `json:"requestedPriv,omitempty"`
	// ExecutedAs records the actual privilege context used:
	//   "user"       → ran as logged-in interactive user
	//   "user→admin" → requires_priv=user but no session; ran as agent
	//   "admin"      → agent's elevated context
	//   "system"     → NT AUTHORITY\SYSTEM
	//   ""           → unannotated legacy step (agent's own context)
	ExecutedAs string `json:"executedAs,omitempty"`
	// Termination mirrors the agent's protocol.StepTermination: how the agent
	// ended a step it terminated itself, and what the step was doing at that
	// instant. Nil for a step that exited on its own, for pooled steps, and for
	// any agent predating the field. Nil means "not reported" — never "no
	// output" — so a reader must omit the evidence rather than assert silence.
	Termination *models.StepTermination `json:"termination,omitempty"`
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

	PerfCPUBefore  float64 `json:"perfCpuBefore,omitempty"`
	PerfCPUAfter   float64 `json:"perfCpuAfter,omitempty"`
	PerfRAMBefore  float64 `json:"perfRamBefore,omitempty"`
	PerfRAMAfter   float64 `json:"perfRamAfter,omitempty"`
	PerfDiskBefore float64 `json:"perfDiskBefore,omitempty"`
	PerfDiskAfter  float64 `json:"perfDiskAfter,omitempty"`
}
