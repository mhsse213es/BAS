package variant

import "time"

// ── Encoding ─────────────────────────────────────────────────────────────────

const (
	EncPlain    = "plain"    // raw script passed as-is
	EncBase64   = "base64"   // UTF-16LE → base64 (-EncodedCommand compatible)
	EncGzipB64  = "gzip_b64" // GZip compressed → base64, decompressed at runtime
	EncCharCode = "charcode" // char-code array iex — evades string-scan signatures
)

// ── Execution Context ─────────────────────────────────────────────────────────

const (
	CtxPowershellDirect = "powershell_direct" // powershell.exe -Command directly
	CtxCmdPowershell    = "cmd_powershell"    // cmd.exe /c powershell.exe
	CtxWMI              = "wmi"               // wmic.exe process call create
	CtxSchedTask        = "schedtask"         // schtasks.exe create + run + delete
)

// ── Evasion ───────────────────────────────────────────────────────────────────

// Default (Phase 1) evasions — safe for all environments including BFSI.
const (
	EvasionNone        = "none"                // no evasion
	EvasionSleepJitter = "sleep_jitter"        // random 3–12s sleep — evades sandbox timeouts
	EvasionDelay       = "delay"               // fixed 5s delay — tests time-gated detections
	EvasionParentShift = "parent_process_shift" // spawns via Start-Process — shifts parent in tree
)

// Advanced Evasion Pack — gated behind IncludeAdvanced flag.
// Classified as offensive tradecraft by many compliance teams; must be
// explicitly opted into. Never included in default runs.
const (
	EvasionAMSIPatch = "amsi_patch" // reflection AMSI bypass — disables PS script scanning
)

// ── Risk Levels ───────────────────────────────────────────────────────────────

// RiskLevel classifies how disruptive/detectable a variant's evasion approach is.
// Used by policy enforcement — e.g., an agent policy of "SAFE only" blocks MODERATE+.
type RiskLevel = string

const (
	RiskSafe     RiskLevel = "SAFE"     // timing or plain — no bypass techniques
	RiskModerate RiskLevel = "MODERATE" // obfuscation, process-tree shift
	RiskAdvanced RiskLevel = "ADVANCED" // active memory manipulation (AMSI bypass)
)

// ── Execution Mode ────────────────────────────────────────────────────────────

// ExecutionMode controls how variants are scheduled on the agent.
// Only Sequential is implemented; Parallel and Adaptive are reserved for Phase 4.
type ExecutionMode = string

const (
	ExecutionSequential ExecutionMode = "sequential" // one variant at a time (default)
	ExecutionParallel   ExecutionMode = "parallel"   // all variants concurrently (Phase 4)
	ExecutionAdaptive   ExecutionMode = "adaptive"   // stop early on first ALLOWED (Phase 4)
)

// ── Core Types ────────────────────────────────────────────────────────────────

// Template is one fully-transformed version of a base technique step, ready to
// be dispatched to an agent as a ScenarioStep.
type Template struct {
	ID          string    `json:"id"`
	TechniqueID string    `json:"techniqueId"`
	BaseType    string    `json:"baseType"`    // "art" | "caldera" | "custom"
	BaseID      string    `json:"baseId"`      // ART test name / family name / ability_id
	Encoding    string    `json:"encoding"`
	ExecContext string    `json:"execContext"`
	Evasion     string    `json:"evasion"`
	Platform    string    `json:"platform"`
	Executor    string    `json:"executor"`    // executor field for ScenarioStep ("powershell"|"cmd")
	Command     string    `json:"command"`     // fully transformed command sent to agent
	RiskLevel   RiskLevel `json:"riskLevel"`   // SAFE | MODERATE | ADVANCED
	VariantHash string    `json:"variantHash"` // sha256[:16] of technique+enc+ctx+evasion+baseID
	CreatedAt   time.Time `json:"createdAt"`
}

// PayloadFamily is one named payload script body for a given technique.
// A technique can have many families (e.g., T1059.001 → whoami, net user,
// systeminfo, download stager). Generate() is applied to each family, so
// the total variant count scales with family count.
type PayloadFamily struct {
	ID          string    `json:"id"`
	TechniqueID string    `json:"techniqueId"`
	Name        string    `json:"name"`        // short human-readable label
	Description string    `json:"description"`
	Payload     string    `json:"payload"`     // raw PowerShell script body
	Purpose     string    `json:"purpose"`     // recon | credential | download | persistence | lateral
	RiskLevel   RiskLevel `json:"riskLevel"`
	Platform    string    `json:"platform"`
	Executor    string    `json:"executor"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Run is the server-side record of a dispatched variant execution set.
type Run struct {
	ID            string     `json:"id"`
	AgentID       string     `json:"agentId"`
	TechniqueID   string     `json:"techniqueId"`
	BaseType      string     `json:"baseType"`
	BaseID        string     `json:"baseId"`
	ScenarioRunID string     `json:"scenarioRunId"`
	TotalVariants int        `json:"totalVariants"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"createdAt"`
	CompletedAt   *time.Time `json:"completedAt,omitempty"`
}

// StepRecord maps a dispatched step's TaskID to its variant dimensions.
// Stored at dispatch time; joined with scenario_run.results at query time.
type StepRecord struct {
	TaskID      string    `json:"taskId"`
	Encoding    string    `json:"encoding"`
	ExecContext string    `json:"execContext"`
	Evasion     string    `json:"evasion"`
	Executor    string    `json:"executor"`
	CmdPreview  string    `json:"cmdPreview"`
	RiskLevel   RiskLevel `json:"riskLevel"`
	VariantHash string    `json:"variantHash"`
}

// Result is one variant's execution outcome, joined from run results + step record.
type Result struct {
	TaskID          string     `json:"taskId"`
	Encoding        string     `json:"encoding"`
	ExecContext     string     `json:"execContext"`
	Evasion         string     `json:"evasion"`
	Executor        string     `json:"executor"`
	CmdPreview      string     `json:"cmdPreview"`
	RiskLevel       RiskLevel  `json:"riskLevel"`
	VariantHash     string     `json:"variantHash"`
	Verdict         string     `json:"verdict"`                   // PREVENTED | ALLOWED | ERROR | PENDING
	DetectionSource string     `json:"detectionSource,omitempty"` // Defender | Trellix | CrowdStrike | …
	Detail          string     `json:"detail,omitempty"`
	ExecutedAt      *time.Time `json:"executedAt,omitempty"`
}

// RunDetail is the full response for GET /api/variants/run/:id.
type RunDetail struct {
	Run     Run      `json:"run"`
	Results []Result `json:"results"`
	Summary Summary  `json:"summary"`
}

// Summary is the aggregate outcome across all variants in a run.
type Summary struct {
	Total           int    `json:"total"`
	Prevented       int    `json:"prevented"`
	Allowed         int    `json:"allowed"`
	Errored         int    `json:"errored"`
	Pending         int    `json:"pending"`
	FirstBypass     string `json:"firstBypass,omitempty"`     // enc|ctx|evasion of first ALLOWED
	FirstBypassRisk string `json:"firstBypassRisk,omitempty"` // risk level of first bypass
}

// CoverageRow is one row in the aggregate variant coverage view.
type CoverageRow struct {
	TechniqueID string    `json:"techniqueId"`
	Tactic      string    `json:"tactic"`      // ATT&CK tactic (Execution, Persistence, …)
	BaseType    string    `json:"baseType"`
	BaseID      string    `json:"baseId"`
	TotalTested int       `json:"totalTested"`
	Prevented   int       `json:"prevented"`
	Allowed     int       `json:"allowed"`
	Errored     int       `json:"errored"`
	FirstBypass string    `json:"firstBypass,omitempty"`
}

// Stats is the response for GET /api/variants/stats.
// Keeps "Executed Variants" and "Available Variants" separate — never inflate
// the executed count with un-run theoretical variants.
type Stats struct {
	ExecutedVariants      int `json:"executedVariants"`      // sum of completed variant_run.total_variants
	AvailableVariants     int `json:"availableVariants"`     // payload_family count × variants_per_family
	PayloadFamilyCount    int `json:"payloadFamilyCount"`
	TechniquesWithFamilies int `json:"techniquesWithFamilies"`
	VariantsPerFamily     int `json:"variantsPerFamily"`     // = 56 default / 70 with advanced
}
