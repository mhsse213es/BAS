package variant

import "time"

// Encoding — how the PowerShell payload body is represented.
const (
	EncPlain    = "plain"    // raw script passed as-is
	EncBase64   = "base64"   // UTF-16LE → base64 (-EncodedCommand compatible)
	EncGzipB64  = "gzip_b64" // GZip compressed → base64, decompressed at runtime
	EncCharCode = "charcode" // char-code array iex — evades string-scan signatures
)

// ExecContext — which process/mechanism launches the payload.
const (
	CtxPowershellDirect = "powershell_direct" // powershell.exe -Command directly
	CtxCmdPowershell    = "cmd_powershell"    // cmd.exe /c powershell.exe
	CtxWMI              = "wmi"               // wmic.exe process call create
	CtxSchedTask        = "schedtask"         // schtasks.exe create + run + delete
)

// Evasion — what wrapper is prepended to the script body before encoding.
const (
	EvasionNone        = "none"         // no evasion
	EvasionAMSIPatch   = "amsi_patch"   // reflection AMSI bypass
	EvasionSleepJitter = "sleep_jitter" // random sleep evades sandbox timeouts
)

// Template is one fully-transformed version of a base technique step, ready to
// be dispatched to an agent as a ScenarioStep.
type Template struct {
	ID          string    `json:"id"`
	TechniqueID string    `json:"techniqueId"`
	BaseType    string    `json:"baseType"`    // "art" | "caldera"
	BaseID      string    `json:"baseId"`      // ART test name or Caldera ability_id
	Encoding    string    `json:"encoding"`
	ExecContext string    `json:"execContext"`
	Evasion     string    `json:"evasion"`
	Platform    string    `json:"platform"`
	Executor    string    `json:"executor"`    // executor field value for ScenarioStep
	Command     string    `json:"command"`     // fully transformed command sent to agent
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
	TaskID      string `json:"taskId"`
	Encoding    string `json:"encoding"`
	ExecContext string `json:"execContext"`
	Evasion     string `json:"evasion"`
	Executor    string `json:"executor"`
	CmdPreview  string `json:"cmdPreview"` // first 120 chars of command
}

// Result is one variant's execution outcome, joined from run results + step record.
type Result struct {
	TaskID      string     `json:"taskId"`
	Encoding    string     `json:"encoding"`
	ExecContext string     `json:"execContext"`
	Evasion     string     `json:"evasion"`
	Executor    string     `json:"executor"`
	CmdPreview  string     `json:"cmdPreview"`
	Verdict     string     `json:"verdict"`               // PREVENTED | ALLOWED | ERROR | PENDING
	ExitCode    *int       `json:"exitCode,omitempty"`
	Detail      string     `json:"detail,omitempty"`
	ExecutedAt  *time.Time `json:"executedAt,omitempty"`
}

// RunDetail is the full response for GET /api/variants/run/:id.
type RunDetail struct {
	Run     Run      `json:"run"`
	Results []Result `json:"results"`
	Summary Summary  `json:"summary"`
}

// Summary is the aggregate outcome across all variants in a run.
type Summary struct {
	Total     int    `json:"total"`
	Prevented int    `json:"prevented"`
	Allowed   int    `json:"allowed"`
	Errored   int    `json:"errored"`
	Pending   int    `json:"pending"`
	// FirstBypass is the encoding|execContext|evasion triple of the first ALLOWED result.
	FirstBypass string `json:"firstBypass,omitempty"`
}

// CoverageRow is one row in the aggregate variant coverage view.
type CoverageRow struct {
	TechniqueID string `json:"techniqueId"`
	BaseType    string `json:"baseType"`
	BaseID      string `json:"baseId"`
	TotalTested int    `json:"totalTested"`
	Prevented   int    `json:"prevented"`
	Allowed     int    `json:"allowed"`
	Errored     int    `json:"errored"`
	FirstBypass string `json:"firstBypass,omitempty"`
}
