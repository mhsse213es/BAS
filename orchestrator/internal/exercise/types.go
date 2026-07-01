package exercise

import "time"

// StepType identifies what an exercise step does.
type StepType string

const (
	StepTypeSendEmail       StepType = "send_email"
	StepTypeSendSMS         StepType = "send_sms"
	StepTypeAgentTask       StepType = "agent_task"
	StepTypeWait            StepType = "wait"
	StepTypeApproval        StepType = "approval"
	StepTypeWebhook         StepType = "webhook"
	StepTypeNotify          StepType = "notify"
	// Event-based waits — step enters StepWaiting and the trigger registry
	// checks the condition on every executor tick.
	StepTypeWaitForAgent     StepType = "wait_for_agent"     // waits until a BAS run completes
	StepTypeWaitForDetection StepType = "wait_for_detection" // waits until EDR/SIEM evidence arrives
	StepTypeWaitForWebhook   StepType = "wait_for_webhook"   // waits until external system POSTs /x/hook/{token}
)

// StepStatus is the runtime state of a single step within an execution.
type StepStatus string

const (
	StepPending   StepStatus = "pending"
	StepRunning   StepStatus = "running"
	StepWaiting   StepStatus = "waiting"   // awaiting external event (approval, SIEM alert, etc.)
	StepCompleted StepStatus = "completed"
	StepFailed    StepStatus = "failed"
	StepCancelled StepStatus = "cancelled"
	StepSkipped   StepStatus = "skipped"
)

// ExecStatus is the overall state of an exercise execution.
type ExecStatus string

const (
	ExecDraft     ExecStatus = "draft"
	ExecScheduled ExecStatus = "scheduled"
	ExecRunning   ExecStatus = "running"
	ExecPaused    ExecStatus = "paused"
	ExecCompleted ExecStatus = "completed"
	ExecAborted   ExecStatus = "aborted"
)

// PlanStep is a single node in the exercise DAG.
type PlanStep struct {
	ID          string     `json:"id"`
	Type        StepType   `json:"type"`
	Label       string     `json:"label"`
	DependsOn   []string   `json:"depends_on,omitempty"`
	// Condition controls whether this step runs.
	// Supported forms:
	//   ""                        → always run (default)
	//   "step:{id}:clicked"       → prior step has link_clicked evidence
	//   "step:{id}:not_clicked"   → no link_clicked evidence
	//   "step:{id}:reported"      → phishing_reported evidence exists
	//   "step:{id}:timeout"       → prior wait step timed out (no event)
	//   "step:{id}:no_timeout"    → prior wait step completed via event
	Condition   string     `json:"condition,omitempty"`
	Config      StepConfig `json:"config"`
	TimeoutSecs int        `json:"timeout_secs,omitempty"`
	RetryMax    int        `json:"retry_max,omitempty"`
}

// StepConfig holds type-specific parameters for a step.
type StepConfig struct {
	// send_email
	Email *EmailConfig `json:"email,omitempty"`
	// send_sms
	SMS *SMSConfig `json:"sms,omitempty"`
	// agent_task
	AgentTask *AgentTaskConfig `json:"agent_task,omitempty"`
	// wait — duration string ("4h", "30m", "5s")
	WaitDuration string `json:"wait_duration,omitempty"`
	// approval
	ApprovalPrompt string   `json:"approval_prompt,omitempty"`
	ApproverRoles  []string `json:"approver_roles,omitempty"`
	// webhook (outbound)
	WebhookURL     string            `json:"webhook_url,omitempty"`
	WebhookMethod  string            `json:"webhook_method,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`
	WebhookBody    string            `json:"webhook_body,omitempty"`
	// notify (same as email but to operator/admin, not exercise target)
	NotifyEmail string `json:"notify_email,omitempty"`
	NotifyMsg   string `json:"notify_msg,omitempty"`
	// wait_for_agent
	WaitForAgent *WaitForAgentConfig `json:"wait_for_agent,omitempty"`
	// wait_for_detection
	WaitForDetection *WaitForDetectionConfig `json:"wait_for_detection,omitempty"`
	// wait_for_webhook (inbound)
	WaitForWebhook *WaitForWebhookConfig `json:"wait_for_webhook,omitempty"`
}

type EmailConfig struct {
	To          []string `json:"to"`
	Subject     string   `json:"subject"`
	BodyHTML    string   `json:"body_html"`
	TrackOpens  bool     `json:"track_opens"`
	TrackClicks bool     `json:"track_clicks"`
	// LandingPage type: "safe" (awareness page) or "cred" (credential harvest)
	LandingPage string `json:"landing_page,omitempty"`
	// AttachFile is a payload filename from the ART payload store (optional)
	AttachFile string `json:"attach_file,omitempty"`
}

type SMSConfig struct {
	To   []string `json:"to"`
	Body string   `json:"body"`
}

type AgentTaskConfig struct {
	AgentID     string `json:"agent_id"`
	ScenarioID  string `json:"scenario_id,omitempty"`
	TechniqueID string `json:"technique_id,omitempty"`
}

// WaitForAgentConfig configures a wait_for_agent step.
// The step enters StepWaiting immediately; the trigger fires once the BAS run
// referenced by AgentTaskStepID's result.bas_run_id reaches a terminal status.
type WaitForAgentConfig struct {
	// AgentTaskStepID is the step ID (in the same plan) whose result holds bas_run_id.
	// Leave empty if bas_run_id will be stored directly in this step's own result.
	AgentTaskStepID string `json:"agent_task_step_id,omitempty"`
}

// WaitForDetectionConfig waits for EDR/SIEM evidence to appear in the
// exercise evidence chain (injected via InjectEvidence or a future SIEM hook).
type WaitForDetectionConfig struct {
	// DetectionTypes restricts which evidence types count as a "detection".
	// Defaults to ["edr_detected", "siem_alerted"] when empty.
	DetectionTypes []string `json:"detection_types,omitempty"`
	// MinCount is the minimum number of matching evidence records required.
	// Defaults to 1.
	MinCount int `json:"min_count,omitempty"`
}

// WaitForWebhookConfig waits for an inbound HTTP POST to /x/hook/{token}.
// The token is minted when the step enters StepWaiting and returned in the
// step result so operators know the URL to configure in their external system.
type WaitForWebhookConfig struct {
	// Description is shown to the operator when the hook URL is generated.
	Description string `json:"description,omitempty"`
}

// Plan is a reusable exercise DAG template.
type Plan struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Steps       []PlanStep `json:"steps"`
	Variables   []VarDef   `json:"variables,omitempty"`
	TemplateID  string     `json:"template_id,omitempty"` // set when derived from a Template
	Version     int        `json:"version,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Execution is a live run of a Plan against a set of targets.
type Execution struct {
	ID          string                 `json:"id"`
	PlanID      string                 `json:"plan_id"`
	Name        string                 `json:"name"`
	Status      ExecStatus             `json:"status"`
	InitiatedBy string                 `json:"initiated_by,omitempty"`
	Targets     []Target               `json:"targets,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	// Variables holds the operator-provided values that override plan defaults.
	// The executor resolves ${VarName} against these before dispatching each step.
	Variables   map[string]string      `json:"variables,omitempty"`
	PlanVersion int                    `json:"plan_version,omitempty"`
	Score       *ExerciseScore         `json:"score,omitempty"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Target is a participant in the exercise (human or agent).
type Target struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	Role  string `json:"role,omitempty"`
	Group string `json:"group,omitempty"`
}

// StepExecution is the runtime state of a single PlanStep within an Execution.
type StepExecution struct {
	ID          string                 `json:"id"`
	ExecutionID string                 `json:"execution_id"`
	StepID      string                 `json:"step_id"`
	StepType    StepType               `json:"step_type"`
	Status      StepStatus             `json:"status"`
	Attempt     int                    `json:"attempt"`
	ScheduledAt *time.Time             `json:"scheduled_at,omitempty"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// Evidence is one tamper-evident record in the exercise chain.
type Evidence struct {
	ID              string                 `json:"id"`
	ExecutionID     string                 `json:"execution_id"`
	StepExecutionID string                 `json:"step_execution_id,omitempty"`
	Seq             int64                  `json:"seq"`
	EvidenceType    string                 `json:"evidence_type"`
	Actor           string                 `json:"actor,omitempty"`
	Source          string                 `json:"source,omitempty"`
	Payload         map[string]interface{} `json:"payload,omitempty"`
	SHA256          string                 `json:"sha256"`
	PrevHash        string                 `json:"prev_hash"`
	Signature       string                 `json:"signature,omitempty"`
	RetentionPolicy string                 `json:"retention_policy,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
}

// ExerciseScore captures multi-dimensional exercise scoring.
type ExerciseScore struct {
	Human      HumanScore      `json:"human"`
	Technical  TechnicalScore  `json:"technical"`
	Management ManagementScore `json:"management"`
	Overall    float64         `json:"overall"`
	ComputedAt time.Time       `json:"computed_at"`
}

type HumanScore struct {
	Sent               int `json:"sent"`
	Opened             int `json:"opened"`
	Clicked            int `json:"clicked"`
	AttachmentOpened   int `json:"attachment_opened"`
	CredentialsEntered int `json:"credentials_entered"`
	Reported           int `json:"reported"`
	AvgTimeToReportS   int `json:"avg_time_to_report_s,omitempty"`
	ClickRate          float64 `json:"click_rate"`
	ReportRate         float64 `json:"report_rate"`
}

type TechnicalScore struct {
	EDRDetected     bool `json:"edr_detected"`
	EDRBlocked      bool `json:"edr_blocked"`
	SIEMAlerted     bool `json:"siem_alerted"`
	SOARIncident    bool `json:"soar_incident"`
	TicketCreated   bool `json:"ticket_created"`
	SOCAcknowledged bool `json:"soc_acknowledged"`
	MTTDSeconds     int  `json:"mttd_seconds,omitempty"`
	MTTRSeconds     int  `json:"mttr_seconds,omitempty"`
}

type ManagementScore struct {
	SLAMet            bool `json:"sla_met"`
	EscalationOccurred bool `json:"escalation_occurred"`
	ExecNotified      bool `json:"exec_notified"`
	IRProcessFollowed bool `json:"ir_process_followed"`
}

// AgentDispatchFn allows the exercise executor to trigger BAS runs without
// importing the api package (avoids circular dependency).
type AgentDispatchFn func(agentID, scenarioID, techniqueID string) (runID string, err error)

// ── Variable system ───────────────────────────────────────────────────────────

// VarType classifies how a variable value is supplied.
type VarType string

const (
	// VarTypeString is a plain text value supplied by the operator at launch time.
	VarTypeString VarType = "string"
	// VarTypeEmailList is a comma-separated list of email addresses.
	VarTypeEmailList VarType = "email_list"
	// VarTypeEndpoint is a BAS agent ID.
	VarTypeEndpoint VarType = "endpoint_id"
	// VarTypeDuration is a Go duration string ("30m", "4h").
	VarTypeDuration VarType = "duration"
	// VarTypeSecret is resolved from an environment variable at runtime —
	// never stored in plan or execution JSON.
	VarTypeSecret VarType = "secret"
	// VarTypeRuntime is generated when the execution starts (e.g. RandomToken).
	VarTypeRuntime VarType = "runtime"
)

// VarDef declares one variable in a plan or template.
type VarDef struct {
	Name        string  `json:"name"`
	Type        VarType `json:"type"`
	Default     string  `json:"default,omitempty"`
	Required    bool    `json:"required,omitempty"`
	Description string  `json:"description,omitempty"`
	// SecretEnv is the OS environment variable name for VarTypeSecret.
	SecretEnv string `json:"secret_env,omitempty"`
}

// ── Template ──────────────────────────────────────────────────────────────────

// Template is a parameterized exercise plan blueprint.
// Templates ship with the platform; operators can also author custom ones.
type Template struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Version     int       `json:"version"`
	Category    string    `json:"category"`   // "phishing" | "ransomware" | "insider" | …
	Description string    `json:"description"`
	Variables   []VarDef  `json:"variables"`
	Steps       []PlanStep `json:"steps"`
	BuiltIn     bool      `json:"built_in"`
	Author      string    `json:"author"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
