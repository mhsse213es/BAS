package exercise

import "time"

// StepType identifies what an exercise step does.
type StepType string

const (
	StepTypeSendEmail  StepType = "send_email"
	StepTypeSendSMS    StepType = "send_sms"
	StepTypeAgentTask  StepType = "agent_task"
	StepTypeWait       StepType = "wait"
	StepTypeApproval   StepType = "approval"
	StepTypeWebhook    StepType = "webhook"
	StepTypeNotify     StepType = "notify"
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
	// webhook
	WebhookURL     string            `json:"webhook_url,omitempty"`
	WebhookMethod  string            `json:"webhook_method,omitempty"`
	WebhookHeaders map[string]string `json:"webhook_headers,omitempty"`
	WebhookBody    string            `json:"webhook_body,omitempty"`
	// notify (same as email but to operator/admin, not exercise target)
	NotifyEmail string `json:"notify_email,omitempty"`
	NotifyMsg   string `json:"notify_msg,omitempty"`
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

// Plan is a reusable exercise DAG template.
type Plan struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Steps       []PlanStep `json:"steps"`
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
