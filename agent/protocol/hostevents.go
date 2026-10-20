package protocol

import "time"

// HostEventRecord is one Windows Security event the agent collected for a run.
// Only the fields the evaluator uses are sent.
type HostEventRecord struct {
	RecordID    uint64    `json:"recordId"`
	EventID     int       `json:"eventId"`
	Host        string    `json:"host"`
	Time        time.Time `json:"ts"`
	Subject     string    `json:"subject,omitempty"`
	NewProcess  string    `json:"newProcess,omitempty"`
	CommandLine string    `json:"commandLine,omitempty"`
	LogonType   int       `json:"logonType,omitempty"`
	TargetUser  string    `json:"targetUser,omitempty"`
}

// AuditSnapshot is the audit state the agent read for the subcategories behind the
// events. Each value is "enabled", "disabled" or "unknown".
type AuditSnapshot struct {
	ProcessCreation string `json:"processCreation"`
	Logon           string `json:"logon"`
	CommandLine     string `json:"commandLine"`
}

// RunHostEvents is the host-event payload for one run. It is kept apart from
// RunDetections, because execution evidence and detection evidence are different.
type RunHostEvents struct {
	RunID      string            `json:"runId"`
	AgentID    string            `json:"agentId"`
	Events     []HostEventRecord `json:"events"`
	Audit      AuditSnapshot     `json:"audit"`
	WindowFrom time.Time         `json:"windowFrom"`
	WindowTo   time.Time         `json:"windowTo"`
	Truncated  bool              `json:"truncated"`
}
