// Package ticketing connects BAS findings to external ITSM systems (ServiceNow,
// Jira, generic webhook). The design is analyst-gated: findings become ticket
// candidates; the analyst decides what gets pushed and as which record type.
// Auto-create is available but off by default to avoid ticket fatigue.
package ticketing

import (
	"context"
	"time"
)

// RecordType is the ITSM record type to create. Providers map these to their
// own concepts (ServiceNow tables, Jira issue types).
type RecordType string

const (
	RecordIncident        RecordType = "incident"
	RecordProblem         RecordType = "problem"
	RecordRisk            RecordType = "risk"
	RecordChangeRequest   RecordType = "change_request"
	RecordTask            RecordType = "task"
	RecordSecurityFinding RecordType = "security_finding"
)

// ValidRecordType returns true if rt is a known record type.
func ValidRecordType(rt RecordType) bool {
	switch rt {
	case RecordIncident, RecordProblem, RecordRisk, RecordChangeRequest, RecordTask, RecordSecurityFinding:
		return true
	}
	return false
}

// TicketFinding is the rich payload passed to connectors. All fields are
// pre-resolved by Manager.enrichFinding before dispatch — connectors never
// query the database.
type TicketFinding struct {
	FindingID       string
	TechniqueID     string
	TechniqueName   string
	Tactic          string
	Severity        string
	ControlClass    string
	ExposureState   string // "missed" | "detected_only"
	AgentID         string
	AgentHostname   string
	OccurrenceCount int
	FirstSeen       time.Time
	LastSeen        time.Time
	DaysExposed     int
	LastRunID       string
	Mitigations     []MitigationRef
	ComplianceMappings []ComplianceMapping
}

// MitigationRef is one ATT&CK mitigation attached to a finding.
type MitigationRef struct {
	Name        string
	Description string
}

// ComplianceMapping is one framework control impacted by the failing technique.
type ComplianceMapping struct {
	Framework   string
	ControlID   string
	ControlName string
}

// TicketRef is the external ticket reference returned after creation.
type TicketRef struct {
	TicketID  string
	TicketURL string
}

// Connector is the interface every ITSM provider implements.
type Connector interface {
	// CreateTicket opens a new ticket and returns its external ID + URL.
	CreateTicket(ctx context.Context, f TicketFinding, rt RecordType) (TicketRef, error)
	// AddComment appends a progress note to an existing ticket.
	AddComment(ctx context.Context, ticketID, body string) error
	// CloseTicket resolves the ticket after BAS-validated prevention.
	CloseTicket(ctx context.Context, ticketID string) error
	// ReopenTicket reopens a previously resolved ticket.
	ReopenTicket(ctx context.Context, ticketID string) error
	// GetStatus returns the current external status.
	GetStatus(ctx context.Context, ticketID string) (string, error)
	// TestConnection verifies credentials and reachability.
	TestConnection(ctx context.Context) error
}

// Config is one persisted connector configuration row.
type Config struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Provider   string            `json:"provider"` // "servicenow" | "jira" | "webhook"
	Enabled    bool              `json:"enabled"`
	AutoCreate string            `json:"autoCreate"` // "off" | "critical" | "critical_high" | "all"
	AutoUpdate bool              `json:"autoUpdate"`
	AutoClose  bool              `json:"autoClose"`
	Settings   map[string]string `json:"settings"`
}

// MaskedConfig returns a copy with sensitive settings values redacted.
func (c Config) MaskedConfig() Config {
	out := c
	out.Settings = make(map[string]string, len(c.Settings))
	for k, v := range c.Settings {
		if isSensitiveKey(k) {
			out.Settings[k] = "***"
		} else {
			out.Settings[k] = v
		}
	}
	return out
}

func isSensitiveKey(k string) bool {
	switch k {
	case "password", "api_token", "token", "secret", "client_secret":
		return true
	}
	return false
}

// SevPriority maps BAS severity to a 1-4 numeric priority string (1 = highest).
func SevPriority(sev string) string {
	switch sev {
	case "Critical":
		return "1"
	case "High":
		return "2"
	case "Medium":
		return "3"
	default:
		return "4"
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
