package ticketing

import (
	"context"
	"fmt"
	"strings"
)

// Exercise tickets are drills a person may want to see in a real ITSM queue. They are always labelled so
// the SOC can tell them from real incidents, and they never carry finding-shaped text (technique, host).

// ExerciseSubjectPrefix starts every exercise ticket's title.
const ExerciseSubjectPrefix = "[BAS EXERCISE] "

// ExerciseLabel is the Jira label (and the marker a queue filter can use) on every exercise ticket.
const ExerciseLabel = "BAS-EXERCISE"

// Notifier is implemented by connectors that can open a free-form exercise ticket. The webhook connector
// does not implement it: a generic webhook has no notion of a ticket subject and body.
type Notifier interface {
	Notify(ctx context.Context, subject, body string, rt RecordType) (TicketRef, error)
}

// exerciseSubject returns the labelled title, cut to max characters, or an error for a blank subject.
func exerciseSubject(subject string, max int) (string, error) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return "", fmt.Errorf("exercise ticket needs a subject")
	}
	title := ExerciseSubjectPrefix + subject
	if len(title) > max {
		title = title[:max]
	}
	return title, nil
}

// exerciseDescription is the ticket body with a plain note that it is a simulation.
func exerciseDescription(body string) string {
	note := "This ticket was created by an Audspect BAS exercise. It is a simulation; no real incident has occurred."
	if strings.TrimSpace(body) == "" {
		return note
	}
	return body + "\n\n" + note
}

// NotifyStep opens one exercise ticket in the connector with id connectorID and reports what was created. It
// is what the exercise engine's ticket step calls. recordType may be blank (defaults to incident). Nothing is
// written to finding_tickets: an exercise ticket belongs to no finding.
func (m *Manager) NotifyStep(ctx context.Context, connectorID, subject, body, recordType string) (map[string]any, error) {
	rt := RecordType(recordType)
	if rt == "" {
		rt = RecordIncident
	}
	if !ValidRecordType(rt) {
		return nil, fmt.Errorf("ticketing: unknown record type %q", recordType)
	}
	m.mu.RLock()
	con, conOK := m.cons[connectorID]
	cfg, cfgOK := m.cfgs[connectorID]
	m.mu.RUnlock()
	if !conOK || !cfgOK {
		return nil, fmt.Errorf("ticketing: connector %q not found or disabled", connectorID)
	}
	n, ok := con.(Notifier)
	if !ok {
		return nil, fmt.Errorf("ticketing: the %s connector does not support exercise tickets", cfg.Provider)
	}
	ref, err := n.Notify(ctx, subject, body, rt)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", cfg.Provider, err)
	}
	return map[string]any{
		"channel":      "ticket",
		"provider":     cfg.Provider,
		"connector_id": connectorID,
		"record_type":  string(rt),
		"ticket_id":    ref.TicketID,
		"ticket_url":   ref.TicketURL,
	}, nil
}
