package main

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// SimCategory is a group of related ATT&CK-aligned checks.
type SimCategory struct {
	Phase  string     `json:"phase"`
	Checks []SimCheck `json:"checks"`
}

// SimCheck is a single simulation result — matches orchestrator SimulationResult schema.
type SimCheck struct {
	ID           string    `json:"id"`
	Technique    Tech      `json:"technique"`
	Result       string    `json:"result"`   // pass | fail | skipped
	Severity     string    `json:"severity"` // Critical | High | Medium | Low
	ThreatImpact string    `json:"threatImpact"`
	Details      string    `json:"details"`
	Remediation  string    `json:"remediation"`
	RawOutput    string    `json:"rawOutput,omitempty"`
	DurationMs   int64     `json:"durationMs"`
	ExecutedAt   time.Time `json:"executedAt"`
	Framework    string    `json:"framework"`
}

// Tech is a MITRE ATT&CK technique reference.
type Tech struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
}

func checkID(techID, name string) string {
	h := sha256.Sum256([]byte(techID + "|" + name))
	return hex.EncodeToString(h[:])[:8]
}

func check(techID, name, tactic, severity, threat, fix string,
	fn func() (result, details string)) SimCheck {

	start := time.Now()
	result, details := fn()
	return SimCheck{
		ID:           checkID(techID, name),
		Technique:    Tech{ID: techID, Name: name, Tactic: tactic},
		Result:       result,
		Severity:     severity,
		ThreatImpact: threat,
		Details:      details,
		Remediation:  fix,
		DurationMs:   time.Since(start).Milliseconds(),
		ExecutedAt:   time.Now(),
		Framework:    "custom",
	}
}
