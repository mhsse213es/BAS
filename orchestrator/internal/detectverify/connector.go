// Package detectverify queries Microsoft Sentinel and Microsoft Defender XDR
// for whether they detected a run's executed techniques, then writes the
// verdict into the Verification Store (internal/verification) with
// Source=api. It is deliberately independent of internal/siem — see
// docs/superpowers/specs/2026-07-14-detection-verification-connectors-design.md
// for why the two packages are not merged.
//
// This package does no database I/O. internal/api owns the
// detection_connectors config table and calls VerifyRun (orchestrate.go)
// with everything it needs already loaded.
package detectverify

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// Verdicts a connector can return for one expectation.
const (
	VerdictDetected    = "Detected"
	VerdictNotDetected = "NotDetected"
)

// Confidence levels matchAlerts assigns to a Detected verdict.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
)

// Config holds the connection settings for one detection connector —
// persisted in detection_connectors, loaded by internal/api and passed to
// NewConnector.
type Config struct {
	ID                 string
	Name               string
	Provider           string // "microsoft_sentinel" | "microsoft_defender" | "splunk" | "qradar" | "crowdstrike" | "trellix"
	Enabled            bool
	AutoVerify         bool
	TenantID           string
	ClientID           string
	ClientSecret       string
	WorkspaceID        string // Sentinel only; empty for Defender XDR
	BaseURL            string // Splunk/QRadar: management API base URL
	APIToken           string // Splunk/QRadar: bearer token
	VerifyDelaySeconds int
}

// VerifyRequest is one expectation to check against a provider, scoped to a
// single host and time window.
type VerifyRequest struct {
	RunID          string
	ExpectationID  string
	TechniqueID    string
	HostName       string
	HostIP         string
	StepExecutedAt time.Time // the step's actual execution time — used for latency
	WindowStart    time.Time // padded query window start
	WindowEnd      time.Time // padded query window end
}

// MatchedAlert is one vendor alert that satisfied a VerifyRequest.
type MatchedAlert struct {
	AlertID   string          `json:"alertId"`
	RuleName  string          `json:"ruleName"`
	Timestamp time.Time       `json:"timestamp"`
	Severity  string          `json:"severity"`
	RawJSON   json.RawMessage `json:"raw,omitempty"`
}

// VerifyResult is the outcome of checking one expectation against a provider.
type VerifyResult struct {
	Verdict          string // Detected | NotDetected
	Confidence       string // high | medium ("" when NotDetected)
	MatchedAlerts    []MatchedAlert
	DetectionLatency time.Duration // 0 when NotDetected
	InvestigationURL string
}

// Connector is one vendor's detection-verification API client.
type Connector interface {
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
	TestConnection(ctx context.Context) error
}

// NewConnector builds the Connector for cfg.Provider. Returns an error for
// any provider not yet implemented — Elastic arrives in a later slice using
// this same framework.
func NewConnector(cfg Config) (Connector, error) {
	switch cfg.Provider {
	case "microsoft_sentinel":
		return newSentinelConnector(cfg), nil
	case "microsoft_defender":
		return newDefenderXDRConnector(cfg), nil
	case "splunk":
		return newSplunkConnector(cfg), nil
	case "qradar":
		return newQRadarConnector(cfg), nil
	case "crowdstrike":
		return newCrowdStrikeConnector(cfg), nil
	case "trellix":
		return newTrellixConnector(cfg), nil
	default:
		return nil, fmt.Errorf("detectverify: provider %q not supported", cfg.Provider)
	}
}
