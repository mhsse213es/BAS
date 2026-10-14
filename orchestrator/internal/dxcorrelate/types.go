// Package dxcorrelate correlates staging, transfer, and encryption
// evidence into a double-extortion classification. It is pure Go, with
// no DB or HTTP import, and deliberately decoupled from
// rwevidence.Capability -- the API-layer adapter (internal/api) is the
// one place allowed to know both this package's Leg vocabulary and MITRE
// technique IDs.
//
// The central rule (design spec section A): ControlEfficacyStatus
// measures how a security control responded to an attempt; it never
// establishes that the underlying behavior (staging/transfer/encryption)
// actually occurred. BehaviorOccurred is set only by a genuine
// direct-observation signal -- none exists in this codebase today, for
// any leg -- never derived from a Verdict/ControlEfficacy value.
package dxcorrelate

import "time"

type Leg string

const (
	LegStaging    Leg = "staging"
	LegTransfer   Leg = "transfer"
	LegEncryption Leg = "encryption"
)

// allLegs is the fixed, canonical order every CorrelationResult.Legs
// follows -- also the expected chronological order for ordering checks
// (Task 3).
var allLegs = []Leg{LegStaging, LegTransfer, LegEncryption}

type ControlEfficacyStatus string

const (
	EfficacyDetected      ControlEfficacyStatus = "detected"
	EfficacyNotDetected   ControlEfficacyStatus = "not_detected"
	EfficacyNotApplicable ControlEfficacyStatus = "not_applicable"
	EfficacyNoEvidence    ControlEfficacyStatus = "no_evidence"
)

type BehaviorStatus string

const (
	BehaviorOccurred       BehaviorStatus = "occurred"
	BehaviorNotEstablished BehaviorStatus = "not_established"
)

// AttemptRow is one piece of evidence for one leg, as the API-layer
// adapter produces it.
type AttemptRow struct {
	Leg             Leg
	Action          string
	ControlEfficacy ControlEfficacyStatus
	Behavior        BehaviorStatus
	Reason          string
	CreatedAt       time.Time
}

// LegEvidence is one leg's selected evidence after Correlate has resolved
// duplicates (earliest-Occurred-wins, see correlate.go).
type LegEvidence struct {
	Leg             Leg
	ControlEfficacy ControlEfficacyStatus
	Behavior        BehaviorStatus
	CreatedAt       time.Time
	Reason          string
}

type Classification string

const (
	ClassificationThreeLegConfirmed                             Classification = "three_leg_confirmed"
	ClassificationExfiltrationConfirmedEncryptionNotEstablished Classification = "exfiltration_confirmed_encryption_not_established"
	ClassificationEncryptionConfirmedExfiltrationNotEstablished Classification = "encryption_confirmed_exfiltration_not_established"
	ClassificationPartialBehaviorEvidence                       Classification = "partial_behavior_evidence"
	ClassificationInsufficientBehaviorEvidence                  Classification = "insufficient_behavior_evidence"
)

// CorrelationResult always carries exactly 3 Legs, in allLegs' fixed
// order. Anomaly is set only when an ordering or time-window violation
// (Task 3) downgraded what would otherwise have been a confirmed
// classification.
type CorrelationResult struct {
	Legs           []LegEvidence
	Classification Classification
	Anomaly        string
}
