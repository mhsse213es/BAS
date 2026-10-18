package dlpclassify

import (
	"fmt"
	"time"
)

// LabelExpectation is what a document's sensitivity-label metadata
// should look like -- structurally parallel to
// dlppolicy.DLPPolicyRuleExpectation's declared-vs-observed check, but
// for a document's label, not a policy rule. Its own independent
// type: ScopeID is a plain string, never dlppolicy.ScopeID.
type LabelExpectation struct {
	DocumentID string `json:"documentId"`
	ScopeID    string `json:"scopeId"` // OU/site identifier, plain string -- dlppolicy.ScopeID is not reused

	ExpectedLabel         SensitivityClass `json:"expectedLabel"`
	ExpectedInheritedFrom string           `json:"expectedInheritedFrom,omitempty"` // non-empty when the label is expected to be inherited from a parent container, not set directly
	LabelAppliedAt        *time.Time       `json:"labelAppliedAt,omitempty"`
	MaxLabelAge           time.Duration    `json:"maxLabelAge,omitempty"` // 0 = staleness not checked
	Note                  string           `json:"note,omitempty"`
}

// LabelEvidence is one observed record of a document's actual label
// metadata. ObservedLabel == "" means no label is present.
type LabelEvidence struct {
	DocumentID            string           `json:"documentId"`
	ScopeID               string           `json:"scopeId"`
	ObservedLabel         SensitivityClass `json:"observedLabel,omitempty"` // empty = no label present
	ObservedInheritedFrom string           `json:"observedInheritedFrom,omitempty"`
	LastModifiedAt        time.Time        `json:"lastModifiedAt"`
	Timestamp             time.Time        `json:"timestamp"`
	Source                EvidenceSource   `json:"source"`
	Provenance            Provenance       `json:"provenance"`
}

// LabelEvidenceProvider supplies label evidence for a document/scope
// and time window.
type LabelEvidenceProvider interface {
	LabelEvidenceFor(documentID, scopeID string, window TimeWindow) ([]LabelEvidence, error)
}

// FixtureLabelEvidenceProvider wraps an in-memory slice of hand-built
// LabelEvidence values -- no live vendor label API is called in this
// slice.
type FixtureLabelEvidenceProvider struct {
	events []LabelEvidence
}

func NewFixtureLabelEvidenceProvider(events []LabelEvidence) *FixtureLabelEvidenceProvider {
	return &FixtureLabelEvidenceProvider{events: events}
}

func (p *FixtureLabelEvidenceProvider) LabelEvidenceFor(documentID, scopeID string, window TimeWindow) ([]LabelEvidence, error) {
	var out []LabelEvidence
	for _, e := range p.events {
		if e.DocumentID != documentID || e.ScopeID != scopeID {
			continue
		}
		if e.Timestamp.Before(window.Start) || e.Timestamp.After(window.End) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyLabelExpectation compares one document's expected label
// metadata against observed evidence as of asOf. Unlike
// VerifyClassificationSample, this evaluator has its own measurement
// dimension entirely: a label-lifecycle defect (missing, incorrect,
// wrong inheritance source, stale) is never counted as, or confused
// with, a classification-accuracy outcome -- see the DLPCLSOutcome
// constants' own doc comment in types.go.
func VerifyLabelExpectation(exp LabelExpectation, provider LabelEvidenceProvider, window TimeWindow, asOf time.Time) DLPCLSVerdict {
	records, err := provider.LabelEvidenceFor(exp.DocumentID, exp.ScopeID, window)
	if err != nil {
		return DLPCLSVerdict{Outcome: OutcomeInconclusive, Reason: fmt.Sprintf("label evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return DLPCLSVerdict{Outcome: OutcomeInconclusive, Reason: "no label evidence found for this document/scope in the window"}
	}
	latest := latestLabelEvidenceByTimestamp(records)

	observed := latest.ObservedLabel
	if observed == "" {
		observed = SensitivityClassNone
	}

	if observed == SensitivityClassNone && exp.ExpectedLabel != SensitivityClassNone {
		return DLPCLSVerdict{Outcome: OutcomeLabelMissing, Reason: fmt.Sprintf("expected label %q but no label is present", exp.ExpectedLabel)}
	}
	if observed != exp.ExpectedLabel {
		return DLPCLSVerdict{Outcome: OutcomeLabelIncorrect, Reason: fmt.Sprintf("expected label %q, observed %q", exp.ExpectedLabel, observed)}
	}
	if exp.ExpectedInheritedFrom != "" && latest.ObservedInheritedFrom != exp.ExpectedInheritedFrom {
		return DLPCLSVerdict{Outcome: OutcomeLabelWrongInheritance, Reason: fmt.Sprintf("label inherited from %q, expected inheritance from %q", latest.ObservedInheritedFrom, exp.ExpectedInheritedFrom)}
	}
	if exp.MaxLabelAge > 0 && asOf.Sub(latest.LastModifiedAt) > exp.MaxLabelAge {
		return DLPCLSVerdict{Outcome: OutcomeLabelStale, Reason: fmt.Sprintf("label last modified %s ago, exceeds max age %s", asOf.Sub(latest.LastModifiedAt), exp.MaxLabelAge)}
	}
	return DLPCLSVerdict{Outcome: OutcomeLabelCurrent}
}

func latestLabelEvidenceByTimestamp(records []LabelEvidence) LabelEvidence {
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest
}
