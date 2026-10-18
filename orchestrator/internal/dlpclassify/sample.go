package dlpclassify

import (
	"fmt"
	"time"
)

// ClassificationEvidence is one normalized record of what the
// evaluated product actually reported for one sample on one channel.
type ClassificationEvidence struct {
	SampleID string `json:"sampleId"`
	// Channel names which submission path produced this evidence --
	// e.g. "web-upload", "email-attachment", "endpoint-usb". Empty
	// when the corpus's evaluation doesn't distinguish channels.
	// Carries cross-channel consistency: the SAME SampleID evaluated
	// through two channels produces two independent
	// ClassificationEvidence records, one per Channel.
	Channel            string                 `json:"channel,omitempty"`
	Decision           ClassificationDecision `json:"decision"`
	ObservedClass      SensitivityClass       `json:"observedClass,omitempty"` // populated only when Decision == DecisionExplicitSensitive
	MatchedPattern     string                 `json:"matchedPattern,omitempty"`
	Confidence         float64                `json:"confidence,omitempty"`
	ConfidenceReported bool                   `json:"confidenceReported"` // distinguishes "0.0 confidence reported" from "no confidence value available"
	Timestamp          time.Time              `json:"timestamp"`
	Source             EvidenceSource         `json:"source"`
	Provenance         Provenance             `json:"provenance"`
}

// ClassificationEvidenceProvider supplies classification evidence for
// a sample ID, channel, and time window. A returned error means
// collection failed -- distinct from a successful search that found
// nothing (nil error, empty slice).
type ClassificationEvidenceProvider interface {
	ClassificationEvidenceFor(sampleID, channel string, window TimeWindow) ([]ClassificationEvidence, error)
}

// FixtureClassificationEvidenceProvider wraps an in-memory slice of
// hand-built ClassificationEvidence values -- no real vendor
// classification API is called in this slice.
type FixtureClassificationEvidenceProvider struct {
	events []ClassificationEvidence
}

func NewFixtureClassificationEvidenceProvider(events []ClassificationEvidence) *FixtureClassificationEvidenceProvider {
	return &FixtureClassificationEvidenceProvider{events: events}
}

func (p *FixtureClassificationEvidenceProvider) ClassificationEvidenceFor(sampleID, channel string, window TimeWindow) ([]ClassificationEvidence, error) {
	var out []ClassificationEvidence
	for _, e := range p.events {
		if e.SampleID != sampleID || e.Channel != channel {
			continue
		}
		if e.Timestamp.Before(window.Start) || e.Timestamp.After(window.End) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyClassificationSample compares one sample's ground truth
// against the evidence from one channel. Unlike dlppolicy's Verify
// functions, there is no asOf -- a classification decision has no
// time-based expiry concept of its own; only window bounds evidence
// relevance. Cross-channel consistency is not a separate evaluator:
// call this once per channel for the same SampleID and compare the
// resulting DLPCLSVerdicts via CompareChannelVerdicts.
func VerifyClassificationSample(truth GroundTruth, channel string, provider ClassificationEvidenceProvider, window TimeWindow) DLPCLSVerdict {
	records, err := provider.ClassificationEvidenceFor(truth.SampleID, channel, window)
	if err != nil {
		return DLPCLSVerdict{Outcome: OutcomeInconclusive, Reason: fmt.Sprintf("classification evidence collection failed: %v", err)}
	}
	if len(records) == 0 {
		return DLPCLSVerdict{Outcome: OutcomeNotTested, Reason: "sample was never submitted for evaluation on this channel in this window"}
	}
	latest := latestClassificationEvidenceByTimestamp(records)

	if latest.Decision == DecisionUnsupportedFormat {
		return DLPCLSVerdict{Outcome: OutcomeUnsupported, Reason: fmt.Sprintf("product does not support this file format or operation: %s", truth.Format)}
	}
	switch latest.Decision {
	case DecisionLabelOnly:
		return DLPCLSVerdict{Outcome: OutcomeInconclusive, Reason: "a label was applied but the underlying classification decision was not exposed"}
	case DecisionInspectionFailed:
		return DLPCLSVerdict{Outcome: OutcomeInconclusive, Reason: "product attempted but failed to inspect the file"}
	case DecisionNoEvidenceReturned:
		return DLPCLSVerdict{Outcome: OutcomeInconclusive, Reason: "product returned no usable evidence either way"}
	}
	if truth.IntendedClass == SensitivityClassAmbiguous {
		return DLPCLSVerdict{Outcome: OutcomeInconclusive, Reason: fmt.Sprintf("sample is ambiguous by design: %s", truth.AdjudicationPolicy)}
	}

	if truth.IntendedClass == SensitivityClassNone {
		if latest.Decision == DecisionExplicitBenign {
			return DLPCLSVerdict{Outcome: OutcomeTrueNegative}
		}
		return DLPCLSVerdict{Outcome: OutcomeFalsePositive, Reason: fmt.Sprintf("sample is benign but was classified as %q", latest.ObservedClass)}
	}

	if latest.Decision == DecisionExplicitBenign {
		return DLPCLSVerdict{Outcome: OutcomeFalseNegative, Reason: fmt.Sprintf("sample is %q but was classified as benign", truth.IntendedClass)}
	}
	if latest.ObservedClass == truth.IntendedClass {
		return DLPCLSVerdict{Outcome: OutcomeTruePositive}
	}
	return DLPCLSVerdict{Outcome: OutcomeMisclassified, Reason: fmt.Sprintf("sample is %q but was classified as %q", truth.IntendedClass, latest.ObservedClass)}
}

func latestClassificationEvidenceByTimestamp(records []ClassificationEvidence) ClassificationEvidence {
	latest := records[0]
	for _, r := range records[1:] {
		if r.Timestamp.After(latest.Timestamp) {
			latest = r
		}
	}
	return latest
}
