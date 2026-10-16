// Package wafdetection is a vendor-neutral, I/O-free evaluator covering
// waf.txt Phase 8's detection-and-telemetry-validation items: WAF events,
// SIEM records, alerts, response timing, and evidence loss. Unlike every
// prior WAF-mastery phase, it validates the evidence pipeline's own
// trustworthiness rather than whether an attack was blocked, so it
// depends only on internal/wafval and never cross-references
// internal/wafcatalog or any sibling WAF-phase package -- no function in
// this package takes a wafcatalog.AttackVector, and there is no
// vector-ID mismatch guard anywhere. Fixture-backed only; real WAF/SIEM/
// alert-queue log collection is deferred.
package wafdetection

import (
	"fmt"

	"github.com/audspect/bas/internal/wafval"
)

// EvidenceChannel is one of the named telemetry destinations this
// package validates correlation/completeness against.
type EvidenceChannel string

const (
	ChannelWAFEventLog     EvidenceChannel = "waf_event_log"
	ChannelSIEMRecord      EvidenceChannel = "siem_record"
	ChannelAlertQueue      EvidenceChannel = "alert_queue"
	ChannelEvidenceArchive EvidenceChannel = "evidence_archive"
)

func validChannel(c EvidenceChannel) bool {
	switch c {
	case ChannelWAFEventLog, ChannelSIEMRecord, ChannelAlertQueue, ChannelEvidenceArchive:
		return true
	default:
		return false
	}
}

// CompletenessScenario is the claim that a given evidence channel
// produces findable, non-lost evidence for a correlated test execution.
type CompletenessScenario struct {
	ID          string
	Channel     EvidenceChannel
	Description string
	Provenance  string
}

// NewCompletenessScenario validates at construction time, never at
// render time.
func NewCompletenessScenario(id string, channel EvidenceChannel, description string, provenance string) (CompletenessScenario, error) {
	if id == "" {
		return CompletenessScenario{}, fmt.Errorf("id must not be empty")
	}
	if !validChannel(channel) {
		return CompletenessScenario{}, fmt.Errorf("channel %q is not one of the known EvidenceChannel constants", channel)
	}
	if description == "" {
		return CompletenessScenario{}, fmt.Errorf("description must not be empty")
	}
	if provenance == "" {
		return CompletenessScenario{}, fmt.Errorf("provenance must not be empty")
	}
	return CompletenessScenario{ID: id, Channel: channel, Description: description, Provenance: provenance}, nil
}

// CompletenessVerdict is the outcome of checking one channel's Coverage
// for one correlated test execution. EvidenceInconclusive is declared for
// enum symmetry with the other verdict types in this package, but
// EvaluateCompleteness itself always resolves to EvidencePresent or
// EvidenceLost given wafval.Coverage's four closed values -- it is never
// the practical result of a call.
type CompletenessVerdict string

const (
	EvidencePresent      CompletenessVerdict = "present"
	EvidenceLost         CompletenessVerdict = "lost"
	EvidenceInconclusive CompletenessVerdict = "inconclusive"
)

// EvaluateCompleteness reads result.Coverage.Present() -- true for
// CoverageFound or CoverageSearchedVerifiedNone (a verified-negative
// search still counts as complete evidence, not loss) -- and resolves
// everything else (CoverageSearchIncomplete, CoverageSourceUnavailable,
// or a zero-value CollectionResult the caller never populated) to
// EvidenceLost: the channel could not establish whether evidence exists
// either way.
func EvaluateCompleteness(scenario CompletenessScenario, result wafval.CollectionResult) (CompletenessVerdict, string, error) {
	if result.Coverage.Present() {
		return EvidencePresent, fmt.Sprintf("%s channel evidence present (coverage=%q)", scenario.Channel, result.Coverage), nil
	}
	return EvidenceLost, fmt.Sprintf("%s channel search could not establish whether evidence exists (coverage=%q)", scenario.Channel, result.Coverage), nil
}
