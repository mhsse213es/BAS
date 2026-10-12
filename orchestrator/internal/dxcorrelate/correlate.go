package dxcorrelate

import (
	"fmt"
	"sort"
	"time"
)

// MaxCorrelationWindow is deliberately generous: this correlates
// simulated/fake-backed evidence today, not real attacker telemetry, so
// tuning a realistic threshold is explicitly deferred to the
// real-observer sub-project.
const MaxCorrelationWindow = 24 * time.Hour

// Correlate always returns exactly 3 LegEvidence entries, in allLegs'
// fixed order. Classification is computed from Behavior alone --
// ControlEfficacy is carried through purely as context (design spec
// section A).
func Correlate(rows []AttemptRow) CorrelationResult {
	legs := make([]LegEvidence, 0, 3)
	for _, leg := range allLegs {
		legs = append(legs, selectLegEvidence(leg, rows))
	}
	classification := classify(legs)
	anomaly := ""
	if isConfirmedClassification(classification) {
		if issue := orderingOrWindowIssue(legs); issue != "" {
			classification = ClassificationPartialBehaviorEvidence
			anomaly = issue
		}
	}
	return CorrelationResult{Legs: legs, Classification: classification, Anomaly: anomaly}
}

func isConfirmedClassification(c Classification) bool {
	return c == ClassificationThreeLegConfirmed ||
		c == ClassificationExfiltrationConfirmedEncryptionNotEstablished ||
		c == ClassificationEncryptionConfirmedExfiltrationNotEstablished
}

// orderingOrWindowIssue checks only the Occurred legs, in allLegs' fixed
// canonical order (staging, transfer, encryption) -- a coherent
// double-extortion sequence requires each later leg's evidence to arrive
// no earlier, and no more than MaxCorrelationWindow later, than the
// previous one.
func orderingOrWindowIssue(legs []LegEvidence) string {
	var occurred []LegEvidence
	for _, l := range legs {
		if l.Behavior == BehaviorOccurred {
			occurred = append(occurred, l)
		}
	}
	for i := 1; i < len(occurred); i++ {
		prev, cur := occurred[i-1], occurred[i]
		if cur.CreatedAt.Before(prev.CreatedAt) {
			return fmt.Sprintf("out-of-order evidence: %s (%s) occurs before %s (%s)", cur.Leg, cur.CreatedAt, prev.Leg, prev.CreatedAt)
		}
		if gap := cur.CreatedAt.Sub(prev.CreatedAt); gap > MaxCorrelationWindow {
			return fmt.Sprintf("temporally unrelated evidence: %s to %s gap of %s exceeds max correlation window of %s", prev.Leg, cur.Leg, gap, MaxCorrelationWindow)
		}
	}
	return ""
}

// selectLegEvidence picks, among rows matching leg, the earliest row
// with Behavior == Occurred (deterministic: ties and reordering of the
// input slice never change the result, since selection is by timestamp,
// not input order). If none occurred, falls back to the earliest row of
// any kind for its ControlEfficacy context; with no rows at all for this
// leg, reports NoEvidence/NotEstablished.
func selectLegEvidence(leg Leg, rows []AttemptRow) LegEvidence {
	var matching []AttemptRow
	for _, r := range rows {
		if r.Leg == leg {
			matching = append(matching, r)
		}
	}
	if len(matching) == 0 {
		return LegEvidence{Leg: leg, ControlEfficacy: EfficacyNoEvidence, Behavior: BehaviorNotEstablished}
	}
	sort.Slice(matching, func(i, j int) bool { return matching[i].CreatedAt.Before(matching[j].CreatedAt) })
	for _, r := range matching {
		if r.Behavior == BehaviorOccurred {
			return LegEvidence{Leg: leg, ControlEfficacy: r.ControlEfficacy, Behavior: BehaviorOccurred, CreatedAt: r.CreatedAt, Reason: r.Reason}
		}
	}
	first := matching[0]
	return LegEvidence{Leg: leg, ControlEfficacy: first.ControlEfficacy, Behavior: BehaviorNotEstablished, CreatedAt: first.CreatedAt, Reason: first.Reason}
}

func classify(legs []LegEvidence) Classification {
	byLeg := map[Leg]LegEvidence{}
	for _, l := range legs {
		byLeg[l.Leg] = l
	}
	staging := byLeg[LegStaging].Behavior == BehaviorOccurred
	transfer := byLeg[LegTransfer].Behavior == BehaviorOccurred
	encryption := byLeg[LegEncryption].Behavior == BehaviorOccurred

	switch {
	case staging && transfer && encryption:
		return ClassificationThreeLegConfirmed
	case staging && transfer && !encryption:
		return ClassificationExfiltrationConfirmedEncryptionNotEstablished
	case encryption && (!staging || !transfer):
		return ClassificationEncryptionConfirmedExfiltrationNotEstablished
	case staging || transfer || encryption:
		return ClassificationPartialBehaviorEvidence
	default:
		return ClassificationInsufficientBehaviorEvidence
	}
}
