package dxcorrelate

import "sort"

// Correlate always returns exactly 3 LegEvidence entries, in allLegs'
// fixed order. Classification is computed from Behavior alone --
// ControlEfficacy is carried through purely as context (design spec
// section A).
func Correlate(rows []AttemptRow) CorrelationResult {
	legs := make([]LegEvidence, 0, 3)
	for _, leg := range allLegs {
		legs = append(legs, selectLegEvidence(leg, rows))
	}
	return CorrelationResult{Legs: legs, Classification: classify(legs)}
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
