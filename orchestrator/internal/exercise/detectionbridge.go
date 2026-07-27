package exercise

import "github.com/audspect/bas/internal/verification"

// PendingEvidence is one exercise evidence row ResolveDetectionEvidence
// determined should be written. The Executor is responsible for the actual
// (stateful, hash-chained) write via EvidenceChain.Append.
type PendingEvidence struct {
	EvidenceType string
	Payload      map[string]any
}

// ResolveDetectionEvidence translates newly-approved verification records
// into exercise evidence. records is everything currently approved for the
// run (from verification.Store.CurrentApprovedForRun); alreadyRecorded is
// the set of expectation IDs this step execution has already emitted
// evidence for — dedup is an exercise concern (what counts as "already
// handled" for this step), not a verification-store concern, so it lives
// here, not in Store. Records with Result != "Detected" produce no
// evidence — this is translation, not gating; a NotDetected or
// NotApplicable record simply isn't evidence of anything happening yet.
func ResolveDetectionEvidence(records []verification.Record, alreadyRecorded map[string]bool) []PendingEvidence {
	var out []PendingEvidence
	for _, r := range records {
		if r.Result != "Detected" || alreadyRecorded[r.ExpectationID] {
			continue
		}
		evType := "security_control_detected"
		switch r.Domain {
		case "endpoint":
			evType = "edr_detected"
		case "siem":
			evType = "siem_alerted"
		}
		out = append(out, PendingEvidence{
			EvidenceType: evType,
			Payload: map[string]any{
				"expectation_id": r.ExpectationID,
				"run_id":         r.RunID,
				"technique_id":   r.TechniqueID,
				"control_domain": r.Domain,
				"provider":       r.Provider,
				"rule_ids":       r.RuleIDs,
			},
		})
	}
	return out
}
