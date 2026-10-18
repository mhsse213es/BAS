package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/phishval"
)

// FromEPPResponseAction translates a real, already-dispatched
// internal/actions.Action -- CrowdStrike/Defender/SentinelOne isolate,
// kill-process, or quarantine-file, via actions.Execute's own real
// vendor API call -- into phishval's Response dimension for
// PH-IR-003 (endpoint follow-through after an email-delivered attack
// reaches the endpoint).
//
// This is dispatch-level evidence only, the same tier
// phishbridge.FromIdentityContainment started at in Phase 6 before
// PH-IR-002 gained real independent verification:
// actions.StatusCompleted means the EPP vendor accepted and completed
// the request, never that the host is independently confirmed
// isolated or the process independently confirmed dead --
// internal/rwevidence.ContainmentObserver (the one place in this
// codebase that performs that independent check) is itself
// fake-backed only, so there is no real postcondition verifier this
// bridge can call yet. That remains a named, honest gap, not silently
// upgraded to a stronger claim than the evidence supports.
func FromEPPResponseAction(action actions.Action) phishval.Observation {
	at := time.Now()
	if action.CompletedAt != nil {
		at = *action.CompletedAt
	}
	switch action.Status {
	case actions.StatusCompleted:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseRemediated, ActionRequired: action.Type, Timestamp: at,
			Source: "epp-response-actions", Evidence: phishval.EvidenceControlReceipt, Confidence: phishval.ConfidenceHigh,
			Detail: "EPP vendor accepted and completed the dispatched " + action.Type + " action -- dispatch-level evidence only, no independent postcondition verification",
		}}
	case actions.StatusFailed:
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseFailed, ActionRequired: action.Type, Timestamp: at,
			Source: "epp-response-actions", Evidence: phishval.EvidenceControlReceipt, Confidence: phishval.ConfidenceHigh,
			Detail: "EPP vendor rejected or failed the dispatched action: " + action.Error,
		}}
	default: // StatusRequested/StatusDispatched -- per actions.go's own doc,
		// Execute never returns with either of these once it has returned at
		// all, but this bridge never treats an in-flight status as a claim.
		return phishval.Observation{}
	}
}
