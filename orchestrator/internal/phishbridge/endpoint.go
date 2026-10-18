package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/actions"
	"github.com/audspect/bas/internal/phishval"
	"github.com/audspect/bas/internal/vendors/defender"
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

// FromIndependentlyVerifiedEndpointIsolation translates a real,
// independently re-read defender.MachineAction (obtained via
// defender.Client.GetMachineAction/PollMachineActionUntilTerminal,
// called AFTER actions.Execute's own dispatch returned) into
// phishval's Response dimension. This is strictly stronger evidence
// than FromEPPResponseAction's own dispatch-level claim above:
// Status == "Succeeded" here comes from a SEPARATE read of Defender's
// own machineAction record (learn.microsoft.com's documented resource,
// confirmed enum: Pending/InProgress/Succeeded/Failed/TimeOut/
// Cancelled), not from the dispatch call's own acceptance response --
// the independent postcondition verification this scenario previously
// had no real way to perform.
//
// Scoped to Defender only. CrowdStrike's and SentinelOne's own
// equivalent containment-status fields are not confirmed against an
// authoritative API source (only third-party integration docs, no
// official vendor schema found) -- the same bar
// internal/vendors/sentinelone's own Agent type already holds itself
// to ("kept deliberately minimal... only fields corroborated with
// enough independent third-party agreement to ship as typed fields").
// This function is never called for those two vendors' actions; their
// own follow-through claim stays at FromEPPResponseAction's
// dispatch-level tier until that evidence bar is met.
func FromIndependentlyVerifiedEndpointIsolation(action defender.MachineAction) phishval.Observation {
	const source = "defender-machineaction-independent-reverify"
	switch action.Status {
	case "Succeeded":
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseRemediated, ActionRequired: action.Type, Timestamp: time.Now(),
			Source: source, Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			Detail: "independently re-read Defender machineAction " + action.ID + " reached status=Succeeded",
		}}
	case "Failed", "TimeOut", "Cancelled":
		return phishval.Observation{Response: &phishval.ResponseObservation{
			Outcome: phishval.ResponseFailed, ActionRequired: action.Type, Timestamp: time.Now(),
			Source: source, Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
			Detail: "independently re-read Defender machineAction " + action.ID + " reached status=" + action.Status,
		}}
	default: // Pending/InProgress -- still in flight, never a terminal claim
		return phishval.Observation{}
	}
}
