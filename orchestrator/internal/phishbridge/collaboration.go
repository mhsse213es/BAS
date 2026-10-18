package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// FromCreatedLure translates a dispatch error plus a
// phishidentity.CreatedState independent read-back (SharingInvite or
// CalendarEventLure, both verified the same way) into phishval's
// Delivery dimension for PH-CHN-002/PH-CHN-004.
//
// Delivery-only, deliberately: creation (confirmed by an independent
// read-back, never the creation call's own response alone) proves the
// lure reached the collaboration/calendaring API. It is never read as
// Enforcement, Detection, or UserInteraction evidence -- nothing here
// observes whether the recipient saw, opened, or acted on the lure, so
// this function cannot and does not produce that claim.
func FromCreatedLure(channel string, dispatchErr error, verified phishidentity.CreatedState, observedAt time.Time) phishval.Observation {
	if dispatchErr != nil {
		return phishval.Observation{Delivery: &phishval.DeliveryObservation{
			Outcome: phishval.DeliveryRejected, Timestamp: observedAt,
			Source: "phishidentity-" + channel, Evidence: phishval.EvidenceControlReceipt,
			Confidence: phishval.ConfidenceHigh, Detail: channel + " creation rejected: " + dispatchErr.Error(),
		}}
	}
	switch verified {
	case phishidentity.CreatedConfirmed:
		return phishval.Observation{Delivery: &phishval.DeliveryObservation{
			Outcome: phishval.DeliveryDelivered, Timestamp: observedAt,
			Source: "phishidentity-" + channel, Evidence: phishval.EvidenceVerifiedTelemetry,
			Confidence: phishval.ConfidenceHigh, Detail: channel + " independently confirmed present via a separate read-back, not inferred from the creation response alone",
		}}
	case phishidentity.CreatedMissing:
		return phishval.Observation{Delivery: &phishval.DeliveryObservation{
			Outcome: phishval.DeliveryRejected, Timestamp: observedAt,
			Source: "phishidentity-" + channel, Evidence: phishval.EvidenceVerifiedTelemetry,
			Confidence: phishval.ConfidenceHigh, Detail: channel + " creation call succeeded, but the independent read-back found nothing -- a confirmed non-creation",
		}}
	default: // phishidentity.CreatedUnknown
		return phishval.Observation{}
	}
}
