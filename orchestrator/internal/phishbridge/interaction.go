package phishbridge

import (
	"time"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishval"
)

// FromExerciseInteractionEvidence translates exercise's own real,
// DB-backed interaction evidence (exercise.Store.ListEvidence for one
// execution) into phishval's UserInteraction dimension -- closing
// PH-ID-001's own previously-documented gap. That gap note ("no typed
// read-side accessor yet") was stale: exercise.Store.ListEvidence
// already exists and already returns everything needed; this function
// is the missing translation, not new storage plumbing.
//
// events should be the FULL evidence list for one execution. Because
// ListEvidence is authoritative for that execution, the absence of a
// given evidence type is read as that interaction genuinely not
// having happened -- InteractionNone, never InteractionUnknown --
// there is no partial-evidence case here the way there is for, say,
// SIEM correlation.
//
// Priority order mirrors how far the simulated target actually got: a
// report -- even one that came after a click -- is graded Reported,
// the best-case outcome a security awareness program can hope for; a
// credential submission (exercise/tracker records only the FACT of
// submission, real credential values are never captured or stored)
// beats a mere click; a click beats a mere open; nothing tracked at
// all is InteractionNone.
func FromExerciseInteractionEvidence(events []exercise.Evidence) phishval.Observation {
	var reported, submitted, clicked, opened *exercise.Evidence
	for i := range events {
		switch events[i].EvidenceType {
		case "phishing_reported":
			reported = &events[i]
		case "credentials_submitted":
			submitted = &events[i]
		case "link_clicked":
			clicked = &events[i]
		case "email_opened":
			opened = &events[i]
		}
	}

	switch {
	case reported != nil:
		return interactionObservation(phishval.InteractionReported, reported.CreatedAt,
			"target reported the simulated phishing message to the security team")
	case submitted != nil:
		return interactionObservation(phishval.InteractionSimulatedSubmission, submitted.CreatedAt,
			"target submitted the credential-harvest form -- exercise/tracker records only the fact of submission, real credential values are never captured or stored")
	case clicked != nil:
		return interactionObservation(phishval.InteractionClicked, clicked.CreatedAt,
			"target clicked the tracked link but did not submit credentials or report")
	case opened != nil:
		return interactionObservation(phishval.InteractionOpened, opened.CreatedAt,
			"target opened the message but took no further tracked action")
	default:
		return interactionObservation(phishval.InteractionNone, time.Now(),
			"no tracked interaction event exists for this execution")
	}
}

func interactionObservation(outcome phishval.UserInteractionOutcome, at time.Time, detail string) phishval.Observation {
	return phishval.Observation{UserInteraction: &phishval.UserInteractionObservation{
		Outcome: outcome, Timestamp: at, Source: "exercise-tracker",
		Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh, Detail: detail,
	}}
}
