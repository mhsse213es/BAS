package phishbridge

import (
	"testing"
	"time"

	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishval"
)

func evidenceAt(evType string, at time.Time) exercise.Evidence {
	return exercise.Evidence{EvidenceType: evType, CreatedAt: at}
}

func TestPHID001_EndToEnd_KnownGood_NoCredentialSubmission(t *testing.T) {
	events := []exercise.Evidence{evidenceAt("email_opened", time.Now()), evidenceAt("link_clicked", time.Now())}
	obs := FromExerciseInteractionEvidence(events)
	outcome := phishval.Evaluate("run-ph-id-001", "known-good", catalogExpectation(t, "PH-ID-001"), obs)
	if outcome.UserInteraction.Verdict != phishval.VerdictPass {
		t.Errorf("UserInteraction.Verdict = %q (%s), want %q", outcome.UserInteraction.Verdict, outcome.UserInteraction.Reason, phishval.VerdictPass)
	}
}

func TestPHID001_EndToEnd_KnownBad_CredentialsSubmitted(t *testing.T) {
	events := []exercise.Evidence{evidenceAt("email_opened", time.Now()), evidenceAt("credentials_submitted", time.Now())}
	obs := FromExerciseInteractionEvidence(events)
	outcome := phishval.Evaluate("run-ph-id-001", "known-bad", catalogExpectation(t, "PH-ID-001"), obs)
	if outcome.UserInteraction.Verdict != phishval.VerdictFail {
		t.Errorf("UserInteraction.Verdict = %q, want %q", outcome.UserInteraction.Verdict, phishval.VerdictFail)
	}
}

func TestFromExerciseInteractionEvidence_NoEvents_GradesNoneNotUnknown(t *testing.T) {
	obs := FromExerciseInteractionEvidence(nil)
	if obs.UserInteraction == nil || obs.UserInteraction.Outcome != phishval.InteractionNone {
		t.Errorf("Outcome = %v, want %q (ListEvidence is authoritative -- absence of evidence IS the evidence here, never Unknown)", obs.UserInteraction, phishval.InteractionNone)
	}
}

func TestFromExerciseInteractionEvidence_ReportAfterClick_GradesReportedNotClicked(t *testing.T) {
	events := []exercise.Evidence{
		evidenceAt("link_clicked", time.Now()),
		evidenceAt("phishing_reported", time.Now().Add(time.Minute)),
	}
	obs := FromExerciseInteractionEvidence(events)
	if obs.UserInteraction.Outcome != phishval.InteractionReported {
		t.Errorf("Outcome = %q, want %q (a later report is the best-case outcome, not overridden by an earlier click)", obs.UserInteraction.Outcome, phishval.InteractionReported)
	}
}

func TestFromExerciseInteractionEvidence_SubmissionBeatsClickAndOpen(t *testing.T) {
	events := []exercise.Evidence{
		evidenceAt("email_opened", time.Now()),
		evidenceAt("link_clicked", time.Now()),
		evidenceAt("credentials_submitted", time.Now()),
	}
	obs := FromExerciseInteractionEvidence(events)
	if obs.UserInteraction.Outcome != phishval.InteractionSimulatedSubmission {
		t.Errorf("Outcome = %q, want %q", obs.UserInteraction.Outcome, phishval.InteractionSimulatedSubmission)
	}
}

func TestFromExerciseInteractionEvidence_OpenOnly_GradesOpened(t *testing.T) {
	obs := FromExerciseInteractionEvidence([]exercise.Evidence{evidenceAt("email_opened", time.Now())})
	if obs.UserInteraction.Outcome != phishval.InteractionOpened {
		t.Errorf("Outcome = %q, want %q", obs.UserInteraction.Outcome, phishval.InteractionOpened)
	}
}
