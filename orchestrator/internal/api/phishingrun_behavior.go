package api

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/exercise"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishval"
)

// detTriageWindow is how long after an execution's creation SOC triage evidence is
// read for PH-DET-002. The window runs forward from the execution, because triage
// happens after a report, not before it.
const detTriageWindow = 24 * time.Hour

// executePHDET002 checks whether SOC triage created a ticket for the report event
// named by params["executionId"] and params["targetId"].
//
// The evidence window is anchored to the execution's persisted creation time, not
// to the moment the check runs. Re-grading the same execution therefore searches the
// same interval. The window is recorded in the verdict reason, so a reader can see
// what was searched.
//
// Missing evidence is never treated as a missed ticket. A missing connector, an
// unreadable execution, or a collection error yields Inconclusive.
func executePHDET002(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	executionID, _ := params["executionId"].(string)
	targetID, _ := params["targetId"].(string)
	if executionID == "" || targetID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-DET-002 requires non-empty executionId and targetId parameters")
	}

	exp := phishbridge.ReportTicketExpectation{
		ExecutionID: executionID, TargetID: targetID, ExpectedTicketCreated: true,
	}

	var verdict emailgwefficacy.VerdictDetail
	var anchor time.Time
	var windowNote string
	switch {
	case env.ReportTicketProvider == nil:
		// No ITSM connector is wired on this deployment. That is "not configured",
		// never "ran and found no ticket".
		verdict = emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive,
			Reason: "phishingrun: no ReportTicketEvidenceProvider configured on this deployment"}
	case env.Pool == nil:
		verdict = emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive,
			Reason: "phishingrun: no database pool, so the execution time that anchors the evidence window cannot be read"}
	default:
		ex, err := exercise.NewStore(env.Pool).GetExecution(ctx, executionID)
		if err != nil {
			verdict = emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive,
				Reason: fmt.Sprintf("execution %q could not be read, so the evidence window cannot be anchored: %v", executionID, err)}
			break
		}
		anchor = ex.CreatedAt
		window := emailgwefficacy.TimeWindow{Start: anchor, End: anchor.Add(detTriageWindow)}
		verdict = phishbridge.VerifyReportTicketExpectation(exp, env.ReportTicketProvider, window)
		windowNote = fmt.Sprintf("evidence window %s to %s, anchored to execution creation",
			window.Start.UTC().Format(time.RFC3339), window.End.UTC().Format(time.RFC3339))
	}

	obs := phishbridge.FromSingleDimensionResponseVerdict(verdict, "phishingrun-PH-DET-002")
	// The response observation stamps time.Now(). That would change on every regrade,
	// so use the execution's anchor when there is one.
	if obs.Response != nil && !anchor.IsZero() {
		obs.Response.Timestamp = anchor
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-DET-002")
	if err != nil {
		return phishval.Outcome{}, err
	}
	outcome := phishval.Evaluate(runID, "", catalogExp, obs)
	if windowNote != "" {
		outcome.Response.Reason = windowNote + "; " + outcome.Response.Reason
	}
	return outcome, nil
}

// executePHID001 reports the observed user behavior for the execution named by
// params["executionId"]. It is behavioral evidence, not a control-efficacy verdict.
//
// PH-ID-001 measures what the targeted user did: opened, clicked, submitted, or
// reported. A user who did not click is not a failed identity control. Whether a
// control should have stopped the action, and whether it did, needs separate
// evidence. So the user-interaction dimension never gets a pass or fail. Each
// result is one of:
//   - the observed behavior, with its evidence source;
//   - no interaction observed, in the execution's window;
//   - Inconclusive, when the telemetry cannot be read.
//
// An unknown execution is a refused request, not a result, so it returns an error.
func executePHID001(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	executionID, _ := params["executionId"].(string)
	if executionID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-001 requires a non-empty executionId parameter")
	}
	if env.Pool == nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-001 requires a database pool (deployment misconfiguration)")
	}

	store := exercise.NewStore(env.Pool)
	ex, err := store.GetExecution(ctx, executionID)
	if err != nil {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-ID-001 execution %q not found: %w", executionID, err)
	}

	var obs phishval.Observation
	events, err := store.ListEvidence(ctx, executionID)
	if err != nil {
		obs = phishval.Observation{UserInteraction: &phishval.UserInteractionObservation{
			Outcome: phishval.InteractionUnknown, Timestamp: ex.CreatedAt, Source: "exercise-tracker",
			Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient,
			Detail: fmt.Sprintf("tracked interaction telemetry could not be read: %v", err),
		}}
	} else {
		obs = phishbridge.FromExerciseInteractionEvidence(eventsSince(events, ex.CreatedAt))
		// "No interaction" has no event time of its own. Stamp it with the execution's
		// creation time, not time.Now(), so a regrade reports the same observation.
		if obs.UserInteraction != nil && obs.UserInteraction.Outcome == phishval.InteractionNone {
			obs.UserInteraction.Timestamp = ex.CreatedAt
		}
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-ID-001")
	if err != nil {
		return phishval.Outcome{}, err
	}
	outcome := phishval.Evaluate(runID, "", catalogExp, obs)
	// The behavior dimension replaces the expectation-based pass or fail. It records what
	// the user did, not whether a control worked.
	outcome.UserInteraction = behaviorDimension(obs.UserInteraction)
	return outcome, nil
}

// eventsSince keeps only evidence recorded at or after the execution's creation. Earlier
// rows cannot belong to this execution's run.
func eventsSince(events []exercise.Evidence, start time.Time) []exercise.Evidence {
	out := events[:0:0]
	for _, e := range events {
		if !e.CreatedAt.Before(start) {
			out = append(out, e)
		}
	}
	return out
}

// behaviorDimension states what the user did, and never claims a control result.
// Missing telemetry is Inconclusive. Anything observed is NotApplicable: no control
// verdict applies to a behavior by itself.
func behaviorDimension(u *phishval.UserInteractionObservation) phishval.DimensionResult {
	const note = " This is behavioral evidence, not a control-efficacy verdict."
	if u == nil || u.Outcome == phishval.InteractionUnknown {
		detail := "no behavioral telemetry was collected"
		if u != nil && u.Detail != "" {
			detail = u.Detail
		}
		return phishval.DimensionResult{Verdict: phishval.VerdictInconclusive,
			Reason: detail + "." + note, Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient}
	}
	return phishval.DimensionResult{
		Verdict:    phishval.VerdictNotApplicable,
		Reason:     fmt.Sprintf("observed user behavior: %s. %s%s", u.Outcome, u.Detail, note),
		Evidence:   u.Evidence,
		Confidence: u.Confidence,
	}
}
