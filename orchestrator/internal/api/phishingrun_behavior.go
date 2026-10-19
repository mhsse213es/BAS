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
	var collection *phishval.CollectionRecord
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
		snap := reportTicketSnapshot(env.ReportTicketProvider, executionID, targetID, window)
		verdict = phishbridge.VerifyReportTicketSnapshot(exp, snap)
		collection = collectionRecordFrom(snap)
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
	outcome.Collection = collection
	return outcome, nil
}

// reportTicketSnapshot runs one search. A provider that implements the completeness
// contract is used as is. Any other provider is treated as Partial.
func reportTicketSnapshot(p phishbridge.ReportTicketEvidenceProvider, executionID, targetID string, window emailgwefficacy.TimeWindow) phishbridge.ReportTicketSnapshot {
	sp, ok := p.(phishbridge.ReportTicketSnapshotProvider)
	if !ok {
		sp = phishbridge.SnapshotFromLegacy(p)
	}
	snap, err := sp.SnapshotReportTickets(executionID, targetID, window)
	if err != nil {
		return phishbridge.ReportTicketSnapshot{ExecutionID: executionID, TargetID: targetID, Window: window,
			CollectedAt: time.Now().UTC(), Completeness: phishval.CollectionFailed, Reason: fmt.Sprintf("collection error: %v", err)}
	}
	return snap
}

// collectionRecordFrom retains what one search established: its window, its time,
// its completeness, and the distinct ticket references it returned.
func collectionRecordFrom(snap phishbridge.ReportTicketSnapshot) *phishval.CollectionRecord {
	seen := map[string]bool{}
	var ids []string
	for _, r := range snap.Records {
		if r.TicketRef != "" && !seen[r.TicketRef] {
			seen[r.TicketRef] = true
			ids = append(ids, r.TicketRef)
		}
	}
	return &phishval.CollectionRecord{
		Source:       "itsm-report-ticket",
		WindowStart:  snap.Window.Start,
		WindowEnd:    snap.Window.End,
		CollectedAt:  snap.CollectedAt,
		Completeness: snap.Completeness,
		RecordIDs:    ids,
		Reason:       snap.Reason,
	}
}

// interactionWindowMax is the longest observation window PH-ID-001 may use. It is a
// product default. A longer window needs an explicit design decision, not an override.
const interactionWindowMax = 72 * time.Hour

// interactionWindow is PH-ID-001's observation window. It starts at the execution's
// persisted creation time, not at check time. It ends at the earlier of the optional
// expiresAt parameter and start+72h. An expiry at or before the start, or beyond the
// maximum, is refused. The window never depends on when the check runs.
func interactionWindow(start time.Time, params map[string]any) (emailgwefficacy.TimeWindow, error) {
	end := start.Add(interactionWindowMax)
	raw, _ := params["expiresAt"].(string)
	if raw == "" {
		return emailgwefficacy.TimeWindow{Start: start, End: end}, nil
	}
	exp, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return emailgwefficacy.TimeWindow{}, fmt.Errorf("phishingrun: PH-ID-001 expiresAt must be RFC 3339: %w", err)
	}
	if !exp.After(start) {
		return emailgwefficacy.TimeWindow{}, fmt.Errorf("phishingrun: PH-ID-001 expiresAt %s is not after the execution start %s", exp.Format(time.RFC3339), start.Format(time.RFC3339))
	}
	if exp.After(end) {
		return emailgwefficacy.TimeWindow{}, fmt.Errorf("phishingrun: PH-ID-001 expiresAt %s is beyond the %s maximum observation window", exp.Format(time.RFC3339), interactionWindowMax)
	}
	return emailgwefficacy.TimeWindow{Start: start, End: exp}, nil
}

// executePHID001 reports the observed user behavior for the execution named by
// params["executionId"]. It is behavioral evidence, not a control-efficacy verdict.
//
// PH-ID-001 measures what the targeted user did: opened, clicked, submitted, or
// reported. A user who did not click is not a failed identity control. Whether a
// control should have stopped the action, and whether it did, needs separate
// evidence. So the user-interaction dimension never gets a pass or fail.
//
// The window is fixed when the execution starts. While it is open, a result is
// provisional. "No interaction" is not final until the window closes. Once it has
// closed, "no interaction" is a final observation. Missing telemetry is Inconclusive
// at any time. Regrading uses the same window, so a regrade cannot extend it.
//
// An unknown execution, or an invalid window, is a refused request and returns an
// error.
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
	window, err := interactionWindow(ex.CreatedAt, params)
	if err != nil {
		return phishval.Outcome{}, err
	}
	now := time.Now().UTC()
	closed := !now.Before(window.End)

	var u *phishval.UserInteractionObservation
	collection := &phishval.CollectionRecord{
		Source: "exercise-tracker", WindowStart: window.Start, WindowEnd: window.End, CollectedAt: now,
	}
	events, err := store.ListEvidence(ctx, executionID)
	if err != nil {
		collection.Completeness = phishval.CollectionFailed
		collection.Reason = fmt.Sprintf("tracked interaction telemetry could not be read: %v", err)
		u = &phishval.UserInteractionObservation{
			Outcome: phishval.InteractionUnknown, Timestamp: window.Start, Source: "exercise-tracker",
			Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient, Detail: collection.Reason,
		}
	} else {
		collection.Completeness = phishval.CollectionComplete
		obs := phishbridge.FromExerciseInteractionEvidence(eventsInWindow(events, window))
		u = obs.UserInteraction
		// "No interaction" has no event time of its own. Stamp it with the window start, so
		// a regrade reports the same observation.
		if u != nil && u.Outcome == phishval.InteractionNone {
			u.Timestamp = window.Start
		}
	}

	catalogExp, err := lookupPhishingCatalogExpectation("PH-ID-001")
	if err != nil {
		return phishval.Outcome{}, err
	}
	outcome := phishval.Evaluate(runID, "", catalogExp, phishval.Observation{UserInteraction: u})
	outcome.UserInteraction = behaviorDimension(u, window, closed)
	outcome.Collection = collection
	return outcome, nil
}

// eventsInWindow keeps only evidence recorded within the window. The end is inclusive.
// Evidence from before the start, or after the end, belongs to another period.
func eventsInWindow(events []exercise.Evidence, w emailgwefficacy.TimeWindow) []exercise.Evidence {
	out := events[:0:0]
	for _, e := range events {
		if !e.CreatedAt.Before(w.Start) && !e.CreatedAt.After(w.End) {
			out = append(out, e)
		}
	}
	return out
}

// behaviorDimension states what the user did, and never claims a control result.
//   - Missing telemetry is Inconclusive, at any time.
//   - Behavior that was observed is NotApplicable. While the window is open it is marked
//     provisional.
//   - No interaction while the window is open is Inconclusive, because it is not final yet.
//   - No interaction after the window closed is NotApplicable: a final observation.
func behaviorDimension(u *phishval.UserInteractionObservation, w emailgwefficacy.TimeWindow, closed bool) phishval.DimensionResult {
	const note = " This is behavioral evidence, not a control-efficacy verdict."
	span := fmt.Sprintf("window %s to %s", w.Start.UTC().Format(time.RFC3339), w.End.UTC().Format(time.RFC3339))
	if u == nil || u.Outcome == phishval.InteractionUnknown {
		detail := "no behavioral telemetry was collected"
		if u != nil && u.Detail != "" {
			detail = u.Detail
		}
		return phishval.DimensionResult{Verdict: phishval.VerdictInconclusive,
			Reason: detail + "." + note, Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient}
	}
	if u.Outcome == phishval.InteractionNone && !closed {
		return phishval.DimensionResult{Verdict: phishval.VerdictInconclusive,
			Reason:   "no interaction observed so far, but the " + span + " is still open. Not a final result." + note,
			Evidence: phishval.EvidenceMissing, Confidence: phishval.ConfidenceInsufficient}
	}
	state := "final: " + span + " has closed"
	if !closed {
		state = "provisional: " + span + " is still open"
	}
	return phishval.DimensionResult{
		Verdict:    phishval.VerdictNotApplicable,
		Reason:     fmt.Sprintf("observed user behavior: %s (%s). %s%s", u.Outcome, state, u.Detail, note),
		Evidence:   u.Evidence,
		Confidence: u.Confidence,
	}
}
