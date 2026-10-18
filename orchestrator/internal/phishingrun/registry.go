package phishingrun

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishval"
)

// ExecutorEnv carries the external dependencies a scenario's own
// Executor needs, injected rather than hardcoded so a future real
// adapter (e.g. an ITSM connector for ReportTicketProvider) can be
// swapped in without touching the registry itself.
type ExecutorEnv struct {
	ReportTicketProvider phishbridge.ReportTicketEvidenceProvider
}

// Executor runs one registered scenario for real and returns its
// phishval.Outcome. params carries whatever scenario-specific
// arguments that scenario's own Executor needs (e.g. PH-DET-002's
// executionId/targetId) -- validated by the Executor itself, not by
// the registry.
type Executor func(ctx context.Context, env ExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error)

// scenarioExecutors is the one place that makes a catalog scenario
// executable. phishcatalog.Scenario.MappedImplementation is plain
// documentation text, not a callable reference -- a scenario absent
// from this map is not executable, regardless of what Coverage tier
// its catalog entry carries. Only PH-DET-002 is registered in this
// slice; expanding to the other adapter-tested scenarios is deliberate
// future work (see this plan's own "What this plan deliberately does
// NOT do" section), not something to add speculatively here.
var scenarioExecutors = map[string]Executor{
	"PH-DET-002": executePHDET002,
}

// LookupExecutor returns scenarioID's registered Executor, or
// ok == false if it is not (yet) executable.
func LookupExecutor(scenarioID string) (Executor, bool) {
	e, ok := scenarioExecutors[scenarioID]
	return e, ok
}

// executePHDET002 runs PH-DET-002 (user-reported phishing / SOC
// triage) for real: checks whether a ticket was created for the
// report event named by params["executionId"]/params["targetId"].
// ExpectedTicketCreated is always true -- this is the catalog's own
// fixed Expectation (a ticket SHOULD be created), never a caller-
// selectable "known-good/known-bad" choice; that distinction only
// ever existed in this initiative's own tests.
func executePHDET002(ctx context.Context, env ExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	executionID, _ := params["executionId"].(string)
	targetID, _ := params["targetId"].(string)
	if executionID == "" || targetID == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-DET-002 requires non-empty executionId and targetId parameters")
	}

	exp := phishbridge.ReportTicketExpectation{
		ExecutionID: executionID, TargetID: targetID, ExpectedTicketCreated: true,
	}
	// PH-DET-002 has no real dwell window to wait out (unlike an
	// SMTP-dispatch scenario) -- it looks back over the last 24 hours
	// for whatever ticketing evidence already exists rather than
	// waiting for new evidence to arrive.
	now := time.Now()
	window := emailgwefficacy.TimeWindow{Start: now.Add(-24 * time.Hour), End: now}
	verdict := phishbridge.VerifyReportTicketExpectation(exp, env.ReportTicketProvider, window)
	obs := phishbridge.FromSingleDimensionResponseVerdict(verdict, "phishingrun-PH-DET-002")

	catalogExp, err := lookupCatalogExpectation("PH-DET-002")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// lookupCatalogExpectation returns scenarioID's own phishval.Expectation
// from the real, current catalog -- never hand-duplicated here, so a
// future catalog edit (e.g. a changed Response outcome) can't silently
// drift out of sync with what this package evaluates against.
func lookupCatalogExpectation(scenarioID string) (phishval.Expectation, error) {
	catalog, err := phishcatalog.AudspectPhishingCatalog()
	if err != nil {
		return phishval.Expectation{}, fmt.Errorf("phishingrun: loading scenario catalog: %w", err)
	}
	for _, s := range catalog {
		if s.ID == scenarioID {
			return s.Expectation, nil
		}
	}
	return phishval.Expectation{}, fmt.Errorf("phishingrun: scenario %q not found in catalog", scenarioID)
}
