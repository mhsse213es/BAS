package api

// Phishing scenario executor registry -- deliberately in package api,
// not internal/phishingrun, for the exact same reason
// ExecuteEmailGWRun lives in internal/api rather than internal/db (see
// emailgwrun_executor.go's own package comment): this file imports
// internal/phishbridge, which imports internal/emailgwefficacy, which
// imports internal/exercise -- and internal/exercise's own tests
// import internal/testutil, which imports internal/db. internal/db
// importing internal/phishingrun for its pure lifecycle types (Task 2)
// is fine; internal/db importing anything that pulls in phishbridge
// transitively is not -- it cycles. internal/phishingrun itself (see
// its own types.go) stays pure types only, importable from internal/db
// safely, exactly like internal/emailgwrun.

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishbridge"
	"github.com/audspect/bas/internal/phishcatalog"
	"github.com/audspect/bas/internal/phishval"
)

// PhishingRunExecutorEnv carries the external dependencies a
// scenario's own PhishingRunExecutor needs, injected rather than
// hardcoded so a future real adapter (e.g. an ITSM connector for
// ReportTicketProvider) can be swapped in without touching the
// registry itself.
type PhishingRunExecutorEnv struct {
	ReportTicketProvider phishbridge.ReportTicketEvidenceProvider
}

// PhishingRunExecutor runs one registered scenario for real and
// returns its phishval.Outcome. params carries whatever scenario-
// specific arguments that scenario's own executor needs (e.g.
// PH-DET-002's executionId/targetId) -- validated by the executor
// itself, not by the registry.
type PhishingRunExecutor func(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error)

// phishingRunExecutors is the one place that makes a catalog scenario
// executable. phishcatalog.Scenario.MappedImplementation is plain
// documentation text, not a callable reference -- a scenario absent
// from this map is not executable, regardless of what Coverage tier
// its catalog entry carries. Only PH-DET-002 is registered in this
// slice; expanding to the other adapter-tested scenarios is deliberate
// future work, not something to add speculatively here.
var phishingRunExecutors = map[string]PhishingRunExecutor{
	"PH-DET-002": executePHDET002,
}

// LookupPhishingRunExecutor returns scenarioID's registered executor,
// or ok == false if it is not (yet) executable.
func LookupPhishingRunExecutor(scenarioID string) (PhishingRunExecutor, bool) {
	e, ok := phishingRunExecutors[scenarioID]
	return e, ok
}

// executePHDET002 runs PH-DET-002 (user-reported phishing / SOC
// triage) for real: checks whether a ticket was created for the
// report event named by params["executionId"]/params["targetId"].
// ExpectedTicketCreated is always true -- this is the catalog's own
// fixed Expectation (a ticket SHOULD be created), never a caller-
// selectable "known-good/known-bad" choice; that distinction only
// ever existed in this initiative's own tests.
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
	if env.ReportTicketProvider == nil {
		// No real ITSM connector is wired on this deployment
		// (Handler.WithPhishingRun was never called) -- this is not
		// "ran and found no evidence," it's "not configured yet," but
		// both degrade identically to NotTested per this initiative's
		// own rule: never fabricate a verdict from absent evidence, and
		// never panic on a nil-interface method call either.
		verdict = emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive, Reason: "phishingrun: no ReportTicketEvidenceProvider configured on this deployment"}
	} else {
		// PH-DET-002 has no real dwell window to wait out (unlike an
		// SMTP-dispatch scenario) -- it looks back over the last 24
		// hours for whatever ticketing evidence already exists rather
		// than waiting for new evidence to arrive.
		now := time.Now()
		window := emailgwefficacy.TimeWindow{Start: now.Add(-24 * time.Hour), End: now}
		verdict = phishbridge.VerifyReportTicketExpectation(exp, env.ReportTicketProvider, window)
	}
	obs := phishbridge.FromSingleDimensionResponseVerdict(verdict, "phishingrun-PH-DET-002")

	catalogExp, err := lookupPhishingCatalogExpectation("PH-DET-002")
	if err != nil {
		return phishval.Outcome{}, err
	}
	return phishval.Evaluate(runID, "", catalogExp, obs), nil
}

// lookupPhishingCatalogExpectation returns scenarioID's own
// phishval.Expectation from the real, current catalog -- never hand-
// duplicated here, so a future catalog edit (e.g. a changed Response
// outcome) can't silently drift out of sync with what this package
// evaluates against.
func lookupPhishingCatalogExpectation(scenarioID string) (phishval.Expectation, error) {
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
