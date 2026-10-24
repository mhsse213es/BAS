package dbrun

import (
	"context"
	"encoding/json"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbbuild"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/scenario"
)

// Shared by the fake pipeline tests (untagged) and the E2E harness (tag
// dbsim_e2e): the expectations per shipped scenario step now come from
// production (dbsim.ExpectationFor / dbbuild.MetaFor), so the live-verified
// E2E and the unit grading run through the same code. Only a scenario/probe
// pair that is not shipped (a test-only scenario id) falls back to the lab
// default: allow + detection.

type labExpectation struct {
	prevention string // "allow" | "deny"
	detection  bool
	requireObs bool
}

func labExpectationFor(scenarioID, probeID string) labExpectation {
	e, ok := dbsim.ExpectationFor(scenarioID, probeID)
	if !ok {
		return labExpectation{prevention: "allow", detection: true}
	}
	return labExpectation{prevention: e.ExpectedPrevention, detection: e.ExpectDetection, requireObs: e.RequireObservation}
}

func labMeta(scenarioID string, spec dbsim.DBProbeSpec) dbsim.ScenarioMeta {
	m, err := dbbuild.MetaFor(&scenario.Scenario{ID: scenarioID, ProductLine: scenario.ProductLineDBSim}, spec)
	if err != nil {
		// Not a shipped scenario/probe pair: the lab default.
		m = dbsim.ScenarioMeta{
			ID: scenarioID, Version: "1", ControlObjective: "lab check of " + spec.ProbeID,
			Preconditions: "dbsim lab stack up", SyntheticDataManifest: "synthetic lab data only",
			ActionAttempted: "named probe " + spec.ProbeID, ExpectedPrevention: "allow",
			ExpectDetection: true, ExpectResponse: true,
			Engine: spec.Engine, TargetID: spec.TargetID, Mode: spec.Mode,
		}
	}
	return m
}

// fakeConn is a detectverify.Connector answering from a function. Its Verdict
// is Detected whenever it returns alerts: Evaluate must never read it.
type fakeConn struct {
	calls int
	reply func(detectverify.VerifyRequest) (detectverify.VerifyResult, error)
}

func (f *fakeConn) Verify(ctx context.Context, r detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	f.calls++
	if err := ctx.Err(); err != nil {
		return detectverify.VerifyResult{}, err
	}
	return f.reply(r)
}
func (f *fakeConn) TestConnection(context.Context) error { return nil }

func alertsReply(as ...detectverify.MatchedAlert) func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	return func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
		v := detectverify.VerdictNotDetected
		if len(as) > 0 {
			v = detectverify.VerdictDetected
		}
		return detectverify.VerifyResult{Verdict: v, MatchedAlerts: as}, nil
	}
}

// elasticLikeAlert builds a MatchedAlert shaped like the Elastic connector's
// RawJSON (A1): summary keys plus the whitelisted alert source under "source".
func elasticLikeAlert(id string, at time.Time, statement string) detectverify.MatchedAlert {
	raw, _ := json.Marshal(map[string]any{
		"alertId": id, "ruleName": "BAS dbsim marker in database audit event", "timestamp": at,
		"source": map[string]any{"message": statement, "event.original": statement, "host.name": "dbsim-pg", "user.name": "dbsim_lab"},
	})
	return detectverify.MatchedAlert{AlertID: id, RuleName: "BAS dbsim marker in database audit event", Timestamp: at, RawJSON: raw}
}
