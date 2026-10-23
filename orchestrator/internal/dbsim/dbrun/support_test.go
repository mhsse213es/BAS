package dbrun

import (
	"context"
	"encoding/json"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/detectverify"
)

// Shared by the fake pipeline tests (untagged) and the E2E harness (tag
// dbsim_e2e): the lab-calibrated expectations per shipped scenario step.
//
// These are NOT product policy. The lab detection rule fires on every statement
// that begins with the marker comment, except the agent's own audit-lookup and
// meta statements (read_audit_config mentions audit-source words, so it never
// alerts). The product run API (Task 16) owns the real per-scenario
// expectations.

type labExpectation struct {
	prevention string // "allow" | "deny"
	detection  bool
	audit      bool
	auditCfg   bool
	requireObs bool
}

func labExpectationFor(scenarioID, probeID string) labExpectation {
	e := labExpectation{prevention: "allow", detection: true}
	switch probeID {
	case "read_audit_config":
		e.detection, e.auditCfg = false, true
	case "read_restricted_table":
		e.prevention = "deny"
	case "read_grants":
		e.requireObs = true
	}
	if scenarioID == "dbsim-db04-audit-coverage" && probeID == "read_roles" {
		e.audit = true
	}
	return e
}

func labMeta(scenarioID string, spec dbsim.DBProbeSpec) dbsim.ScenarioMeta {
	e := labExpectationFor(scenarioID, spec.ProbeID)
	return dbsim.ScenarioMeta{
		ID: scenarioID, Version: "1", ControlObjective: "lab check of " + spec.ProbeID,
		Preconditions: "dbsim lab stack up", SyntheticDataManifest: "synthetic lab data only",
		ActionAttempted: "named probe " + spec.ProbeID, ExpectedPrevention: e.prevention,
		ExpectDetection: e.detection, ExpectResponse: e.detection,
		ExpectAudit: e.audit, ExpectAuditConfig: e.auditCfg, RequireObservation: e.requireObs,
		Engine: spec.Engine, TargetID: spec.TargetID, Mode: spec.Mode,
	}
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
