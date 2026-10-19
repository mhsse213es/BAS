package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/phishval"
)

// relayLegRun seeds one EmailGW run for one leg of PH-EVA-002 under its
// expectation ID, graded from a fixture enforcement action.
func relayLegRun(t *testing.T, pool *pgxpool.Pool, id, expID string, exp emailgwefficacy.MailExpectation, action string) {
	t.Helper()
	provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
		[]emailgwefficacy.EnforcementEvidence{{
			Message: exp.Ref(), Action: action, ControlProduct: exp.ControlProduct,
			Timestamp: time.Now(), Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
		}},
		nil,
	)
	result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal efficacy result: %v", err)
	}
	seedEmailGWRun(t, pool, id, expID, raw)
}

func runRelayPath(t *testing.T, pool *pgxpool.Pool, direct, relay string) (phishval.Outcome, error) {
	t.Helper()
	exec, ok := LookupPhishingRunExecutor("PH-EVA-002")
	if !ok {
		t.Fatal("PH-EVA-002 must be registered as executable")
	}
	return exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
		map[string]any{"emailGwRunId": direct, "relayEmailGwRunId": relay})
}

func TestExecutePHEVA002_DirectBlockedRelayBlocked_NoBypass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relayLegRun(t, pool, "eva-direct-caught", "EG-016.relay-path.direct.known-good", emailgwefficacy.RelayPathBypassDirectExpectation(true), "quarantine")
		relayLegRun(t, pool, "eva-relay-caught", "EG-016.relay-path.relay.known-good", emailgwefficacy.RelayPathBypassRelayExpectation(true), "quarantine")

		outcome, err := runRelayPath(t, pool, "eva-direct-caught", "eva-relay-caught")
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q: the direct path blocked the spoof", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
		if !strings.Contains(outcome.Enforcement.Reason, "no bypass observed") {
			t.Errorf("Reason = %q, want it to say no bypass was observed", outcome.Enforcement.Reason)
		}
	})
}

func TestExecutePHEVA002_DirectBlockedRelayDelivered_BypassReported(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relayLegRun(t, pool, "eva-direct-caught-2", "EG-016.relay-path.direct.known-good", emailgwefficacy.RelayPathBypassDirectExpectation(true), "quarantine")
		relayLegRun(t, pool, "eva-relay-delivered", "EG-016.relay-path.relay.known-bad", emailgwefficacy.RelayPathBypassRelayExpectation(false), "deliver")

		outcome, err := runRelayPath(t, pool, "eva-direct-caught-2", "eva-relay-delivered")
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		// The verdict stays on the direct path. The relay bypass is a labeled
		// finding, never a PASS or FAIL of its own.
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q: verdict is graded on the direct path only", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
		if !strings.Contains(outcome.Enforcement.Reason, "BYPASS observed") {
			t.Errorf("Reason = %q, want it to report the relay bypass", outcome.Enforcement.Reason)
		}
	})
}

func TestExecutePHEVA002_DirectDelivered_Fail(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relayLegRun(t, pool, "eva-direct-delivered", "EG-016.relay-path.direct.known-bad", emailgwefficacy.RelayPathBypassDirectExpectation(false), "deliver")
		relayLegRun(t, pool, "eva-relay-delivered-2", "EG-016.relay-path.relay.known-bad", emailgwefficacy.RelayPathBypassRelayExpectation(false), "deliver")

		outcome, err := runRelayPath(t, pool, "eva-direct-delivered", "eva-relay-delivered-2")
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictFail {
			t.Errorf("Enforcement.Verdict = %q, want %q: the direct path delivered the spoof", outcome.Enforcement.Verdict, phishval.VerdictFail)
		}
	})
}

func TestExecutePHEVA002_SwappedLegs_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relayLegRun(t, pool, "eva-swap-relay", "EG-016.relay-path.relay.known-good", emailgwefficacy.RelayPathBypassRelayExpectation(true), "quarantine")
		relayLegRun(t, pool, "eva-swap-direct", "EG-016.relay-path.direct.known-good", emailgwefficacy.RelayPathBypassDirectExpectation(true), "quarantine")

		// The relay run supplied as the direct leg must be refused, not graded.
		if _, err := runRelayPath(t, pool, "eva-swap-relay", "eva-swap-direct"); err == nil {
			t.Fatal("swapped legs must be rejected, never graded")
		}
	})
}

func TestExecutePHEVA002_MissingRelayRun_Error(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exec, _ := LookupPhishingRunExecutor("PH-EVA-002")
		_, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eva-direct-caught"})
		if err == nil {
			t.Fatal("PH-EVA-002 requires relayEmailGwRunId; a missing value must be an error")
		}
	})
}

// An incomplete direct leg refuses the whole grade. Nothing is graded from it.
func TestExecutePHEVA002_IncompleteDirectLeg_Refused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		if _, err := pool.Exec(context.Background(),
			`INSERT INTO email_gw_runs (id, scenario_id, status) VALUES ('eva-direct-running', 'EG-016.relay-path.direct.known-good', 'running')`); err != nil {
			t.Fatalf("seed running direct leg: %v", err)
		}
		relayLegRun(t, pool, "eva-relay-ok", "EG-016.relay-path.relay.known-good", emailgwefficacy.RelayPathBypassRelayExpectation(true), "quarantine")

		_, err := runRelayPath(t, pool, "eva-direct-running", "eva-relay-ok")
		if err == nil || !strings.Contains(err.Error(), "only a completed run") {
			t.Fatalf("an incomplete direct leg must refuse the grade, got err=%v", err)
		}
	})
}

// A completed relay leg with no efficacy result refuses the grade. It is not
// graded as NotTested, and the direct leg is not graded alone.
func TestExecutePHEVA002_CompletedRelayWithoutResult_Refused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relayLegRun(t, pool, "eva-direct-ok", "EG-016.relay-path.direct.known-good", emailgwefficacy.RelayPathBypassDirectExpectation(true), "quarantine")
		seedEmailGWRun(t, pool, "eva-relay-no-result", "EG-016.relay-path.relay.known-good", nil)

		_, err := runRelayPath(t, pool, "eva-direct-ok", "eva-relay-no-result")
		if err == nil || !strings.Contains(err.Error(), "no efficacy result") {
			t.Fatalf("a completed relay leg without a result must refuse the grade, got err=%v", err)
		}
	})
}

// A graded pair names both runs it was read from.
func TestExecutePHEVA002_RecordsProvenanceForBothLegs(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		relayLegRun(t, pool, "eva-prov-direct", "EG-016.relay-path.direct.known-good", emailgwefficacy.RelayPathBypassDirectExpectation(true), "quarantine")
		relayLegRun(t, pool, "eva-prov-relay", "EG-016.relay-path.relay.known-good", emailgwefficacy.RelayPathBypassRelayExpectation(true), "quarantine")

		outcome, err := runRelayPath(t, pool, "eva-prov-direct", "eva-prov-relay")
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Provenance == nil || outcome.Provenance.EmailGWRunID != "eva-prov-direct" {
			t.Errorf("Provenance = %+v, want the direct run eva-prov-direct", outcome.Provenance)
		}
		if outcome.RelayProvenance == nil || outcome.RelayProvenance.EmailGWRunID != "eva-prov-relay" {
			t.Errorf("RelayProvenance = %+v, want the relay run eva-prov-relay", outcome.RelayProvenance)
		}
	})
}
