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

// Every scenario with a verified PH→EG mapping is registered as executable.
func TestLookupPhishingRunExecutor_EmailGWReadbackRegistered(t *testing.T) {
	for phID := range phishEmailGWExpectation {
		if _, ok := LookupPhishingRunExecutor(phID); !ok {
			t.Errorf("%s has an EmailGW mapping and must be registered as executable", phID)
		}
	}
	if _, ok := LookupPhishingRunExecutor("PH-URL-005"); ok {
		t.Error("PH-URL-005 is excluded by decision and must not be registered")
	}
}

func readbackScenarioWindow() emailgwefficacy.TimeWindow {
	now := time.Now()
	return emailgwefficacy.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(time.Minute)}
}

func seedEmailGWRun(t *testing.T, pool *pgxpool.Pool, id, scenarioID string, result []byte) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO email_gw_runs (id, scenario_id, status, result) VALUES ($1, $2, 'completed', $3)`,
		id, scenarioID, result); err != nil {
		t.Fatalf("seed email_gw_run %s: %v", id, err)
	}
}

func TestExecutePHEmailGWReadback_MissingRunID_Error(t *testing.T) {
	exec, ok := LookupPhishingRunExecutor("PH-BEC-001")
	if !ok {
		t.Fatal("PH-BEC-001 not registered")
	}
	if _, err := exec(context.Background(), PhishingRunExecutorEnv{}, "run-1", map[string]any{}); err == nil {
		t.Fatal("missing emailGwRunId must be an error, not a verdict")
	}
}

func TestExecutePHEmailGWReadback_WrongExpectation_Refused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedEmailGWRun(t, pool, "eg-wrong-exp", "EG-001.spf.known-bad", nil)
		exec, _ := LookupPhishingRunExecutor("PH-BEC-001")
		_, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-wrong-exp"})
		if err == nil || !strings.Contains(err.Error(), "EG-002.known-good") {
			t.Fatalf("a run for another expectation must be refused, got err=%v", err)
		}
	})
}

func TestExecutePHEmailGWReadback_UnknownRun_Error(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exec, _ := LookupPhishingRunExecutor("PH-BEC-001")
		if _, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "does-not-exist"}); err == nil {
			t.Fatal("an unknown email gateway run must be an error")
		}
	})
}

func TestExecutePHEmailGWReadback_IncompleteRun_NotTested(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedEmailGWRun(t, pool, "eg-incomplete", "EG-002.known-good", nil)
		exec, _ := LookupPhishingRunExecutor("PH-BEC-001")
		outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-incomplete"})
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictNotTested {
			t.Errorf("Enforcement.Verdict = %q, want %q (no efficacy result is no evidence)", outcome.Enforcement.Verdict, phishval.VerdictNotTested)
		}
	})
}

func TestExecutePHEmailGWReadback_CompletedKnownGoodRun_Pass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, ok := emailgwefficacy.ExpectationByID("EG-002.known-good")
		if !ok {
			t.Fatal("EG-002.known-good expectation missing")
		}
		now := time.Now()
		ev := func(kind emailgwefficacy.ProvenanceKind) emailgwefficacy.Provenance {
			return emailgwefficacy.Provenance{Kind: kind, Confidence: emailgwefficacy.ConfidenceHigh}
		}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
				Timestamp: now, Source: emailgwefficacy.SourceFixture, Provenance: ev(emailgwefficacy.ProvenanceObserved),
			}},
			[]emailgwefficacy.DetectionEvidence{{
				Message: exp.Ref(), AlertGenerated: true, Product: "m365-defender-o365",
				Timestamp: now, Source: emailgwefficacy.SourceFixture, Provenance: ev(emailgwefficacy.ProvenanceObserved),
			}},
		).WithResponse([]emailgwefficacy.ResponseEvidence{{
			Message: exp.Ref(), ActionRequired: "quarantine", Completed: true,
			Timestamp: now, Source: emailgwefficacy.SourceFixture, Provenance: ev(emailgwefficacy.ProvenanceObserved),
		}})
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal efficacy result: %v", err)
		}
		seedEmailGWRun(t, pool, "eg-known-good", "EG-002.known-good", raw)

		exec, _ := LookupPhishingRunExecutor("PH-BEC-001")
		outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-known-good"})
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q for a control that quarantined a known-good run", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
	})
}

// PH-CHN-005 maps to the QR-lure expectation EG-011, which the EmailGW
// dispatch table now carries. Its read-back is graded on a completed run.
func TestExecutePHEmailGWReadback_CHN005_CompletedQRRun_Pass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, ok := emailgwefficacy.ExpectationByID("EG-011.qr-code-lure.known-good")
		if !ok {
			t.Fatal("EG-011.qr-code-lure.known-good missing from the dispatch table")
		}
		now := time.Now()
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
				Timestamp: now, Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
			}},
			nil,
		)
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal efficacy result: %v", err)
		}
		seedEmailGWRun(t, pool, "eg-qr-known-good", "EG-011.qr-code-lure.known-good", raw)

		exec, ok := LookupPhishingRunExecutor("PH-CHN-005")
		if !ok {
			t.Fatal("PH-CHN-005 must be registered as executable")
		}
		outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-qr-known-good"})
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q for a QR lure the gateway quarantined", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
	})
}

// PH-ATT-002 maps to the PDF-embedded-link expectation EG-012, which the
// EmailGW dispatch table carries. Its read-back is graded on a completed run.
func TestExecutePHEmailGWReadback_ATT002_CompletedPDFRun_Pass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, ok := emailgwefficacy.ExpectationByID("EG-012.pdf-embedded-link.known-good")
		if !ok {
			t.Fatal("EG-012.pdf-embedded-link.known-good missing from the dispatch table")
		}
		now := time.Now()
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
				Timestamp: now, Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
			}},
			nil,
		)
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal efficacy result: %v", err)
		}
		seedEmailGWRun(t, pool, "eg-pdf-known-good", "EG-012.pdf-embedded-link.known-good", raw)

		exec, ok := LookupPhishingRunExecutor("PH-ATT-002")
		if !ok {
			t.Fatal("PH-ATT-002 must be registered as executable")
		}
		outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-pdf-known-good"})
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q for a PDF the gateway quarantined", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
	})
}

// PH-ATT-003 maps to the Office-external-link expectation EG-013, which the
// EmailGW dispatch table carries. Its read-back is graded on a completed run.
func TestExecutePHEmailGWReadback_ATT003_CompletedDOCXRun_Pass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, ok := emailgwefficacy.ExpectationByID("EG-013.office-external-link.known-good")
		if !ok {
			t.Fatal("EG-013.office-external-link.known-good missing from the dispatch table")
		}
		now := time.Now()
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
				Timestamp: now, Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
			}},
			nil,
		)
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal efficacy result: %v", err)
		}
		seedEmailGWRun(t, pool, "eg-docx-known-good", "EG-013.office-external-link.known-good", raw)

		exec, ok := LookupPhishingRunExecutor("PH-ATT-003")
		if !ok {
			t.Fatal("PH-ATT-003 must be registered as executable")
		}
		outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-docx-known-good"})
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q for a DOCX the gateway quarantined", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
	})
}

// PH-AUTH-007 maps to the internal-sender-spoof expectation EG-014, which the
// EmailGW dispatch table carries. Its read-back is graded on a completed run.
func TestExecutePHEmailGWReadback_AUTH007_CompletedSpoofRun_Pass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, ok := emailgwefficacy.ExpectationByID("EG-014.internal-sender-spoof.known-good")
		if !ok {
			t.Fatal("EG-014.internal-sender-spoof.known-good missing from the dispatch table")
		}
		now := time.Now()
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
				Timestamp: now, Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
			}},
			nil,
		)
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal efficacy result: %v", err)
		}
		seedEmailGWRun(t, pool, "eg-spoof-known-good", "EG-014.internal-sender-spoof.known-good", raw)

		exec, ok := LookupPhishingRunExecutor("PH-AUTH-007")
		if !ok {
			t.Fatal("PH-AUTH-007 must be registered as executable")
		}
		outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-spoof-known-good"})
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q for a spoof the gateway quarantined", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
	})
}

// PH-BEC-006 maps to the reply-chain-hijack expectation EG-015, which the
// EmailGW dispatch table carries. Its read-back is graded on a completed run.
func TestExecutePHEmailGWReadback_BEC006_CompletedReplyChainRun_Pass(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		exp, ok := emailgwefficacy.ExpectationByID("EG-015.reply-chain-hijack.known-good")
		if !ok {
			t.Fatal("EG-015.reply-chain-hijack.known-good missing from the dispatch table")
		}
		now := time.Now()
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: exp.Ref(), Action: "quarantine", ControlProduct: exp.ControlProduct,
				Timestamp: now, Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved, Confidence: emailgwefficacy.ConfidenceHigh},
			}},
			nil,
		)
		result := emailgwefficacy.VerifyMailExpectation(exp, emailgwefficacy.OriginDeliveryObservation{}, provider, readbackScenarioWindow())
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatalf("marshal efficacy result: %v", err)
		}
		seedEmailGWRun(t, pool, "eg-replychain-known-good", "EG-015.reply-chain-hijack.known-good", raw)

		exec, ok := LookupPhishingRunExecutor("PH-BEC-006")
		if !ok {
			t.Fatal("PH-BEC-006 must be registered as executable")
		}
		outcome, err := exec(context.Background(), PhishingRunExecutorEnv{Pool: pool}, "run-1",
			map[string]any{"emailGwRunId": "eg-replychain-known-good"})
		if err != nil {
			t.Fatalf("executor: %v", err)
		}
		if outcome.Enforcement.Verdict != phishval.VerdictPass {
			t.Errorf("Enforcement.Verdict = %q, want %q for a reply-chain message the gateway quarantined", outcome.Enforcement.Verdict, phishval.VerdictPass)
		}
	})
}

