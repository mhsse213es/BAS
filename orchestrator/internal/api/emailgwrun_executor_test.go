package api

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	gosmtp "github.com/emersion/go-smtp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/emailgwefficacy"
	"github.com/audspect/bas/internal/emailgwrun"
)

// Local SMTP test server, independently built in this package (the
// originals in internal/exercise and internal/emailgwefficacy are both
// unexported) -- proves ExecuteEmailGWRun's injection half actually
// puts a real message on the wire, never a production delivery path.

type emailgwrunTestBackend struct {
	mu       sync.Mutex
	received int
}

func (b *emailgwrunTestBackend) NewSession(c *gosmtp.Conn) (gosmtp.Session, error) {
	return &emailgwrunTestSession{backend: b}, nil
}

type emailgwrunTestSession struct{ backend *emailgwrunTestBackend }

func (s *emailgwrunTestSession) Mail(from string, opts *gosmtp.MailOptions) error { return nil }
func (s *emailgwrunTestSession) Rcpt(to string, opts *gosmtp.RcptOptions) error    { return nil }
func (s *emailgwrunTestSession) Data(r io.Reader) error {
	if _, err := io.ReadAll(r); err != nil {
		return err
	}
	s.backend.mu.Lock()
	s.backend.received++
	s.backend.mu.Unlock()
	return nil
}
func (s *emailgwrunTestSession) Reset()        {}
func (s *emailgwrunTestSession) Logout() error { return nil }

func startEmailGWRunTestServer(t *testing.T) (*emailgwrunTestBackend, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backend := &emailgwrunTestBackend{}
	srv := gosmtp.NewServer(backend)
	srv.Domain = "emailgwrun-test.local"
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 10 * time.Second
	srv.MaxRecipients = 1
	srv.AllowInsecureAuth = true
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)
	return backend, ln.Addr().String()
}

func TestExecuteEmailGWRun_UnknownScenarioID_ReturnsErrorNoRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := ExecuteEmailGWRun(context.Background(), pool, emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil),
			emailgwefficacy.InjectionTarget{}, EmailGWRunRequest{ScenarioID: "EG-999.no-such-scenario"})
		if err == nil {
			t.Fatal("expected an error for an unknown scenario id")
		}
	})
}

func TestExecuteEmailGWRun_NotWiredScenario_ReturnsErrorNoRow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		// EG-001.spf.known-good is deliberately not wired for real injection
		// (needs a lab domain with a real SPF record) -- see scenarios.go.
		_, err := ExecuteEmailGWRun(context.Background(), pool, emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil),
			emailgwefficacy.InjectionTarget{}, EmailGWRunRequest{ScenarioID: "EG-001.spf.known-good"})
		if err == nil {
			t.Fatal("expected an error for a scenario with no EnvelopeFrom")
		}
	})
}

func TestExecuteEmailGWRun_WiredScenario_InjectsRealMessageAndReturnsRunning(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		backend, addr := startEmailGWRunTestServer(t)
		run, err := ExecuteEmailGWRun(context.Background(), pool, emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil),
			emailgwefficacy.InjectionTarget{TargetMX: addr}, EmailGWRunRequest{ScenarioID: "EG-002.known-bad", InitiatedBy: "tester"})
		if err != nil {
			t.Fatalf("ExecuteEmailGWRun: %v", err)
		}
		if run.Status != emailgwrun.StatusRunning {
			t.Errorf("Status = %q, want %q", run.Status, emailgwrun.StatusRunning)
		}
		if run.SenderPayloadHash == "" {
			t.Error("SenderPayloadHash is empty, want a hash of the real sent payload")
		}
		if run.WindowEnd == nil {
			t.Fatal("WindowEnd is nil, want it set once injection succeeds")
		}
		if got := run.WindowEnd.Sub(*run.WindowStart); got != DefaultEmailGWDwellWindowPreventionDetection {
			t.Errorf("dwell window = %v, want the prevention/detection default %v", got, DefaultEmailGWDwellWindowPreventionDetection)
		}

		backend.mu.Lock()
		received := backend.received
		backend.mu.Unlock()
		if received != 1 {
			t.Errorf("test SMTP server received %d messages, want 1", received)
		}

		persisted, err := db.GetEmailGWRun(context.Background(), pool, run.ID)
		if err != nil {
			t.Fatalf("GetEmailGWRun: %v", err)
		}
		if persisted.Status != emailgwrun.StatusRunning || persisted.InitiatedBy != "tester" {
			t.Errorf("persisted = %+v, want Status=running InitiatedBy=tester", persisted)
		}
	})
}

func TestExecuteEmailGWRun_ResponseScenario_UsesLongerDwellWindow(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, addr := startEmailGWRunTestServer(t)
		run, err := ExecuteEmailGWRun(context.Background(), pool, emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil),
			emailgwefficacy.InjectionTarget{TargetMX: addr}, EmailGWRunRequest{ScenarioID: "EG-008.known-good"})
		if err != nil {
			t.Fatalf("ExecuteEmailGWRun: %v", err)
		}
		if got := run.WindowEnd.Sub(*run.WindowStart); got != DefaultEmailGWDwellWindowResponse {
			t.Errorf("dwell window = %v, want the response-scenario default %v", got, DefaultEmailGWDwellWindowResponse)
		}
	})
}

func TestFinishEmailGWRunAfterWindow_PastWindow_VerifiesImmediatelyAndWritesCompleted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		exp := emailgwefficacy.ExecutiveImpersonationExpectation(false)
		run := &emailgwrun.EmailGWRun{ID: "finish-completed-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusRunning, StartedAt: time.Now().UTC()}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		now := time.Now()
		window := emailgwefficacy.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(-time.Second)} // already closed
		observation := emailgwefficacy.OriginDeliveryObservation{SenderPayloadHash: "abc123", Timestamp: now.Add(-time.Minute)}
		msg := exp.Ref()
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: msg, Action: "quarantined-but-not-what-was-expected", Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved}, Timestamp: now.Add(-30 * time.Second),
			}},
			[]emailgwefficacy.DetectionEvidence{{
				Message: msg, AlertGenerated: true, Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved}, Timestamp: now.Add(-30 * time.Second),
			}},
		).WithResponse([]emailgwefficacy.ResponseEvidence{{
			Message: msg, Completed: true, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved}, Timestamp: now.Add(-30 * time.Second),
		}})

		finishEmailGWRunAfterWindow(pool, provider, exp, observation, window, run.ID)

		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != emailgwrun.StatusCompleted {
			t.Fatalf("Status = %q, want %q (fully definitive verdicts)", got.Status, emailgwrun.StatusCompleted)
		}
		if got.CompletedAt == nil || got.VerifiedAt == nil {
			t.Errorf("CompletedAt/VerifiedAt not both set: %+v", got)
		}
		if len(got.Result) == 0 {
			t.Error("Result is empty, want the marshaled EfficacyResult")
		}
	})
}

func TestFinishEmailGWRunAfterWindow_NoEvidence_WritesPartial(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		exp := emailgwefficacy.ExecutiveImpersonationExpectation(false)
		run := &emailgwrun.EmailGWRun{ID: "finish-partial-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusRunning, StartedAt: time.Now().UTC()}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}

		now := time.Now()
		window := emailgwefficacy.TimeWindow{Start: now.Add(-time.Minute), End: now.Add(-time.Second)}
		observation := emailgwefficacy.OriginDeliveryObservation{SenderPayloadHash: "abc123", Timestamp: now.Add(-time.Minute)}
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil) // no evidence at all -> Inconclusive dimensions

		finishEmailGWRunAfterWindow(pool, provider, exp, observation, window, run.ID)

		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != emailgwrun.StatusPartial {
			t.Fatalf("Status = %q, want %q -- absence of evidence must never read as completed success/failure", got.Status, emailgwrun.StatusPartial)
		}
	})
}

func TestRecoverEmailGWRuns_RunningRowWithPastWindow_GetsVerifiedAndTerminal(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{ID: "recover-past-1", ScenarioID: "EG-002.known-bad", Status: emailgwrun.StatusPending, StartedAt: time.Now().UTC()}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		now := time.Now().UTC()
		if err := db.UpdateEmailGWRunInjected(ctx, pool, run.ID, "deadbeef", now.Add(-time.Hour), now.Add(-time.Hour), now.Add(-time.Minute)); err != nil {
			t.Fatalf("update injected: %v", err)
		}

		msg := emailgwefficacy.ExecutiveImpersonationExpectation(false).Ref() // EG-002.known-bad's own underlying MailExpectation
		provider := emailgwefficacy.NewFixtureMailEvidenceProvider(
			[]emailgwefficacy.EnforcementEvidence{{
				Message: msg, Action: "quarantined-but-not-what-was-expected", Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved}, Timestamp: now.Add(-30 * time.Minute),
			}},
			[]emailgwefficacy.DetectionEvidence{{
				Message: msg, AlertGenerated: true, Source: emailgwefficacy.SourceFixture,
				Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved}, Timestamp: now.Add(-30 * time.Minute),
			}},
		).WithResponse([]emailgwefficacy.ResponseEvidence{{
			Message: msg, Completed: true, Source: emailgwefficacy.SourceFixture,
			Provenance: emailgwefficacy.Provenance{Kind: emailgwefficacy.ProvenanceObserved}, Timestamp: now.Add(-30 * time.Minute),
		}})

		if err := RecoverEmailGWRuns(ctx, pool, provider); err != nil {
			t.Fatalf("RecoverEmailGWRuns: %v", err)
		}

		deadline := time.Now().Add(3 * time.Second)
		for {
			got, err := db.GetEmailGWRun(ctx, pool, run.ID)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got.Status != emailgwrun.StatusRunning {
				if got.Status != emailgwrun.StatusCompleted {
					t.Fatalf("Status = %q, want %q", got.Status, emailgwrun.StatusCompleted)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for recovery goroutine to finish verifying an already-past-window run")
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

func TestRecoverEmailGWRuns_UnknownScenarioID_MarkedFailed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		run := &emailgwrun.EmailGWRun{ID: "recover-unknown-1", ScenarioID: "EG-999.vanished", Status: emailgwrun.StatusPending, StartedAt: time.Now().UTC()}
		if err := db.InsertEmailGWRun(ctx, pool, run); err != nil {
			t.Fatalf("insert: %v", err)
		}
		now := time.Now().UTC()
		if err := db.UpdateEmailGWRunInjected(ctx, pool, run.ID, "deadbeef", now, now, now.Add(time.Minute)); err != nil {
			t.Fatalf("update injected: %v", err)
		}

		if err := RecoverEmailGWRuns(ctx, pool, emailgwefficacy.NewFixtureMailEvidenceProvider(nil, nil)); err != nil {
			t.Fatalf("RecoverEmailGWRuns: %v", err)
		}

		got, err := db.GetEmailGWRun(ctx, pool, run.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != emailgwrun.StatusFailed {
			t.Errorf("Status = %q, want %q -- an unresolvable scenario id must never be left running forever", got.Status, emailgwrun.StatusFailed)
		}
	})
}

func TestDwellWindowFor(t *testing.T) {
	cases := []struct {
		name       string
		scenarioID string
		override   int
		want       time.Duration
	}{
		{"prevention default", "EG-002.known-bad", 0, DefaultEmailGWDwellWindowPreventionDetection},
		{"response default", "EG-008.known-good", 0, DefaultEmailGWDwellWindowResponse},
		{"response default via EG-010", "EG-010.detection", 0, DefaultEmailGWDwellWindowResponse},
		{"override within bounds", "EG-002.known-bad", 90, 90 * time.Second},
		{"override clamped to min", "EG-002.known-bad", 1, MinEmailGWDwellWindow},
		{"override clamped to max", "EG-002.known-bad", 100000, MaxEmailGWDwellWindow},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dwellWindowFor(c.scenarioID, c.override); got != c.want {
				t.Errorf("dwellWindowFor(%q, %d) = %v, want %v", c.scenarioID, c.override, got, c.want)
			}
		})
	}
}

func TestStatusForEmailGWResult(t *testing.T) {
	definitive := emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictConfirmedFailure}
	inconclusive := emailgwefficacy.VerdictDetail{Verdict: emailgwefficacy.VerdictInconclusive}

	allDefinitive := emailgwefficacy.EfficacyResult{Prevention: definitive, DetectionVerdict: definitive, ResponseVerdict: definitive}
	if got := statusForEmailGWResult(allDefinitive); got != emailgwrun.StatusCompleted {
		t.Errorf("all-definitive result = %q, want %q", got, emailgwrun.StatusCompleted)
	}

	onePartial := emailgwefficacy.EfficacyResult{Prevention: definitive, DetectionVerdict: inconclusive, ResponseVerdict: definitive}
	if got := statusForEmailGWResult(onePartial); got != emailgwrun.StatusPartial {
		t.Errorf("one-inconclusive result = %q, want %q", got, emailgwrun.StatusPartial)
	}
}
