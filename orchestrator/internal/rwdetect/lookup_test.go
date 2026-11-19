package rwdetect

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/rwevidence"
)

type fakeConnector struct {
	result detectverify.VerifyResult
	err    error
	calls  int
	last   detectverify.VerifyRequest
}

func (f *fakeConnector) Verify(_ context.Context, req detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	f.calls++
	f.last = req
	return f.result, f.err
}

func (f *fakeConnector) TestConnection(context.Context) error { return nil }

type fakeContextSource struct {
	ctx AttemptContext
	err error
}

func (f fakeContextSource) AttemptContextFor(context.Context, rwevidence.AttemptKey) (AttemptContext, error) {
	return f.ctx, f.err
}

var fixedNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func newTestLookup(conn detectverify.Connector, src ContextSource) *ConnectorLookup {
	l := NewConnectorLookup(conn, src)
	l.Now = func() time.Time { return fixedNow }
	return l
}

func validContext() AttemptContext {
	return AttemptContext{
		HostName:   "HOST01",
		HostIP:     "10.0.0.10",
		ExecutedAt: time.Date(2026, 10, 28, 11, 30, 0, 0, time.UTC),
	}
}

func lookupKey() rwevidence.AttemptKey {
	return rwevidence.AttemptKey{RunID: "run-1", TechniqueID: "T1490", Action: "T1490:vss_delete"}
}

func TestConnectorLookup_WindowIsAnchoredOnExecutionTimestampWithDefaultPolicy(t *testing.T) {
	conn := &fakeConnector{result: detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}}
	l := newTestLookup(conn, fakeContextSource{ctx: validContext()})

	if _, _, _, err := l.LookupDetection(context.Background(), lookupKey()); err != nil {
		t.Fatal(err)
	}
	if conn.calls != 1 {
		t.Fatalf("connector calls = %d, want 1", conn.calls)
	}
	exec := validContext().ExecutedAt
	if !conn.last.WindowStart.Equal(exec.Add(-DefaultWindowPolicy.Before)) {
		t.Fatalf("WindowStart = %s, want execution - %s", conn.last.WindowStart, DefaultWindowPolicy.Before)
	}
	if !conn.last.WindowEnd.Equal(exec.Add(DefaultWindowPolicy.After)) {
		t.Fatalf("WindowEnd = %s, want execution + %s", conn.last.WindowEnd, DefaultWindowPolicy.After)
	}
	if !conn.last.StepExecutedAt.Equal(exec) {
		t.Fatalf("StepExecutedAt = %s, want %s", conn.last.StepExecutedAt, exec)
	}
}

func TestConnectorLookup_NormalizesNonUTCExecutionTimeToUTC(t *testing.T) {
	ist := time.FixedZone("UTC+3", 3*60*60)
	ac := validContext()
	ac.ExecutedAt = time.Date(2026, 10, 28, 14, 30, 0, 0, ist) // 11:30 UTC
	conn := &fakeConnector{result: detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}}
	l := newTestLookup(conn, fakeContextSource{ctx: ac})

	if _, _, _, err := l.LookupDetection(context.Background(), lookupKey()); err != nil {
		t.Fatal(err)
	}
	if conn.last.WindowStart.Location() != time.UTC || conn.last.WindowEnd.Location() != time.UTC {
		t.Fatal("window bounds must be UTC")
	}
	if !conn.last.WindowStart.Equal(time.Date(2026, 10, 28, 11, 25, 0, 0, time.UTC)) {
		t.Fatalf("WindowStart = %s, want 11:25 UTC", conn.last.WindowStart)
	}
}

func TestConnectorLookup_PassesHostIdentityFromContextSource(t *testing.T) {
	conn := &fakeConnector{result: detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}}
	l := newTestLookup(conn, fakeContextSource{ctx: validContext()})

	if _, _, _, err := l.LookupDetection(context.Background(), lookupKey()); err != nil {
		t.Fatal(err)
	}
	if conn.last.HostName != "HOST01" || conn.last.HostIP != "10.0.0.10" {
		t.Fatalf("host = %q/%q, want HOST01/10.0.0.10", conn.last.HostName, conn.last.HostIP)
	}
	if conn.last.RunID != "run-1" || conn.last.TechniqueID != "T1490" {
		t.Fatalf("run/technique = %q/%q", conn.last.RunID, conn.last.TechniqueID)
	}
}

func TestConnectorLookup_DetectedVerdictVerifies(t *testing.T) {
	conn := &fakeConnector{result: detectverify.VerifyResult{
		Verdict:       detectverify.VerdictDetected,
		Confidence:    "high",
		MatchedAlerts: []detectverify.MatchedAlert{{}},
	}}
	l := newTestLookup(conn, fakeContextSource{ctx: validContext()})

	tested, verified, reason, err := l.LookupDetection(context.Background(), lookupKey())
	if err != nil {
		t.Fatal(err)
	}
	if !tested || !verified {
		t.Fatalf("tested=%v verified=%v, want true/true", tested, verified)
	}
	if !strings.Contains(reason, "1 alert matched") {
		t.Fatalf("reason %q should describe the matched alert", reason)
	}
}

func TestConnectorLookup_ReasonRecordsProvenance(t *testing.T) {
	conn := &fakeConnector{result: detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}}
	l := newTestLookup(conn, fakeContextSource{ctx: validContext()})

	_, _, reason, err := l.LookupDetection(context.Background(), lookupKey())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"HOST01", "10.0.0.10", "2026-10-28T11:30:00Z", "time source=step execution timestamp"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("reason %q missing provenance %q", reason, want)
		}
	}
}

func TestConnectorLookup_MissingExecutionTimestampIsInconclusiveAndNeverQueries(t *testing.T) {
	ac := validContext()
	ac.ExecutedAt = time.Time{}
	conn := &fakeConnector{}
	l := newTestLookup(conn, fakeContextSource{ctx: ac})

	tested, verified, reason, err := l.LookupDetection(context.Background(), lookupKey())
	if err != nil {
		t.Fatal(err)
	}
	if tested || verified {
		t.Fatalf("tested=%v verified=%v, want false/false", tested, verified)
	}
	if conn.calls != 0 {
		t.Fatal("connector must not be queried without a real execution timestamp")
	}
	if !strings.Contains(reason, "inconclusive") {
		t.Fatalf("reason %q should say inconclusive", reason)
	}
}

func TestConnectorLookup_FutureExecutionTimestampBeyondToleranceIsInconclusive(t *testing.T) {
	ac := validContext()
	ac.ExecutedAt = fixedNow.Add(2 * time.Hour)
	conn := &fakeConnector{}
	l := newTestLookup(conn, fakeContextSource{ctx: ac})

	tested, _, reason, err := l.LookupDetection(context.Background(), lookupKey())
	if err != nil {
		t.Fatal(err)
	}
	if tested || conn.calls != 0 {
		t.Fatal("a future execution timestamp must not be queried")
	}
	if !strings.Contains(reason, "inconclusive") {
		t.Fatalf("reason %q should say inconclusive", reason)
	}
}

func TestConnectorLookup_MissingHostIdentityIsInconclusive(t *testing.T) {
	ac := validContext()
	ac.HostName = ""
	ac.HostIP = ""
	conn := &fakeConnector{}
	l := newTestLookup(conn, fakeContextSource{ctx: ac})

	tested, _, reason, err := l.LookupDetection(context.Background(), lookupKey())
	if err != nil {
		t.Fatal(err)
	}
	if tested || conn.calls != 0 {
		t.Fatal("no host identity means no query")
	}
	if !strings.Contains(reason, "inconclusive") {
		t.Fatalf("reason %q should say inconclusive", reason)
	}
}

func TestConnectorLookup_TechniqueWithoutMitreIDIsInconclusive(t *testing.T) {
	conn := &fakeConnector{}
	l := newTestLookup(conn, fakeContextSource{ctx: validContext()})
	key := rwevidence.AttemptKey{RunID: "run-1", TechniqueID: "", Action: "x"}

	tested, _, _, err := l.LookupDetection(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if tested || conn.calls != 0 {
		t.Fatal("a technique with no MITRE mapping cannot be queried")
	}
}

func TestConnectorLookup_ContextSourceErrorPropagates(t *testing.T) {
	boom := errors.New("registry unavailable")
	conn := &fakeConnector{}
	l := newTestLookup(conn, fakeContextSource{err: boom})

	_, _, _, err := l.LookupDetection(context.Background(), lookupKey())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the context source's error", err)
	}
	if conn.calls != 0 {
		t.Fatal("no query when context cannot be resolved")
	}
}

func TestConnectorLookup_ConnectorErrorPropagates(t *testing.T) {
	boom := errors.New("tenant auth failed")
	conn := &fakeConnector{err: boom}
	l := newTestLookup(conn, fakeContextSource{ctx: validContext()})

	_, _, _, err := l.LookupDetection(context.Background(), lookupKey())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the connector's error", err)
	}
}

func TestConnectorLookup_ReasonCarriesHostProblemWhenHostUnavailable(t *testing.T) {
	ac := validContext()
	ac.HostName, ac.HostIP = "", ""
	ac.HostProblem = "agent registration record has no hostname or IP"
	conn := &fakeConnector{}
	l := newTestLookup(conn, fakeContextSource{ctx: ac})

	_, _, reason, err := l.LookupDetection(context.Background(), lookupKey())
	if err != nil {
		t.Fatal(err)
	}
	if conn.calls != 0 {
		t.Fatal("no query without host identity")
	}
	if !strings.Contains(reason, "agent registration record has no hostname or IP") {
		t.Fatalf("reason %q must carry the specific host problem", reason)
	}
}

func TestConnectorLookup_ReasonCarriesTimeProblemAndKeepsHostContext(t *testing.T) {
	ac := validContext()
	ac.ExecutedAt = time.Time{}
	ac.TimeProblem = "orchestrator fallback timestamp recorded for this step; it is submission time, not agent-observed execution time"
	conn := &fakeConnector{}
	l := newTestLookup(conn, fakeContextSource{ctx: ac})

	_, _, reason, err := l.LookupDetection(context.Background(), lookupKey())
	if err != nil {
		t.Fatal(err)
	}
	if conn.calls != 0 {
		t.Fatal("no query without a trustworthy event time")
	}
	if !strings.Contains(reason, "not agent-observed") {
		t.Fatalf("reason %q must carry the specific time problem", reason)
	}
	if !strings.Contains(reason, "HOST01") {
		t.Fatalf("reason %q must retain the valid host context", reason)
	}
}

func TestConnectorLookup_ReasonDistinguishesMissingStepMetadataFromAmbiguousTime(t *testing.T) {
	ac := validContext()
	ac.ExecutedAt = time.Time{}
	ac.TimeProblem = "step metadata missing for this attempt"
	l := newTestLookup(&fakeConnector{}, fakeContextSource{ctx: ac})

	_, _, reason, _ := l.LookupDetection(context.Background(), lookupKey())
	if !strings.Contains(reason, "step metadata missing") {
		t.Fatalf("reason %q must name missing step metadata", reason)
	}

	ac.TimeProblem = "2 distinct execution timestamps recorded for this step; the event cannot be identified"
	l = newTestLookup(&fakeConnector{}, fakeContextSource{ctx: ac})
	_, _, reason, _ = l.LookupDetection(context.Background(), lookupKey())
	if !strings.Contains(reason, "2 distinct execution timestamps") {
		t.Fatalf("reason %q must name the duplicate executions", reason)
	}
}
