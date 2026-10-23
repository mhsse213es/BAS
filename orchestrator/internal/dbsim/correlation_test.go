package dbsim

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

const (
	corrMarkerA = "bas-dbsim:0123456789abcdef01234567"
	corrMarkerB = "bas-dbsim:fedcba9876543210fedcba98"
)

var corrT0 = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

type fakeConn struct {
	reqs  []detectverify.VerifyRequest
	reply func(detectverify.VerifyRequest) (detectverify.VerifyResult, error)
}

func (f *fakeConn) Verify(ctx context.Context, r detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	f.reqs = append(f.reqs, r)
	if err := ctx.Err(); err != nil {
		return detectverify.VerifyResult{}, err
	}
	return f.reply(r)
}
func (f *fakeConn) TestConnection(context.Context) error { return nil }

func corrAlert(id string, at time.Time, text string) detectverify.MatchedAlert {
	raw, _ := json.Marshal(map[string]any{"source": map[string]any{"message": text}})
	return detectverify.MatchedAlert{AlertID: id, RuleName: "r", Timestamp: at, RawJSON: raw}
}

// fixed returns a connector that answers every Verify with the same alerts.
// Its Verdict is deliberately Detected: Correlate must ignore it.
func fixed(alerts ...detectverify.MatchedAlert) *fakeConn {
	return &fakeConn{reply: func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
		v := detectverify.VerdictNotDetected
		if len(alerts) > 0 {
			v = detectverify.VerdictDetected
		}
		return detectverify.VerifyResult{Verdict: v, MatchedAlerts: alerts}, nil
	}}
}

func corrIn() CorrelationInput {
	return CorrelationInput{
		Marker: corrMarkerA, Principal: "dbsim_test", RunID: "run-a",
		DBHost: "db01", DBIP: "10.0.0.5", AgentIP: "10.0.0.9",
		ProbeAt: corrT0, Window: 5 * time.Minute, SkewAllowance: 2 * time.Second,
	}
}

func TestExactMarkerInRawCreditsDetection(t *testing.T) {
	c := fixed(corrAlert("a1", corrT0.Add(7*time.Second), "SELECT 1 /* "+corrMarkerA+" */"))
	r, err := Correlate(context.Background(), c, corrIn())
	if err != nil {
		t.Fatal(err)
	}
	if r.Match != MatchExact || r.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("got %s/%s", r.Match, r.Telemetry)
	}
	if r.Latency != 7*time.Second {
		t.Fatalf("latency %s", r.Latency)
	}
	if r.Response != dlpreport.ResponseNotTested || !strings.Contains(r.Limitations, "Response was not assessed") {
		t.Fatalf("response %s lims %q", r.Response, r.Limitations)
	}
	if len(r.Alerts) != 1 {
		t.Fatalf("alerts %d", len(r.Alerts))
	}
}

func TestAlertWithoutMarkerIsUnverifiableNotAbsent(t *testing.T) {
	c := fixed(corrAlert("a1", corrT0.Add(time.Second), "some other SELECT"))
	r, err := Correlate(context.Background(), c, corrIn())
	if err != nil {
		t.Fatal(err)
	}
	if r.Match != MatchAmbiguous || r.Telemetry != dlpreport.TelemetryUnverifiable {
		t.Fatalf("got %s/%s", r.Match, r.Telemetry)
	}
	if r.Telemetry == dlpreport.TelemetryAbsent {
		t.Fatal("must not be absent")
	}
}

func TestNoAlertsHealthySourceIsAbsent(t *testing.T) {
	r, err := Correlate(context.Background(), fixed(), corrIn())
	if err != nil {
		t.Fatal(err)
	}
	if r.Match != MatchNone || r.Telemetry != dlpreport.TelemetryAbsent {
		t.Fatalf("got %s/%s", r.Match, r.Telemetry)
	}
}

func TestConnectorErrorIsUnverifiableNeverAbsent(t *testing.T) {
	for _, e := range []error{errors.New("401 unauthorised"), context.DeadlineExceeded} {
		c := &fakeConn{reply: func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
			return detectverify.VerifyResult{}, e
		}}
		r, err := Correlate(context.Background(), c, corrIn())
		if err == nil {
			t.Fatalf("%v: error must be returned", e)
		}
		if r.Telemetry != dlpreport.TelemetryUnverifiable || r.Match != MatchNone {
			t.Fatalf("%v: got %s/%s", e, r.Match, r.Telemetry)
		}
	}
}

func TestPartialLookupFailureNeverAbsent(t *testing.T) {
	n := 0
	c := &fakeConn{reply: func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
		n++
		if n == 2 {
			return detectverify.VerifyResult{}, errors.New("boom")
		}
		return detectverify.VerifyResult{}, nil
	}}
	r, err := Correlate(context.Background(), c, corrIn())
	if err == nil || r.Telemetry != dlpreport.TelemetryUnverifiable {
		t.Fatalf("got %v %s", err, r.Telemetry)
	}
}

func TestPositiveSurvivesOtherLookupFailure(t *testing.T) {
	n := 0
	c := &fakeConn{reply: func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
		n++
		if n == 2 {
			return detectverify.VerifyResult{}, errors.New("boom")
		}
		return detectverify.VerifyResult{MatchedAlerts: []detectverify.MatchedAlert{corrAlert("a", corrT0, corrMarkerA)}}, nil
	}}
	r, err := Correlate(context.Background(), c, corrIn())
	if err != nil || r.Match != MatchExact || r.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("got %v %s/%s", err, r.Match, r.Telemetry)
	}
	if !strings.Contains(r.Limitations, "lookups failed") {
		t.Fatalf("lims %q", r.Limitations)
	}
}

func TestAlertAfterWindowIsDelayed(t *testing.T) {
	in := corrIn()
	late := corrAlert("a1", corrT0.Add(in.Window+in.SkewAllowance+time.Minute), corrMarkerA)
	r, err := Correlate(context.Background(), fixed(late), in)
	if err != nil {
		t.Fatal(err)
	}
	if r.Telemetry != dlpreport.TelemetryDelayed || r.Match != MatchExact {
		t.Fatalf("got %s/%s", r.Match, r.Telemetry)
	}
	if r.Latency <= in.Window {
		t.Fatalf("latency %s", r.Latency)
	}
}

func TestAlertInsideSkewAllowanceAfterWindowIsOnTime(t *testing.T) {
	in := corrIn()
	a := corrAlert("a1", corrT0.Add(in.Window+time.Second), corrMarkerA)
	r, _ := Correlate(context.Background(), fixed(a), in)
	if r.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("got %s", r.Telemetry)
	}
}

func TestTwoConcurrentRunsDoNotCrossCorrelate(t *testing.T) {
	a := corrAlert("a", corrT0.Add(time.Second), "q "+corrMarkerA)
	b := corrAlert("b", corrT0.Add(2*time.Second), "q "+corrMarkerB)
	un := corrAlert("u", corrT0.Add(3*time.Second), "no marker at all")
	// only B's alert exists: A must not be credited.
	r, _ := Correlate(context.Background(), fixed(b), corrIn())
	if r.Match == MatchExact || r.Telemetry == dlpreport.TelemetryPresent {
		t.Fatalf("A credited with B's alert: %s/%s", r.Match, r.Telemetry)
	}
	if r.Match != MatchNone || r.Telemetry != dlpreport.TelemetryAbsent {
		t.Fatalf("foreign-only: got %s/%s", r.Match, r.Telemetry)
	}
	// both alerts exist: each run credited with its own.
	rA, _ := Correlate(context.Background(), fixed(a, b), corrIn())
	inB := corrIn()
	inB.Marker, inB.RunID = corrMarkerB, "run-b"
	rB, _ := Correlate(context.Background(), fixed(a, b), inB)
	if rA.Match != MatchExact || len(rA.Alerts) != 1 || rA.Alerts[0].AlertID != "a" {
		t.Fatalf("A: %+v", rA)
	}
	if rB.Match != MatchExact || len(rB.Alerts) != 1 || rB.Alerts[0].AlertID != "b" {
		t.Fatalf("B: %+v", rB)
	}
	// an alert without any marker alongside a foreign one is ambiguous, never exact.
	rU, _ := Correlate(context.Background(), fixed(b, un), corrIn())
	if rU.Match != MatchAmbiguous || rU.Telemetry != dlpreport.TelemetryUnverifiable {
		t.Fatalf("unmarked: %s/%s", rU.Match, rU.Telemetry)
	}
}

func TestUnionOfDBHostAndAgentIPDeduplicatesAlerts(t *testing.T) {
	shared := corrAlert("same", corrT0.Add(time.Second), corrMarkerA)
	c := fixed(shared)
	r, err := Correlate(context.Background(), c, corrIn())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.reqs) != 2 {
		t.Fatalf("verify calls %d", len(c.reqs))
	}
	if len(r.Alerts) != 1 {
		t.Fatalf("alerts %d", len(r.Alerts))
	}
	if c.reqs[0].HostName != "db01" || c.reqs[0].HostIP != "10.0.0.5" {
		t.Fatalf("db call %+v", c.reqs[0])
	}
	if c.reqs[1].HostName != "" || c.reqs[1].HostIP != "10.0.0.9" {
		t.Fatalf("agent call %+v", c.reqs[1])
	}
}

func TestQueryWindowsIncludeSkewAndNeverUseEmptyIdentifier(t *testing.T) {
	in := corrIn()
	c := fixed()
	if _, err := Correlate(context.Background(), c, in); err != nil {
		t.Fatal(err)
	}
	for _, q := range c.reqs {
		if !q.WindowStart.Equal(corrT0.Add(-in.SkewAllowance)) {
			t.Fatalf("start %s", q.WindowStart)
		}
		if q.WindowEnd.Before(corrT0.Add(in.Window + in.SkewAllowance)) {
			t.Fatalf("end %s", q.WindowEnd)
		}
	}
	for _, mut := range []func(*CorrelationInput){
		func(i *CorrelationInput) { i.DBHost = "" },
		func(i *CorrelationInput) { i.DBIP = "" },
		func(i *CorrelationInput) { i.AgentIP = "" },
		func(i *CorrelationInput) { i.DBHost, i.DBIP = " ", "" },
	} {
		in := corrIn()
		mut(&in)
		c := fixed()
		_, _ = Correlate(context.Background(), c, in)
		for _, q := range c.reqs {
			if strings.TrimSpace(q.HostName) == "" && strings.TrimSpace(q.HostIP) == "" {
				t.Fatalf("empty identifier query %+v for %+v", q, in)
			}
		}
	}
	// no identity at all: no query, unverifiable, error.
	in = corrIn()
	in.DBHost, in.DBIP, in.AgentIP = "", "", ""
	c = fixed()
	r, err := Correlate(context.Background(), c, in)
	if err == nil || len(c.reqs) != 0 || r.Telemetry != dlpreport.TelemetryUnverifiable {
		t.Fatalf("got %v %d %s", err, len(c.reqs), r.Telemetry)
	}
}

func TestSameHostRunNotedInLimitations(t *testing.T) {
	in := corrIn()
	in.AgentIP = in.DBIP
	c := fixed(corrAlert("a", corrT0, corrMarkerA))
	r, _ := Correlate(context.Background(), c, in)
	if !strings.Contains(r.Limitations, "same host") {
		t.Fatalf("lims %q", r.Limitations)
	}
	if len(c.reqs) != 1 {
		t.Fatalf("calls %d", len(c.reqs))
	}
	if r2, _ := Correlate(context.Background(), fixed(), corrIn()); strings.Contains(r2.Limitations, "same host") {
		t.Fatal("different hosts must not be flagged")
	}
}

func TestSkewAboveThresholdDowngradesTimingConfidence(t *testing.T) {
	a := corrAlert("a", corrT0.Add(time.Second), corrMarkerA)
	lo, _ := Correlate(context.Background(), fixed(a), corrIn())
	if lo.TimingConfidence != "normal" || strings.Contains(lo.Limitations, "low confidence") {
		t.Fatalf("normal skew: %q %q", lo.TimingConfidence, lo.Limitations)
	}
	in := corrIn()
	in.SkewAllowance = MaxTrustedSkew + time.Second
	hi, _ := Correlate(context.Background(), fixed(a), in)
	if hi.TimingConfidence != "low" || !strings.Contains(hi.Limitations, "low confidence") {
		t.Fatalf("high skew: %q %q", hi.TimingConfidence, hi.Limitations)
	}
	if hi.Match != MatchExact {
		t.Fatalf("match grade must stay honest: %s", hi.Match)
	}
}

func TestMarkerPrefixCollisionNotMatched(t *testing.T) {
	short := "bas-dbsim:0123456789abcdef012345"
	in := corrIn()
	in.Marker = short
	// run with the shorter marker must not match the longer one's alert
	r, _ := Correlate(context.Background(), fixed(corrAlert("a", corrT0, corrMarkerA)), in)
	if r.Match == MatchExact {
		t.Fatal("prefix collision matched")
	}
	// and the longer must not match an alert holding a longer token
	in.Marker = corrMarkerA
	r, _ = Correlate(context.Background(), fixed(corrAlert("a", corrT0, corrMarkerA+"ff")), in)
	if r.Match == MatchExact {
		t.Fatal("suffix-extended token matched")
	}
	// case-sensitive
	r, _ = Correlate(context.Background(), fixed(corrAlert("a", corrT0, strings.ToUpper(corrMarkerA))), corrIn())
	if r.Match == MatchExact {
		t.Fatal("case-insensitive match")
	}
	// trailing sentence punctuation still matches
	r, _ = Correlate(context.Background(), fixed(corrAlert("a", corrT0, "id "+corrMarkerA+".")), corrIn())
	if r.Match != MatchExact {
		t.Fatalf("punctuation: %s", r.Match)
	}
}

func TestPrincipalAndRunIDIsStrongNotExact(t *testing.T) {
	c := fixed(corrAlert("a", corrT0.Add(time.Second), "user dbsim_test ran run-a"))
	r, _ := Correlate(context.Background(), c, corrIn())
	if r.Match != MatchStrong || r.Telemetry != dlpreport.TelemetryPresent {
		t.Fatalf("got %s/%s", r.Match, r.Telemetry)
	}
	if !strings.Contains(r.Limitations, "strong contextual") {
		t.Fatalf("lims %q", r.Limitations)
	}
	// principal alone is not enough to attribute (shared account, concurrent runs).
	r, _ = Correlate(context.Background(), fixed(corrAlert("a", corrT0, "user dbsim_test")), corrIn())
	if r.Match != MatchAmbiguous {
		t.Fatalf("principal-only: %s", r.Match)
	}
}

func TestForeignAlertQuotingAnotherRunsMarker(t *testing.T) {
	// carries principal and run id of ours AND another run's marker: not ours.
	c := fixed(corrAlert("a", corrT0, "dbsim_test run-a "+corrMarkerB))
	r, _ := Correlate(context.Background(), c, corrIn())
	if r.Match == MatchExact || r.Match == MatchStrong {
		t.Fatalf("credited foreign alert: %s", r.Match)
	}
}

func TestTruncatedRawIsAmbiguousNotAbsent(t *testing.T) {
	raw := json.RawMessage(`{"source":{"message":"long..."},"sourceTruncated":true}`)
	a := detectverify.MatchedAlert{AlertID: "t", Timestamp: corrT0, RawJSON: raw}
	r, _ := Correlate(context.Background(), fixed(a), corrIn())
	if r.Match != MatchAmbiguous || r.Telemetry != dlpreport.TelemetryUnverifiable {
		t.Fatalf("got %s/%s", r.Match, r.Telemetry)
	}
	// even with a foreign marker visible, truncation keeps it unattributable.
	raw = json.RawMessage(`{"source":{"message":"` + corrMarkerB + `"},"sourceTruncated":true}`)
	a.RawJSON = raw
	r, _ = Correlate(context.Background(), fixed(a), corrIn())
	if r.Match != MatchAmbiguous {
		t.Fatalf("foreign+truncated: %s", r.Match)
	}
}

func TestVerdictIsIgnored(t *testing.T) {
	c := &fakeConn{reply: func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
		return detectverify.VerifyResult{Verdict: detectverify.VerdictDetected, Confidence: detectverify.ConfidenceHigh}, nil
	}}
	r, _ := Correlate(context.Background(), c, corrIn())
	if r.Telemetry != dlpreport.TelemetryAbsent {
		t.Fatalf("verdict leaked: %s", r.Telemetry)
	}
}

func TestCorrelateContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := fixed()
	r, err := Correlate(ctx, c, corrIn())
	if err == nil || r.Telemetry != dlpreport.TelemetryUnverifiable {
		t.Fatalf("got %v %s", err, r.Telemetry)
	}
}

func TestAlertOutsideQueriedRangeIgnored(t *testing.T) {
	in := corrIn()
	old := corrAlert("o", corrT0.Add(-time.Hour), corrMarkerA)
	r, _ := Correlate(context.Background(), fixed(old), in)
	if r.Match == MatchExact {
		t.Fatal("alert from before the probe credited")
	}
}

func TestResultToCorrelationFeedsReport(t *testing.T) {
	r, _ := Correlate(context.Background(), fixed(corrAlert("a", corrT0, corrMarkerA)), corrIn())
	c := r.ToCorrelation()
	if !c.Evaluated || c.Match != MatchExactMarker || c.Alerts != 1 || detectionGrade(c) != DimPass {
		t.Fatalf("%+v", c)
	}
}
