package dbjobs

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/dbsim/dbrun"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

// settleThenErrStore plays the concurrent winner: its Transition optionally
// settles the job (as another Ingest, the reaper or a cancel would) and fails.
type settleThenErrStore struct {
	*fakeStore
	to      dbsim.JobStatus
	settle  bool
	callErr error
}

func (s *settleThenErrStore) Transition(_ context.Context, id string, _ []dbsim.JobStatus, _ dbsim.JobStatus, _ string, _ dbadmin.AuditEntry) (bool, error) {
	if s.settle {
		s.mu.Lock()
		j := s.jobs[id]
		j.Status = s.to
		s.jobs[id] = j
		s.mu.Unlock()
	}
	return false, s.callErr
}

func TestIngestLostFinishRaceIsBenignWhenJobAlreadySettled(t *testing.T) {
	for _, to := range []dbsim.JobStatus{dbsim.JobCompleted, dbsim.JobPartial, dbsim.JobFailed, dbsim.JobCancelled} {
		r := newIngestRig(t, threeScenarios)
		r.svc.Jobs = &settleThenErrStore{fakeStore: r.store, to: to, settle: true, callErr: errors.New("tx aborted")}
		handled, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
		if !handled || err != nil {
			t.Errorf("settled to %s: handled=%v err=%v, want true,nil", to, handled, err)
		}
		if len(r.sink.rows) != 3 {
			t.Errorf("rows = %d, want one set", len(r.sink.rows))
		}
	}
	// A real store error with the job still active IS reported (and redacted).
	r := newIngestRig(t, threeScenarios)
	r.svc.Jobs = &settleThenErrStore{fakeStore: r.store, callErr: errors.New("tx aborted password=hunter2")}
	_, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v, want a redacted store error", err)
	}
}

func TestIngestTwoRacingSubmissionsSaveOneSetOfRows(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	var wg sync.WaitGroup
	var errs atomic.Int32
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
				errs.Add(1)
			}
		}()
	}
	wg.Wait()
	if errs.Load() != 0 || len(r.sink.rows) != 3 || r.status() != dbsim.JobCompleted {
		t.Fatalf("errs=%d rows=%d status=%s", errs.Load(), len(r.sink.rows), r.status())
	}
}

func TestIngestCancelDuringGradingSavesNothing(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	r.conn.reply = func(detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
		r.store.mu.Lock()
		j := r.store.jobs[runIDx]
		j.Status = dbsim.JobCancelled
		r.store.jobs[runIDx] = j
		r.store.mu.Unlock()
		return detectverify.VerifyResult{Verdict: detectverify.VerdictNotDetected}, nil
	}
	handled, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
	if !handled || err != nil {
		t.Fatalf("handled=%v err=%v, want true,nil", handled, err)
	}
	if r.conn.calls == 0 {
		t.Fatal("test setup: the connector was never asked")
	}
	if r.sink.saves != 0 || r.status() != dbsim.JobCancelled {
		t.Errorf("saves=%d status=%s: a job cancelled during grading must save nothing", r.sink.saves, r.status())
	}
}

type blockingConn struct{ calls atomic.Int32 }

func (b *blockingConn) Verify(ctx context.Context, _ detectverify.VerifyRequest) (detectverify.VerifyResult, error) {
	b.calls.Add(1)
	<-ctx.Done()
	return detectverify.VerifyResult{}, ctx.Err()
}
func (b *blockingConn) TestConnection(context.Context) error { return nil }

func reportOf(t *testing.T, row RunRecord) dbsim.StoredReport {
	t.Helper()
	var rep dbsim.StoredReport
	if err := json.Unmarshal(row.Report, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestIngestBlockingConnectorIsBoundedAndUnverifiable(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
	bc := &blockingConn{}
	r.svc.ConnectorFactory = func(context.Context) (detectverify.Connector, error) { return bc, nil }
	r.svc.ConnectorTimeout = 30 * time.Millisecond
	start := time.Now()
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the connector call was not bounded")
	}
	row, ok := r.sink.row(runIDx, scDB05)
	if !ok || bc.calls.Load() == 0 {
		t.Fatalf("ok=%v calls=%d", ok, bc.calls.Load())
	}
	if got := reportOf(t, row).Record.Telemetry; got != dlpreport.TelemetryUnverifiable || row.Result == string(dbsim.ResultPass) {
		t.Errorf("telemetry=%v result=%s, want Unverifiable and never a pass", got, row.Result)
	}
}

func TestIngestBlockingFactoryIsBounded(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
	r.svc.ConnectorFactory = func(ctx context.Context) (detectverify.Connector, error) { <-ctx.Done(); return nil, ctx.Err() }
	r.svc.ConnectorTimeout = 30 * time.Millisecond
	start := time.Now()
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	row, ok := r.sink.row(runIDx, scDB05)
	if time.Since(start) > 5*time.Second || !ok || reportOf(t, row).Record.Telemetry != dlpreport.TelemetryUnverifiable {
		t.Errorf("elapsed=%v ok=%v: a stuck factory must be bounded and leave telemetry Unverifiable", time.Since(start), ok)
	}
}

func TestIngestOverallDeadlineBoundsGrading(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	bc := &blockingConn{}
	r.svc.ConnectorFactory = func(context.Context) (detectverify.Connector, error) { return bc, nil }
	r.svc.ConnectorTimeout = time.Hour
	r.svc.IngestTimeout = 80 * time.Millisecond
	start := time.Now()
	handled, err := r.svc.Ingest(context.Background(), r.sub(r.results()))
	if time.Since(start) > 5*time.Second {
		t.Fatal("Ingest ignored its overall deadline")
	}
	if !handled || err != nil {
		t.Fatalf("handled=%v err=%v", handled, err)
	}
	for _, k := range r.sink.order {
		if reportOf(t, r.sink.rows[k]).Record.Telemetry == dlpreport.TelemetryAbsent {
			t.Errorf("%s: a timed-out lookup must never be an Absent/miss", k)
		}
	}
}

func TestIngestInlineDetectionWaitIsCapped(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
	clock := t0
	r.svc.Now = func() time.Time { return clock }
	sleeps := 0
	r.svc.Sleep = func(_ context.Context, d time.Duration) { sleeps++; clock = clock.Add(d) }
	r.svc.DetectionWait = 24 * time.Hour
	r.svc.DetectionPoll = 10 * time.Second
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	if max := int(MaxInlineDetectionWait/(10*time.Second)) + 1; sleeps == 0 || sleeps > max {
		t.Errorf("sleeps = %d, want between 1 and %d (wait clamped to %s)", sleeps, max, MaxInlineDetectionWait)
	}
}

func TestIngestUnknownPrincipalSkipsCorrelation(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
	r.svc.Principal = nil // no source of the DB account name: never guess
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	row, _ := r.sink.row(runIDx, scDB05)
	rep := reportOf(t, row)
	if r.conn.calls != 0 {
		t.Error("no principal: the SIEM must not be queried")
	}
	if rep.Record.Telemetry != dlpreport.TelemetryUnverifiable || row.Result == string(dbsim.ResultPass) {
		t.Errorf("telemetry=%v result=%s", rep.Record.Telemetry, row.Result)
	}
	if !strings.Contains(rep.Record.Limitations, "principal unknown") {
		t.Errorf("limitations = %q, want 'principal unknown'", rep.Record.Limitations)
	}
}

func TestIngestUnavailableTargetSkipsCorrelation(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
	delete(r.tg.recs, "lab-db")
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	row, ok := r.sink.row(runIDx, scDB05)
	if !ok {
		t.Fatal("no row")
	}
	rep := reportOf(t, row)
	if r.conn.calls != 0 || rep.Record.Telemetry != dlpreport.TelemetryUnverifiable || !strings.Contains(rep.Record.Limitations, "target unavailable") {
		t.Errorf("calls=%d telemetry=%v limitations=%q", r.conn.calls, rep.Record.Telemetry, rep.Record.Limitations)
	}
}

func TestIngestPrincipalComesFromServiceFunc(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB05, "suspicious_read"}})
	var gotJob dbsim.RunJob
	var gotRec dbsim.TargetRecord
	r.svc.Principal = func(j dbsim.RunJob, tr dbsim.TargetRecord, _ dbsim.DBProbeResult) string {
		gotJob, gotRec = j, tr
		return "svc_account"
	}
	if _, err := r.svc.Ingest(context.Background(), r.sub(r.results())); err != nil {
		t.Fatal(err)
	}
	if gotJob.ID != runIDx || gotRec.ID != "lab-db" || r.conn.calls == 0 {
		t.Errorf("job=%s rec=%s calls=%d", gotJob.ID, gotRec.ID, r.conn.calls)
	}
}

func TestIngestFinishAuditCarriesPerStepVerdicts(t *testing.T) {
	r := newIngestRig(t, []pstep{{scDB01, "auth_check"}, {scDB01, "read_roles"}})
	res := r.results()
	res[1] = dbrun.AgentExec{TaskID: res[1].TaskID, ExitCode: 1, Stderr: "boom password=hunter2"}
	if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r.store.audits[len(r.store.audits)-1].Entry.Detail)
	body := string(b)
	for _, want := range []string{"auth_check", "read_roles", "ERROR"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit detail lacks %q: %s", want, body)
		}
	}
	if strings.Contains(body, "hunter2") {
		t.Errorf("audit leaks a secret: %s", body)
	}
}

func TestIngestDuplicateEchoedTaskIDKeepsFirst(t *testing.T) {
	r := newIngestRig(t, threeScenarios)
	res := r.results()
	res[1].TaskID = res[0].TaskID // two results echo task-a: the second is dropped, step b has nothing
	if _, err := r.svc.Ingest(context.Background(), r.sub(res)); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.sink.row(runIDx, scDB01); ok || r.status() != dbsim.JobPartial {
		t.Errorf("status=%s: a repeated echo must not fill another step", r.status())
	}
}

func TestAgentExecTaskIDWireTag(t *testing.T) {
	b, err := json.Marshal(dbrun.AgentExec{TaskID: "t1"})
	if err != nil || !strings.Contains(string(b), `"taskId":"t1"`) {
		t.Fatalf("marshal = %s err=%v", b, err)
	}
	var x dbrun.AgentExec
	if err := json.Unmarshal([]byte(`{"taskId":"t9","exitCode":0,"stdout":"","dbProbe":{"denied":true}}`), &x); err != nil || x.TaskID != "t9" || x.DBProbe == nil || !x.DBProbe.Denied {
		t.Fatalf("unmarshal = %+v err=%v", x, err)
	}
}
