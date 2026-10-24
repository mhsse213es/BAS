package dbjobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/dbsim/dbadmin"
	"github.com/audspect/bas/internal/dbsim/dbbuild"
	"github.com/audspect/bas/internal/dbsim/dbrun"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

// Lab defaults for the detection window and clock skew (the values the live
// staging e2e runs were graded with). Service fields override them.
const (
	DefaultDetectionWindow = 3 * time.Minute
	DefaultSkewAllowance   = 5 * time.Second
	DefaultDetectionPoll   = 10 * time.Second
)

// RunRecord is one graded scenario row. It mirrors db.DBSimRun field for field
// (internal/db cannot be imported here without a cycle risk, and must never
// import this package), so the sink adapter converts it directly.
type RunRecord struct {
	ScenarioID      string
	ScenarioVersion string
	TargetID        string
	Engine          string
	RunID           string
	Result          string // PASS, FAIL, ERROR or SKIPPED
	Report          []byte
}

// RunSink stores graded rows. Save reports duplicate=true (and stores nothing)
// when the (run id, scenario) row already exists; Count is the number of rows
// stored for a run (the deadline reaper uses it to tell failed from partial).
type RunSink interface {
	Save(ctx context.Context, rec RunRecord) (duplicate bool, err error)
	Count(ctx context.Context, runID string) (int, error)
}

// ConnectorFactory supplies the alert source. nil, or an error, means the run is
// graded without correlation: Telemetry stays Unverifiable, never a miss.
type ConnectorFactory func(ctx context.Context) (detectverify.Connector, error)

// IdentityRecorder records the result of an identity-check job. It must record
// nothing (returning ErrNotRecorded) when the target changed during the check.
type IdentityRecorder interface {
	Record(ctx context.Context, job dbsim.RunJob, res dbsim.DBProbeResult) error
}

// ErrNotRecorded means the recorder deliberately stored nothing (the target was
// changed, deleted or superseded while the check ran).
var ErrNotRecorded = errors.New("dbsim: identity check result not recorded")

// Submission is what an agent reported for a run id: ONE result list in plan
// step order for the concatenated steps of every selected scenario.
type Submission struct {
	RunID, AgentID string
	Partial        bool
	Results        []dbrun.AgentExec
}

func redactErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(dbsim.Redact(err.Error()))
}

func redactf(format string, a ...any) error {
	return errors.New(dbsim.Redact(fmt.Sprintf(format, a...)))
}

// Ingest grades and stores an agent's result for a dbsim job.
//
// handled=false means the run id is not a dbsim job and the caller continues
// exactly as before. handled=true with a nil error covers success AND the
// deliberate no-ops: a result for a job that is no longer active (cancelled,
// failed, already finished: a replay) changes nothing. A result from an agent
// other than the job's bound agent is rejected with an error and saves nothing.
//
// Grading uses only the STORED plan (marker, probe id, run id, expectations);
// from the agent it takes the execution outcome. The agent's echoed task id is
// only a cross-check for matching results to plan steps.
func (s *Service) Ingest(ctx context.Context, sub Submission) (handled bool, err error) {
	if s == nil || s.Jobs == nil || !strings.HasPrefix(sub.RunID, dbbuild.RunIDPrefix) {
		return false, nil
	}
	job, err := s.Jobs.Get(ctx, sub.RunID)
	if err != nil {
		if errors.Is(err, dbsim.ErrJobNotFound) {
			return false, nil
		}
		return true, redactf("dbsim: ingest: load job: %v", err)
	}
	if sub.AgentID != job.AgentID {
		return true, redactf("dbsim: ingest: result for run %s came from agent %q, not the job's bound agent", trunc(job.ID, 80), trunc(sub.AgentID, 64))
	}
	if !job.Status.Active() {
		return true, nil
	}
	if job.Kind == dbsim.JobKindIdentityCheck {
		return true, s.ingestIdentity(ctx, job, sub)
	}
	return true, s.ingestRun(ctx, job, sub)
}

func (s *Service) finish(ctx context.Context, job dbsim.RunJob, to dbsim.JobStatus, reason, outcome string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["runId"], detail["targetId"], detail["agentId"] = job.ID, job.TargetID, job.AgentID
	if reason != "" {
		detail["reason"] = dbsim.Redact(reason)
	}
	action := "dbsim.run_" + string(to)
	e := dbadmin.AuditEntry{ActorID: "agent:" + job.AgentID, Action: action, Resource: "dbsim-run:" + job.ID, Detail: detail, Outcome: outcome}
	if _, err := s.Jobs.Transition(ctx, job.ID, []dbsim.JobStatus{dbsim.JobPending, dbsim.JobRunning}, to, dbsim.Redact(reason), e); err != nil {
		return redactf("dbsim: ingest: finish job: %v", err)
	}
	return nil
}

// ---- identity-check jobs ------------------------------------------------------

func (s *Service) ingestIdentity(ctx context.Context, job dbsim.RunJob, sub Submission) error {
	res, ok := dbsim.DBProbeResult{ErrorClass: "no_result"}, false
	if !sub.Partial && len(job.Plan) == 1 {
		for _, r := range sub.Results {
			if r.TaskID != "" && r.TaskID != job.Plan[0].TaskID {
				continue
			}
			if r.DBProbe != nil {
				res, ok = *r.DBProbe, true
			}
			break
		}
	}
	if s.Identity == nil {
		reason := "no identity recorder is configured: nothing was recorded"
		if ferr := s.finish(ctx, job, dbsim.JobFailed, reason, "error", nil); ferr != nil {
			return ferr
		}
		return errors.New("dbsim: " + reason)
	}
	if err := s.Identity.Record(ctx, job, res); err != nil {
		if errors.Is(err, ErrNotRecorded) {
			return s.finish(ctx, job, dbsim.JobFailed, "the target changed during the check: nothing was recorded", "error", nil)
		}
		if ferr := s.finish(ctx, job, dbsim.JobFailed, "the check result could not be recorded", "error", nil); ferr != nil {
			return errors.Join(redactErr(err), ferr)
		}
		return redactf("dbsim: ingest: record identity check: %v", err)
	}
	if !ok {
		return s.finish(ctx, job, dbsim.JobFailed, "the agent returned no usable check result (a failed check was recorded)", "error", nil)
	}
	return s.finish(ctx, job, dbsim.JobCompleted, "", "ok", nil)
}

// IdentityStore is the part of dbadmin.TargetStore the default recorder needs.
type IdentityStore interface {
	Get(ctx context.Context, id string) (dbsim.TargetRecord, error)
	SaveIdentityCheck(ctx context.Context, against dbsim.TargetRecord, st dbsim.IdentityCheckState, audit dbadmin.AuditEntry) error
}

type identityRecorder struct{ store IdentityStore }

// NewIdentityRecorder is the default IdentityRecorder: dbsim.EvaluateReadOnlyIdentity,
// then the existing version-bound, audited SaveIdentityCheck, with the same
// semantics as dbadmin.Service.RunIdentityCheck: a check that does not pass for
// ANY reason (including a malformed or missing result) records a FAILED check,
// which withdraws an earlier pass; a pass is recorded only for a well-formed
// result with every capability observed as "no". A target that was deleted,
// re-registered, edited or rebound since the job started, or a newer stored
// result, records nothing (ErrNotRecorded).
func NewIdentityRecorder(store IdentityStore) IdentityRecorder {
	return &identityRecorder{store: store}
}

func (r *identityRecorder) Record(ctx context.Context, job dbsim.RunJob, res dbsim.DBProbeResult) error {
	if r == nil || r.store == nil {
		return errors.New("dbsim: identity store unavailable")
	}
	rec, err := r.store.Get(ctx, job.TargetID)
	if err != nil {
		if errors.Is(err, dbsim.ErrTargetNotFound) {
			return ErrNotRecorded
		}
		return err
	}
	if len(job.Plan) != 1 || !specMatchesRecord(job.Plan[0].Spec, rec) || rec.AgentID != job.AgentID || rec.CreatedAt.After(job.CreatedAt) {
		return ErrNotRecorded
	}
	verdict := dbsim.EvaluateReadOnlyIdentity(rec.Engine, res)
	const action = "dbsim.target_identity_checked"
	audit := dbadmin.AuditEntry{ActorID: job.CreatedBy, Action: action, Resource: "dbsim-target:" + trunc(job.TargetID, 64),
		Detail: map[string]any{"passed": verdict.Passed, "reasons": verdict.Reasons, "runId": job.ID}, Outcome: "ok"}
	st := dbsim.IdentityCheckState{Checked: true, Passed: verdict.Passed, At: job.CreatedAt, By: job.CreatedBy, Reasons: verdict.Reasons}
	if err := r.store.SaveIdentityCheck(ctx, rec, st, audit); err != nil {
		if errors.Is(err, dbsim.ErrTargetChanged) || errors.Is(err, dbsim.ErrIdentityCheckSuperseded) {
			return ErrNotRecorded
		}
		return err
	}
	return nil
}

func specMatchesRecord(sp dbsim.DBProbeSpec, rec dbsim.TargetRecord) bool {
	return sp.TargetID == rec.ID && sp.Engine == rec.Engine && sp.Host == rec.Host && sp.Port == rec.Port &&
		sp.Database == rec.Database && sp.TLSMode == rec.TLSMode && sp.ExpectedIdentity == rec.ExpectedIdentity &&
		sp.CredentialRef == rec.CredentialRef
}

// ---- run jobs -----------------------------------------------------------------

// matchResults maps the agent's single result list onto the plan. A result that
// echoes a task id is matched by it (an id outside the plan, or a repeat, is
// dropped); a result without an echo is matched by its position. The returned
// slice has one entry per plan step, nil where nothing usable arrived.
func matchResults(plan []dbsim.PlannedStep, results []dbrun.AgentExec) []*dbrun.AgentExec {
	out := make([]*dbrun.AgentExec, len(plan))
	byTask := make(map[string]int, len(plan))
	for i, p := range plan {
		byTask[p.TaskID] = i
	}
	for i := range results {
		r := &results[i]
		at := i
		if r.TaskID != "" {
			j, ok := byTask[r.TaskID]
			if !ok {
				continue
			}
			at = j
		}
		if at < 0 || at >= len(plan) || out[at] != nil {
			continue
		}
		out[at] = r
	}
	return out
}

// worse ranks verdicts: ERROR, then FAIL, then SKIPPED, then PASS.
func rank(r dbsim.RunResult) int {
	switch r {
	case dbsim.ResultError:
		return 3
	case dbsim.ResultFail:
		return 2
	case dbsim.ResultSkipped:
		return 1
	}
	return 0
}

func (s *Service) window() time.Duration {
	if s.DetectionWindow > 0 {
		return s.DetectionWindow
	}
	return DefaultDetectionWindow
}

func (s *Service) skew() time.Duration {
	if s.SkewAllowance > 0 {
		return s.SkewAllowance
	}
	return DefaultSkewAllowance
}

func (s *Service) sleep(ctx context.Context, d time.Duration) {
	if s.Sleep != nil {
		s.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (s *Service) connector(ctx context.Context) detectverify.Connector {
	if s.ConnectorFactory == nil {
		return nil
	}
	c, err := s.ConnectorFactory(ctx)
	if err != nil || c == nil {
		return nil
	}
	return c
}

func principalOf(s *Service, rec dbsim.TargetRecord, spec dbsim.DBProbeSpec) string {
	if s.Principal != nil {
		return s.Principal(rec, spec)
	}
	return strings.TrimPrefix(spec.CredentialRef, "dbcred:")
}

// evaluateStep grades one step, re-asking the SIEM (never re-running the probe)
// until the alert is present or DetectionWait is over.
func (s *Service) evaluateStep(ctx context.Context, conn detectverify.Connector, in dbrun.StepInput) (dbrun.Evaluation, error) {
	start := s.now()
	poll := s.DetectionPoll
	if poll <= 0 {
		poll = DefaultDetectionPoll
	}
	for {
		ev, err := dbrun.Evaluate(ctx, conn, in)
		if err != nil || conn == nil || s.DetectionWait <= 0 || !in.Scenario.ExpectDetection && in.Spec.ProbeID != dbsim.ProbeReadClassifiedFixture {
			return ev, err
		}
		done := ev.Record.Telemetry == dlpreport.TelemetryPresent
		if in.Spec.ProbeID == dbsim.ProbeReadClassifiedFixture {
			done = done && ev.Record.Classification == dlpreport.ClassificationCorrect
		}
		if done || ev.Correlation == nil || s.now().Sub(start) >= s.DetectionWait || ctx.Err() != nil {
			return ev, err
		}
		s.sleep(ctx, poll)
	}
}

func (s *Service) ingestRun(ctx context.Context, job dbsim.RunJob, sub Submission) error {
	if s.Sink == nil || s.Scenarios == nil {
		return errors.New("dbsim: ingest: result sink or scenario source unavailable")
	}
	matched := matchResults(job.Plan, sub.Results)
	conn := s.connector(ctx)

	// The target supplies where the alerts are looked for.
	var rec dbsim.TargetRecord
	if s.Targets != nil {
		if r, err := s.Targets.Get(ctx, job.TargetID); err == nil {
			rec = r
		}
	}
	dbHost := rec.DBServerHost
	if dbHost == "" {
		dbHost = rec.Host
	}
	dbIP := ""
	if net.ParseIP(dbHost) != nil {
		dbIP = dbHost
	}
	agentIP := ""
	if s.AgentIP != nil {
		agentIP = s.AgentIP(ctx, job.AgentID)
	}

	seen := map[string]bool{}
	graded, duplicates := 0, 0
	var missing []string
	for _, scID := range job.ScenarioIDs {
		if seen[scID] {
			continue
		}
		seen[scID] = true
		row, reason := s.gradeScenario(ctx, conn, job, rec, scID, matched, dbHost, dbIP, agentIP)
		if reason != "" {
			missing = append(missing, scID+": "+reason)
			continue
		}
		dup, err := s.Sink.Save(ctx, row)
		if err != nil {
			// A storage failure leaves the job active: a replay or the deadline
			// reaper settles it; nothing is claimed finished.
			return redactf("dbsim: ingest: save %s: %v", trunc(scID, 80), err)
		}
		graded++
		if dup {
			duplicates++
		}
	}

	expected := len(seen)
	detail := map[string]any{"scenariosExpected": expected, "scenariosGraded": graded, "duplicates": duplicates, "partialReported": sub.Partial}
	switch {
	case graded == 0:
		return s.finish(ctx, job, dbsim.JobFailed, "no scenario could be graded: "+strings.Join(missing, "; "), "error", detail)
	case graded < expected || sub.Partial:
		why := "the agent reported a partial run"
		if len(missing) > 0 {
			why = fmt.Sprintf("%d of %d scenarios graded: %s", graded, expected, strings.Join(missing, "; "))
		}
		return s.finish(ctx, job, dbsim.JobPartial, why, "ok", detail)
	}
	return s.finish(ctx, job, dbsim.JobCompleted, "", "ok", detail)
}

// gradeScenario grades every plan step of one scenario and returns the row, or a
// reason string when the scenario cannot be graded (a step has no result, or the
// step could not be evaluated). The row's Result is the worst verdict of its
// steps (ERROR, then FAIL, then SKIPPED, then PASS); its report is that step's
// report (the first one with the worst verdict).
func (s *Service) gradeScenario(ctx context.Context, conn detectverify.Connector, job dbsim.RunJob, rec dbsim.TargetRecord, scID string, matched []*dbrun.AgentExec, dbHost, dbIP, agentIP string) (RunRecord, string) {
	sc, ok := s.Scenarios.Get(scID)
	if !ok || sc == nil {
		return RunRecord{}, "scenario is no longer loaded"
	}
	var (
		best    *dbrun.Evaluation
		bestSpc dbsim.DBProbeSpec
		steps   int
	)
	for i, p := range job.Plan {
		if p.ScenarioID != scID {
			continue
		}
		steps++
		if matched[i] == nil {
			return RunRecord{}, fmt.Sprintf("no result for step %d", p.Index+1)
		}
		meta, err := dbbuild.MetaFor(sc, p.Spec)
		if err != nil {
			return RunRecord{}, "no grading expectations for step " + fmt.Sprint(p.Index+1)
		}
		in := dbrun.StepInput{
			Scenario: meta, Spec: p.Spec, Exec: *matched[i], Principal: principalOf(s, rec, p.Spec),
			DBHost: dbHost, DBIP: dbIP, AgentIP: agentIP, Window: s.window(), SkewAllowance: s.skew(),
		}
		if job.Mode == dbsim.ModeLab && p.Spec.ProbeID == dbsim.ProbeReadClassifiedFixture {
			in.ClassificationRuleName = dbsim.LabClassificationRuleName
		}
		ev, err := s.evaluateStep(ctx, conn, in)
		if err != nil {
			return RunRecord{}, "step " + fmt.Sprint(p.Index+1) + " could not be evaluated: " + dbsim.Redact(err.Error())
		}
		if best == nil || rank(ev.Result) > rank(best.Result) {
			e := ev
			best, bestSpc = &e, p.Spec
		}
	}
	if best == nil || steps == 0 {
		return RunRecord{}, "no steps in the plan"
	}
	body, err := json.Marshal(best.Report)
	if err != nil {
		return RunRecord{}, "report could not be encoded"
	}
	return RunRecord{
		ScenarioID: scID, ScenarioVersion: best.Report.Scenario.Version, TargetID: job.TargetID, Engine: bestSpc.Engine,
		RunID: job.ID, Result: string(best.Result), Report: body,
	}, ""
}
