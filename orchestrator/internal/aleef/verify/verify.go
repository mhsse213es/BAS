// Package verify is the only code allowed to promote an ALEEF finding to
// 'verified' (it is the only caller of Store.MarkVerified; a repository test
// enforces that).
//
// A finding is verified only when the same test, run on N independent fresh
// environments, finds the flaw every time, and in every round the owner
// control (the legitimate actor doing the legitimate thing) and the negative
// control (the test's own oracle on a request a correct application must
// allow) both pass. Every run, test or control, gets its OWN fresh fixture
// and is cleaned up straight afterwards; fixtures are never reused.
//
// State machine (end states):
//
//	clean       round-1 test says No: no finding is created
//	verified    N/N reproductions and both controls pass in every round
//	rejected    a later reproduction is No, or a control fires / fails
//	unconfirmed controls unavailable, any inconclusive verdict, cleanup
//	            failure (orphans listed), halt, interruption or an
//	            execution/recording error
//	candidate   the transient state after round 1 says Yes
//
// Execution numbering (aleef_results.exec_no, per test id): the test's round
// i is execution i; the owner control of round i is N+i and the negative
// control of round i is 2N+i. Controls are separate test ids (<ID>-OC,
// <ID>-NC), so the numbers never collide; the scheme just keeps them
// distinct and ordered. Callers must have saved the test and its two controls
// (Store.SaveTest) before calling Verify.
//
// The package is on the generator side: it must not import the benchmark
// bank, its sealed data or the bench harness.
package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/aleef/exec"
	"github.com/audspect/bas/internal/aleef/generate"
	"github.com/audspect/bas/internal/aleef/model"
	"github.com/audspect/bas/internal/aleef/property"
	"github.com/audspect/bas/internal/aleef/store"
	"github.com/audspect/bas/internal/apibas/runner"
)

// End states.
const (
	StateClean       = "clean"
	StateCandidate   = "candidate"
	StateVerified    = "verified"
	StateRejected    = "rejected"
	StateUnconfirmed = "unconfirmed"
)

// Verdict is the verifier's decision for one test.
type Verdict struct {
	State string
	// Reproductions counts test runs whose verdict was Yes.
	Reproductions   int
	OwnerControl    bool
	NegativeControl bool
	EvidenceHash    string
	// Reason never contains tokens or response bodies.
	Reason  string
	Orphans []model.CreatedObject
}

// Env builds a FRESH fixture and a new executor on every call, and returns a
// cleanup func that compensates everything that fixture created. Cleanup
// returns the objects it could not compensate and an error.
type Env interface {
	Fresh(ctx context.Context) (*exec.Executor, func(context.Context) ([]model.CreatedObject, error), error)
}

// Recorder is the persistence the verifier needs; *store.Store satisfies it.
type Recorder interface {
	CreateFinding(ctx context.Context, runID string, t generate.Test, res exec.Result) (store.Finding, error)
	SetFindingState(ctx context.Context, id, state, reason, actor string) error
	MarkVerified(ctx context.Context, id, evidenceHash, actor string) error
	SaveResult(ctx context.Context, runID string, t generate.Test, execNo int, res exec.Result) error
}

// Options configures a Verifier.
type Options struct {
	// Reproductions is N, the number of rounds. Default 3.
	Reproductions int
	// Actor is recorded in finding history. Default "aleef-verifier".
	Actor string
	// Halt is checked before every run; a non-nil error stops verification.
	Halt  func() error
	RunID string
}

// Verifier promotes findings.
type Verifier struct {
	env Env
	rec Recorder
	opt Options
}

// New returns a verifier.
func New(env Env, rec Recorder, opt Options) *Verifier {
	if opt.Reproductions <= 0 {
		opt.Reproductions = 3
	}
	if opt.Actor == "" {
		opt.Actor = "aleef-verifier"
	}
	return &Verifier{env: env, rec: rec, opt: opt}
}

type role string

const (
	roleTest     role = "test"
	roleOwner    role = "owner"
	roleNegative role = "negative"
)

// runOut is the outcome of one fresh-environment run.
type runOut struct {
	res     exec.Result
	haveRes bool
	// stop is non-nil when verification must end here, with the end state.
	stop *Verdict
	// cleanupFailed is true when cleanup errored or left orphans.
	cleanupFailed bool
	orphans       []model.CreatedObject
}

// Verify runs the full procedure for t.
func (v *Verifier) Verify(ctx context.Context, t generate.Test) (Verdict, error) {
	n := v.opt.Reproductions
	if t.ControlsBlocked || t.OwnerControl == nil || t.NegativeControl == nil {
		return Verdict{State: StateUnconfirmed, Reason: "controls unavailable"}, nil
	}
	var (
		out      Verdict
		fid      string
		evidence []execEvidence
	)
	// detached outlives ctx cancellation so end states are still recorded.
	detached := context.WithoutCancel(ctx)
	finish := func(state, reason string) (Verdict, error) {
		out.State, out.Reason = state, reason
		if fid != "" && state != StateVerified {
			if err := v.rec.SetFindingState(detached, fid, state, reason, v.opt.Actor); err != nil {
				return out, fmt.Errorf("verify: record state %s: %w", state, err)
			}
		}
		return out, nil
	}
	stopWith := func(s *Verdict) (Verdict, error) {
		out.Orphans = s.Orphans
		return finish(s.State, s.Reason)
	}

	for i := 1; i <= n; i++ {
		// ---- the test itself
		o := v.runOne(ctx, t, roleTest, i, i)
		if o.cleanupFailed && o.haveRes && i == 1 && fid == "" && o.res.Verdict.Finding == exec.FindingYes {
			// Keep a record of what was seen even though it can never be verified.
			f, err := v.rec.CreateFinding(detached, v.opt.RunID, t, o.res)
			if err != nil {
				return out, fmt.Errorf("verify: create finding: %w", err)
			}
			fid = f.ID
		}
		if o.stop != nil {
			return stopWith(o.stop)
		}
		evidence = append(evidence, newEvidence(roleTest, i, o.res))
		fv := o.res.Verdict.Finding
		switch {
		case i == 1 && fv == exec.FindingNo:
			return finish(StateClean, "first run found nothing")
		case fv == exec.FindingInconclusive:
			return finish(StateUnconfirmed, "test verdict inconclusive: "+o.res.Verdict.Reason)
		case fv == exec.FindingNo:
			return finish(StateRejected, fmt.Sprintf("not reproducible (%d/%d)", out.Reproductions, n))
		case fv != exec.FindingYes:
			return finish(StateUnconfirmed, "test verdict unrecognised")
		}
		out.Reproductions++
		if i == 1 {
			f, err := v.rec.CreateFinding(detached, v.opt.RunID, t, o.res)
			if err != nil {
				return out, fmt.Errorf("verify: create finding: %w", err)
			}
			fid = f.ID
		}

		// ---- controls, each on its own fresh environment
		for _, c := range []struct {
			r  role
			t  *generate.Test
			no int
		}{{roleOwner, t.OwnerControl, n + i}, {roleNegative, t.NegativeControl, 2*n + i}} {
			co := v.runOne(ctx, *c.t, c.r, i, c.no)
			if co.stop != nil {
				return stopWith(co.stop)
			}
			evidence = append(evidence, newEvidence(c.r, i, co.res))
			state, reason := judgeControl(c.r, *c.t, co.res)
			if state != "" {
				if c.r == roleOwner {
					out.OwnerControl = false
				} else {
					out.NegativeControl = false
				}
				return finish(state, reason)
			}
			if c.r == roleOwner {
				out.OwnerControl = true
			} else {
				out.NegativeControl = true
			}
		}
	}

	hash, err := evidenceHash(t, evidence)
	if err != nil {
		return finish(StateUnconfirmed, "evidence hash failed")
	}
	if err := v.rec.MarkVerified(detached, fid, hash, v.opt.Actor); err != nil {
		return out, fmt.Errorf("verify: mark verified: %w", err)
	}
	out.State, out.EvidenceHash, out.Reason = StateVerified, hash, "verified with evidence"
	return out, nil
}

// judgeControl returns an end state and reason when the control failed, or
// empty strings when it passed.
func judgeControl(r role, c generate.Test, res exec.Result) (string, string) {
	name := string(r) + " control"
	switch res.Verdict.Finding {
	case exec.FindingInconclusive:
		return StateUnconfirmed, name + " inconclusive"
	case exec.FindingYes:
		if r == roleOwner {
			return StateRejected, "owner control failed"
		}
		return StateRejected, "negative control fired: oracle not selective"
	case exec.FindingNo:
	default:
		return StateUnconfirmed, name + " verdict unrecognised"
	}
	if !property.GradedSuccess(finalResponses(c, res)) {
		if r == roleOwner {
			return StateRejected, "owner control failed: legitimate request was not a success"
		}
		return StateRejected, "negative control failed: permitted request was not a success"
	}
	return "", ""
}

// finalResponses are the responses to the test's last step, after the
// baseline exchange.
func finalResponses(c generate.Test, res exec.Result) []property.Response {
	if len(c.Scenario.Steps) == 0 || len(res.Report.Exchanges) < 2 {
		return nil
	}
	last := c.Scenario.Steps[len(c.Scenario.Steps)-1].ID
	var rs []property.Response
	for _, e := range res.Report.Exchanges[1:] {
		if e.StepID == last {
			rs = append(rs, property.Response{Status: e.Status, Body: []byte(e.Body)})
		}
	}
	return rs
}

// runOne performs one run on a fresh environment, cleans it up, records the
// result and classifies anything that must stop verification.
func (v *Verifier) runOne(ctx context.Context, tst generate.Test, r role, round, execNo int) runOut {
	stop := func(state, reason string) runOut {
		return runOut{stop: &Verdict{State: state, Reason: reason}}
	}
	if err := ctx.Err(); err != nil {
		return stop(StateUnconfirmed, "interrupted")
	}
	if v.opt.Halt != nil {
		if err := v.opt.Halt(); err != nil {
			return stop(StateUnconfirmed, "halted: "+err.Error())
		}
		if ctx.Err() != nil { // Halt itself may have been the trigger
			return stop(StateUnconfirmed, "interrupted")
		}
	}
	ex, cleanup, err := v.env.Fresh(ctx)
	if err != nil || ex == nil {
		if cleanup != nil {
			_, _ = v.cleanup(ctx, cleanup)
		}
		if ctx.Err() != nil {
			return stop(StateUnconfirmed, "interrupted")
		}
		return stop(StateUnconfirmed, "fresh environment unavailable")
	}
	res, rerr := ex.Run(ctx, tst)
	orphans, cerr := v.cleanup(ctx, cleanup)
	orphans = mergeOrphans(orphans, ex.Orphans())

	if rerr == nil && ctx.Err() != nil {
		// A run that finished under a cancelled context is not evidence.
		rerr = ctx.Err()
	}
	o := runOut{res: res, haveRes: rerr == nil, orphans: orphans}
	if rerr == nil {
		if serr := v.rec.SaveResult(context.WithoutCancel(ctx), v.opt.RunID, tst, execNo, res); serr != nil {
			return stop(StateUnconfirmed, "result could not be recorded")
		}
	}
	runnerCleanup := errors.Is(rerr, exec.ErrCleanupFailed) || res.Report.Outcome.Reason == runner.ReasonCleanupFailed
	if cerr != nil || len(orphans) > 0 || runnerCleanup {
		o.cleanupFailed = true
		o.stop = &Verdict{State: StateUnconfirmed, Reason: "cleanup failed", Orphans: orphans}
		return o
	}
	if rerr != nil {
		if ctx.Err() != nil {
			o.stop = &Verdict{State: StateUnconfirmed, Reason: "interrupted"}
		} else {
			o.stop = &Verdict{State: StateUnconfirmed, Reason: "execution failed (" + string(r) + ")"}
		}
	}
	return o
}

func (v *Verifier) cleanup(ctx context.Context, c func(context.Context) ([]model.CreatedObject, error)) ([]model.CreatedObject, error) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()
	return c(cctx)
}

func mergeOrphans(a, b []model.CreatedObject) []model.CreatedObject {
	out := append([]model.CreatedObject(nil), a...)
	for _, o := range b {
		dup := false
		for _, e := range out {
			if e.ID == o.ID && e.Operation == o.Operation {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, o)
		}
	}
	return out
}

// ---- evidence hash

type exchangeEvidence struct {
	StepID   string `json:"step_id"`
	Status   int    `json:"status"`
	BodySHA  string `json:"body_sha256"`
	BodySize int    `json:"body_size"`
}

type execEvidence struct {
	Role      string             `json:"role"`
	Round     int                `json:"round"`
	Exchanges []exchangeEvidence `json:"exchanges"`
	Finding   string             `json:"finding"`
	Reason    string             `json:"reason"`
	Oracle    string             `json:"oracle"`
}

type evidenceDoc struct {
	Property   string            `json:"property"`
	TestID     string            `json:"test_id"`
	Params     map[string]string `json:"params"`
	Scenario   json.RawMessage   `json:"scenario"`
	Executions []execEvidence    `json:"executions"`
}

func newEvidence(r role, round int, res exec.Result) execEvidence {
	e := execEvidence{
		Role: string(r), Round: round, Exchanges: []exchangeEvidence{},
		Finding: string(res.Verdict.Finding), Reason: res.Verdict.Reason, Oracle: string(res.Verdict.Oracle),
	}
	for _, x := range res.Report.Exchanges {
		sum := sha256.Sum256([]byte(x.Body))
		e.Exchanges = append(e.Exchanges, exchangeEvidence{
			StepID: x.StepID, Status: x.Status, BodySHA: hex.EncodeToString(sum[:]), BodySize: len(x.Body),
		})
	}
	return e
}

// evidenceHash is the SHA-256 of the canonical JSON of the evidence: fixed
// struct field order, map keys sorted by encoding/json, executions in the
// order they ran, bodies reduced to hashes, no timestamps, run tags or ids.
func evidenceHash(t generate.Test, ex []execEvidence) (string, error) {
	sc, err := json.Marshal(t.Scenario)
	if err != nil {
		return "", err
	}
	params := t.Params
	if params == nil {
		params = map[string]string{}
	}
	raw, err := json.Marshal(evidenceDoc{
		Property: t.Property, TestID: t.ID, Params: params, Scenario: sc, Executions: ex,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
