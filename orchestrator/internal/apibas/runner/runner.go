// Package runner executes API BAS scenarios against a target. It is the
// dedicated test runner from blueprint D2: it sends requests, holds the
// short-lived identity credentials for one execution, captures redacted
// evidence and grades the result. It does not schedule, decide policy or
// persist results; those belong to the orchestrator.
//
// Credential handling:
//   - Tokens are resolved from a SecretResolver by reference at execution time.
//     They are held in memory for the run and are never written to the report,
//     logs or scenario files.
//   - Evidence stores status and a redacted body only. Request headers are
//     never recorded.
package runner

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
)

// SecretResolver returns the secret behind a reference. Implementations must
// not log the value.
type SecretResolver interface {
	Resolve(ref string) (string, error)
}

// StateRecord is one object as seen by the ground-truth state adapter.
// It deliberately excludes protected values.
type StateRecord struct {
	ID      string
	OwnerID string
	Status  string
	Tag     string
}

// StateReader is the ground-truth state adapter. A nil StateReader means the
// adapter is unavailable and every scenario that needs it is SKIPPED.
type StateReader interface {
	Snapshot(ctx context.Context) (map[string]StateRecord, error)
}

const maxEvidenceBody = 2048

// Config holds the runner's dependencies for one target.
type Config struct {
	BaseURL string
	Fixture fixture.Fixture
	Secrets SecretResolver
	State   StateReader
	HTTP    *http.Client
}

// Exchange is one request/response pair in evidence, after redaction.
type Exchange struct {
	StepID   string
	Identity string
	Method   string
	Path     string
	Status   int
	Body     string // truncated and with leaked protected values replaced
	Leaked   int
}

// Report is the complete output of one scenario execution.
type Report struct {
	ScenarioID string
	RunTag     string
	Outcome    grade.Outcome
	Exchanges  []Exchange
	// Skipped is the human-readable detail behind a SKIPPED or ERROR outcome.
	Skipped string
}

// Runner executes scenarios against one target.
type Runner struct {
	cfg Config
}

// New validates the configuration and returns a runner.
func New(cfg Config) (*Runner, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("runner: BaseURL is required")
	}
	if cfg.Secrets == nil {
		return nil, errors.New("runner: Secrets is required")
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 10 * time.Second}
	}
	return &Runner{cfg: cfg}, nil
}

// Run executes one scenario and returns its graded report. A returned error
// means the runner itself could not run; target and evidence problems are
// graded into the report instead.
func (r *Runner) Run(ctx context.Context, s contract.Scenario) (Report, error) {
	rep := Report{ScenarioID: s.ID, RunTag: newRunTag()}

	// Preflight: every check below happens before any traffic is sent.
	if s.Preconditions.Fixture != r.cfg.Fixture.Name {
		return r.skip(rep, grade.ReasonPreconditionMissing, "scenario fixture "+s.Preconditions.Fixture+" is not loaded"), nil
	}
	obj, ok := r.cfg.Fixture.Object(s.Preconditions.Object)
	if !ok {
		return r.skip(rep, grade.ReasonPreconditionMissing, "object "+s.Preconditions.Object+" not in fixture"), nil
	}
	baseline, attack := s.Steps[0], s.Steps[1]
	owner, ok := r.cfg.Fixture.Identity(baseline.Identity)
	if !ok || owner.CustomerID != obj.OwnerID {
		return r.skip(rep, grade.ReasonPreconditionMissing, "baseline identity is not the object owner"), nil
	}
	attacker, ok := r.cfg.Fixture.Identity(attack.Identity)
	if !ok {
		return r.skip(rep, grade.ReasonPreconditionMissing, "attack identity "+attack.Identity+" not in fixture"), nil
	}
	if attacker.CustomerID == obj.OwnerID {
		return r.skip(rep, grade.ReasonNotCrossIdentity, "attacker is the object owner; no cross-identity claim exists"), nil
	}
	if r.cfg.State == nil {
		return r.skip(rep, grade.ReasonAdapterUnavailable, "state adapter is not configured"), nil
	}
	ownerToken, err := r.cfg.Secrets.Resolve(owner.TokenRef)
	if err != nil {
		return r.skip(rep, grade.ReasonPreconditionMissing, "owner credential unavailable"), nil
	}
	attackerToken, err := r.cfg.Secrets.Resolve(attacker.TokenRef)
	if err != nil {
		return r.skip(rep, grade.ReasonPreconditionMissing, "attacker credential unavailable"), nil
	}

	// A failing state read is an infrastructure fault, not a skip: the adapter
	// was configured, so its failure must not look like a missing control.
	before, err := r.cfg.State.Snapshot(ctx)
	if err != nil {
		return r.errorOut(rep, stateErrorReason(err), "state snapshot failed before execution"), nil
	}

	// Execute: baseline (owner) then attack (attacker).
	var ev grade.Evidence
	// The baseline is also redacted: evidence never holds raw protected values,
	// even the owner's own. Its leak count is ignored for grading.
	baseExch, transport := r.do(ctx, baseline, ownerToken, obj, &obj)
	rep.Exchanges = append(rep.Exchanges, baseExch)
	if transport {
		ev.Transport = true
	} else {
		ev.Baseline = grade.Exchange{Status: baseExch.Status}
	}

	attackExch := Exchange{}
	if !ev.Transport {
		attackExch, transport = r.do(ctx, attack, attackerToken, obj, &obj)
		rep.Exchanges = append(rep.Exchanges, attackExch)
		if transport {
			ev.Transport = true
		} else {
			ev.Attack = grade.Exchange{Status: attackExch.Status, LeakedProtected: attackExch.Leaked}
		}
	}

	after, err := r.cfg.State.Snapshot(ctx)
	if err != nil {
		// Without the after-state, the attack's effect is unknown. Report the
		// fault rather than grading on partial ground truth.
		return r.errorOut(rep, stateErrorReason(err), "state snapshot failed after execution"), nil
	}
	ev.StateChanged = !sameState(before, after)

	rep.Outcome = grade.Assess(ev)
	return rep, nil
}

func (r *Runner) errorOut(rep Report, reason, detail string) Report {
	rep.Outcome = grade.Error(reason)
	rep.Skipped = detail
	return rep
}

// stateErrorReason maps a state-adapter failure to a machine-readable reason.
func stateErrorReason(err error) string {
	if errors.Is(err, ErrUnreachable) {
		return grade.ReasonTargetUnreachable
	}
	return grade.ReasonAdapterReadFailed
}

// do sends one step's request. When protect is non-nil the response body is
// scanned for that object's protected values, which are redacted from the
// evidence. The second return value is true on transport failure.
func (r *Runner) do(ctx context.Context, step contract.Step, token string, obj fixture.Object, protect *fixture.Object) (Exchange, bool) {
	path := strings.ReplaceAll(step.Path, "{object}", obj.ID)
	ex := Exchange{StepID: step.ID, Identity: step.Identity, Method: step.Method, Path: path}

	req, err := http.NewRequestWithContext(ctx, step.Method, r.cfg.BaseURL+path, nil)
	if err != nil {
		return ex, true
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := r.cfg.HTTP.Do(req)
	if err != nil {
		return ex, true
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return ex, true
	}
	ex.Status = resp.StatusCode

	body := string(raw)
	if protect != nil {
		for _, v := range protect.Protected {
			if v != "" && strings.Contains(body, v) {
				ex.Leaked++
				body = strings.ReplaceAll(body, v, "[REDACTED]")
			}
		}
	}
	if len(body) > maxEvidenceBody {
		body = body[:maxEvidenceBody] + "...[truncated]"
	}
	ex.Body = body
	return ex, false
}

func (r *Runner) skip(rep Report, reason, detail string) Report {
	rep.Outcome = grade.Skip(reason)
	rep.Skipped = detail
	return rep
}

// sameState reports whether two snapshots are identical. Any added, removed or
// changed record counts as a state change.
func sameState(a, b map[string]StateRecord) bool {
	if len(a) != len(b) {
		return false
	}
	for id, rec := range a {
		if other, ok := b[id]; !ok || other != rec {
			return false
		}
	}
	return true
}

func newRunTag() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("apibas-%d", time.Now().UnixNano())
	}
	return "apibas-" + hex.EncodeToString(b[:])
}
