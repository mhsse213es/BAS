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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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

// Resetter restores the target to its seed state. Scenarios that change state
// need it, both before the run (known starting point) and after (cleanup).
type Resetter interface {
	Reset(ctx context.Context) error
}

// RevocationChecker asks the lab whether a token is known and revoked. The
// revoked-token scenario uses it as a guard: if the lab does not report the
// credential as revoked, the lab is misconfigured and the result would be a
// false pass, so the run is an ERROR instead.
type RevocationChecker interface {
	TokenStatus(ctx context.Context, token string) (known, revoked bool, err error)
}

// Reason added in Phase 2: cleanup of a sandbox run did not succeed.
const ReasonCleanupFailed = "CLEANUP_FAILED"

// Reason added in Phase 3: the lab does not match the scenario's expectations.
const ReasonLabConfigMismatch = "LAB_CONFIG_MISMATCH"

const maxEvidenceBody = 2048

// Config holds the runner's dependencies for one target.
type Config struct {
	BaseURL string
	Fixture fixture.Fixture
	Secrets SecretResolver
	State   StateReader
	Reset   Resetter // required for STATE_CHANGE_SANDBOX scenarios
	HTTP    *http.Client
}

// Exchange is one request/response pair in evidence, after redaction.
type Exchange struct {
	StepID   string
	Identity string
	Auth     string
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
	// Detail is the human-readable reason behind a SKIPPED or ERROR outcome.
	Detail string
	// Reset records whether a sandbox scenario's cleanup reset succeeded.
	Reset string
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

	attacker, attackerKnown := fixture.Identity{}, false
	if attackAuth(attack) != "none" {
		attacker, attackerKnown = r.cfg.Fixture.Identity(attack.Identity)
		if !attackerKnown {
			return r.skip(rep, grade.ReasonPreconditionMissing, "attack identity "+attack.Identity+" not in fixture"), nil
		}
	}
	switch s.Claim {
	case "cross_identity":
		if !attackerKnown || attacker.CustomerID == obj.OwnerID {
			return r.skip(rep, grade.ReasonNotCrossIdentity, "attacker is the object owner; no cross-identity claim exists"), nil
		}
	case "property_level":
		if !attackerKnown || attacker.CustomerID != obj.OwnerID {
			return r.skip(rep, grade.ReasonPreconditionMissing, "property-level claim requires the attacker to own the object"), nil
		}
	}
	if r.cfg.State == nil {
		return r.skip(rep, grade.ReasonAdapterUnavailable, "state adapter is not configured"), nil
	}
	sandbox := s.SideEffectClass == "STATE_CHANGE_SANDBOX"
	if sandbox && r.cfg.Reset == nil {
		return r.skip(rep, grade.ReasonAdapterUnavailable, "sandbox scenario needs a reset adapter"), nil
	}

	ownerToken, err := r.cfg.Secrets.Resolve(owner.TokenRef)
	if err != nil {
		return r.skip(rep, grade.ReasonPreconditionMissing, "owner credential unavailable"), nil
	}
	attackToken, err := r.attackCredential(attack, attacker)
	if err != nil {
		return r.skip(rep, grade.ReasonPreconditionMissing, err.Error()), nil
	}
	if attackAuth(attack) == "revoked" {
		checker, ok := r.cfg.State.(RevocationChecker)
		if !ok {
			return r.skip(rep, grade.ReasonAdapterUnavailable, "revoked-token scenario needs the lab revocation check"), nil
		}
		known, revoked, err := checker.TokenStatus(ctx, attackToken)
		if err != nil {
			return r.errorOut(rep, stateErrorReason(err), "revocation check failed"), nil
		}
		if !known || !revoked {
			return r.errorOut(rep, grade.ReasonLabConfigMismatch,
				"lab does not report the attack credential as revoked; a pass here would be false"), nil
		}
	}

	if sandbox {
		if err := r.cfg.Reset.Reset(ctx); err != nil {
			return r.errorOut(rep, stateErrorReason(err), "reset before execution failed"), nil
		}
	}

	var ev grade.Evidence
	ev.Denied = s.DeniedStatuses
	ev.CleanIsEnforcement = s.CleanIsEnforced

	// Baseline: the owner's legitimate request. Redacted like everything else,
	// but its leak count is not used for grading.
	baseExch, transport := r.do(ctx, baseline, ownerToken, obj, &obj)
	rep.Exchanges = append(rep.Exchanges, baseExch)
	if transport {
		ev.Transport = true
	} else {
		ev.Baseline = grade.Exchange{Status: baseExch.Status}
	}

	// The state is read between baseline and attack, so a baseline write is
	// never blamed on the attacker.
	var mid map[string]StateRecord
	if !ev.Transport {
		mid, err = r.cfg.State.Snapshot(ctx)
		if err != nil {
			return r.finish(ctx, sandbox, r.errorOut(rep, stateErrorReason(err), "state snapshot failed after baseline")), nil
		}
		attackExch, transport := r.do(ctx, attack, attackToken, obj, &obj)
		rep.Exchanges = append(rep.Exchanges, attackExch)
		if transport {
			ev.Transport = true
		} else {
			ev.Attack = grade.Exchange{Status: attackExch.Status, LeakedProtected: attackExch.Leaked}
		}
	}

	after, err := r.cfg.State.Snapshot(ctx)
	if err != nil {
		return r.finish(ctx, sandbox, r.errorOut(rep, stateErrorReason(err), "state snapshot failed after execution")), nil
	}
	if mid != nil {
		ev.StateChanged = !sameState(mid, after)
	}
	rep.Outcome = grade.Assess(ev)
	return r.finish(ctx, sandbox, rep), nil
}

// finish runs sandbox cleanup and folds a cleanup failure into the outcome. A
// lab left dirty after a run is a failed test, so it is never reported as a
// clean PASS.
func (r *Runner) finish(ctx context.Context, sandbox bool, graded Report) Report {
	if !sandbox {
		return graded
	}
	if err := r.cfg.Reset.Reset(ctx); err != nil {
		graded.Reset = "failed"
		graded.Outcome = grade.Error(ReasonCleanupFailed)
		graded.Detail = "reset after execution failed; target state is unknown"
		return graded
	}
	graded.Reset = "ok"
	return graded
}

// attackCredential resolves the token for the attack step's declared auth mode.
func (r *Runner) attackCredential(attack contract.Step, attacker fixture.Identity) (string, error) {
	switch attackAuth(attack) {
	case "none":
		return "", nil
	case "alg_none":
		forged, ok := r.cfg.Fixture.Identity(attack.ForgeAs)
		if !ok {
			return "", errors.New("forge_as identity not in fixture")
		}
		return unsignedJWT(forged.CustomerID), nil
	case "revoked":
		if attacker.RevokedTokenRef == "" {
			return "", errors.New("identity has no revoked credential")
		}
		tok, err := r.cfg.Secrets.Resolve(attacker.RevokedTokenRef)
		if err != nil {
			return "", errors.New("revoked credential unavailable")
		}
		return tok, nil
	default:
		tok, err := r.cfg.Secrets.Resolve(attacker.TokenRef)
		if err != nil {
			return "", errors.New("attacker credential unavailable")
		}
		return tok, nil
	}
}

func attackAuth(st contract.Step) string {
	if st.Auth == "" {
		return "valid"
	}
	return st.Auth
}

// do sends one step's request. When protect is non-nil the response body is
// scanned for that object's protected values, which are redacted from the
// evidence. The second return value is true on transport failure.
func (r *Runner) do(ctx context.Context, step contract.Step, token string, obj fixture.Object, protect *fixture.Object) (Exchange, bool) {
	path := strings.ReplaceAll(step.Path, "{object}", obj.ID)
	ex := Exchange{StepID: step.ID, Identity: step.Identity, Auth: attackAuth(step), Method: step.Method, Path: path}

	var body io.Reader
	if step.Body != "" {
		body = bytes.NewReader([]byte(step.Body))
	}
	req, err := http.NewRequestWithContext(ctx, step.Method, r.cfg.BaseURL+path, body)
	if err != nil {
		return ex, true
	}
	if step.Body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range step.Headers {
		req.Header.Set(k, v)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
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

	text := string(raw)
	if protect != nil {
		for _, v := range protect.Protected {
			if v != "" && strings.Contains(text, v) {
				ex.Leaked++
				text = strings.ReplaceAll(text, v, "[REDACTED]")
			}
		}
	}
	if len(text) > maxEvidenceBody {
		text = text[:maxEvidenceBody] + "...[truncated]"
	}
	ex.Body = text
	return ex, false
}

func (r *Runner) skip(rep Report, reason, detail string) Report {
	rep.Outcome = grade.Skip(reason)
	rep.Detail = detail
	return rep
}

func (r *Runner) errorOut(rep Report, reason, detail string) Report {
	rep.Outcome = grade.Error(reason)
	rep.Detail = detail
	return rep
}

// stateErrorReason maps a state-adapter failure to a machine-readable reason.
func stateErrorReason(err error) string {
	if errors.Is(err, ErrUnreachable) {
		return grade.ReasonTargetUnreachable
	}
	return grade.ReasonAdapterReadFailed
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

// unsignedJWT builds a token with alg "none" and an empty signature. It is
// only ever sent to the lab, to test whether the lab verifies signatures.
func unsignedJWT(sub string) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(fmt.Sprintf(`{"sub":%q,"iat":0}`, sub)))
	return header + "." + payload + "."
}

func newRunTag() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("apibas-%d", time.Now().UnixNano())
	}
	return "apibas-" + hex.EncodeToString(b[:])
}
