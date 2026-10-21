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
	"math"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"encoding/json"
	"github.com/audspect/bas/internal/apibas/calibration"
	"github.com/audspect/bas/internal/apibas/contract"
	"github.com/audspect/bas/internal/apibas/fixture"
	"github.com/audspect/bas/internal/apibas/grade"
	"github.com/audspect/bas/internal/apibas/latency"
	"strconv"
)

// SecretResolver returns the secret behind a reference. Implementations must
// not log the value.
type SecretResolver interface {
	Resolve(ref string) (string, error)
}

// StateRecord is one object as seen by the ground-truth state adapter.
// It deliberately excludes protected values.
type StateRecord struct {
	ID       string
	OwnerID  string
	Status   string
	Tag      string
	Quantity string
	// BeneficiaryRef is the payout beneficiary reference. A change to it is a state change (BIZ-009).
	BeneficiaryRef string
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
	Reset   Resetter    // required for STATE_CHANGE_SANDBOX scenarios
	Events  EventSource // access events for detection scenarios
	// Faults reports the faults the lab was started with. Required only by scenarios
	// that name lab_faults in their preconditions.
	Faults FaultReader
	HTTP   *http.Client
	// DetectionWindow is how long the detection stage waits for the SIEM to deliver the run's events.
	// Zero means DefaultDetectionWindow. Events delivered after the window are not seen.
	DetectionWindow time.Duration
	// Machine is the operator's label for this hardware. Calibration records are bound to it.
	Machine string
}

// FaultReader reports the faults a lab was started with.
type FaultReader interface {
	ActiveFaults(ctx context.Context) ([]string, error)
}

// missingFaults returns the required faults that the lab does not have active. Without a
// fault reader, every required fault is reported missing.
func (r *Runner) missingFaults(ctx context.Context, required []string) ([]string, error) {
	if r.cfg.Faults == nil {
		return required, nil
	}
	active, err := r.cfg.Faults.ActiveFaults(ctx)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, f := range required {
		if !slices.Contains(active, f) {
			missing = append(missing, f)
		}
	}
	return missing, nil
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
	headers  http.Header
	raw      []byte
	// request is the path and body sent, used to skip forbidden values the attacker sent.
	request string
}

// Report is the complete output of one scenario execution.
type Report struct {
	// DetectionProvenance labels every detection result from the fixture.
	DetectionProvenance string `json:"detection_provenance,omitempty"`
	// DetectionResults holds the result of each additional rule, keyed by rule ID. The primary rule is in Outcome.
	DetectionResults map[string]string `json:"detection_results,omitempty"`
	// DetectionReason says why a detection result is inconclusive, when it is.
	DetectionReason string `json:"detection_reason,omitempty"`
	// TimingVerdict is the timing grade, reported even when a resource limit decides the outcome.
	TimingVerdict string `json:"timing_verdict,omitempty"`
	// Latency holds the per-round timing statistics for timing scenarios.
	Latency    []latency.Summary `json:"latency,omitempty"`
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
	tag := newRunTag()
	ctx = context.WithValue(ctx, runTagKey{}, tag)
	rep, err := r.run(ctx, s, tag)
	if err != nil {
		return rep, err
	}
	return r.detectionStage(ctx, s, tag, rep), nil
}

func (r *Runner) run(ctx context.Context, s contract.Scenario, tag string) (Report, error) {
	rep := Report{ScenarioID: s.ID, RunTag: tag}
	// Protocols without an adapter are reported, never counted as covered.
	if !contract.ProtocolSupported(s.Protocol) {
		rep.Outcome = grade.Unsupported(grade.ReasonUnsupportedProtocol)
		rep.Detail = "protocol " + s.Protocol + " has no adapter yet; reported UNSUPPORTED, no traffic sent"
		return rep, nil
	}

	// Preflight: every check below happens before any traffic is sent.
	if s.Preconditions.Fixture != r.cfg.Fixture.Name {
		return r.skip(rep, grade.ReasonPreconditionMissing, "scenario fixture "+s.Preconditions.Fixture+" is not loaded"), nil
	}
	obj, ok := r.cfg.Fixture.Object(s.Preconditions.Object)
	if !ok {
		return r.skip(rep, grade.ReasonPreconditionMissing, "object "+s.Preconditions.Object+" not in fixture"), nil
	}
	if len(s.Preconditions.LabFaults) > 0 {
		missing, err := r.missingFaults(ctx, s.Preconditions.LabFaults)
		if err != nil {
			return r.skip(rep, grade.ReasonPreconditionMissing, "lab faults could not be read: "+err.Error()), nil
		}
		if len(missing) > 0 {
			return r.skip(rep, grade.ReasonPreconditionMissing,
				"lab fault not active: "+strings.Join(missing, ",")+" (start the lab with -fault)"), nil
		}
	}
	baseline, attack := s.Steps[0], s.Steps[len(s.Steps)-1]
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
	if s.Latency != nil {
		return r.runLatency(ctx, rep, s, obj, ownerToken, attackToken), nil
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
	ev.MaxAccepted = s.MaxAcceptedAttempts
	ev.CleanIsEnforcement = s.CleanIsEnforced
	ev.BaselineStatus = s.BaselineStatus

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
		// Setup steps run in order. A denial stops the chain and that denial is
		// the attack result, because the control held there. A 2xx lets the chain
		// continue. The final step is the attack, sent Repeat times.
		for i := 1; i < len(s.Steps); i++ {
			step := s.Steps[i]
			if i == len(s.Steps)-1 {
				agg, transport := r.runAttack(ctx, &rep, step, s, attackToken, obj)
				if transport {
					ev.Transport = true
				} else {
					ev.Attack = agg
				}
				break
			}
			exch, transport := r.do(ctx, step, attackToken, obj, &obj)
			rep.Exchanges = append(rep.Exchanges, exch)
			if transport {
				ev.Transport = true
				break
			}
			if slices.Contains(s.DeniedStatuses, exch.Status) || exch.Status/100 != 2 {
				ev.Attack = grade.Exchange{
					Status:           exch.Status,
					LeakedProtected:  exch.Leaked,
					ForbiddenHeaders: forbiddenHeaderHits(exch, s.ForbiddenResponseHeaders),
				}
				break
			}
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

	// {lab_url} lets a body name the target itself, for the SSRF scenario.
	payload := strings.ReplaceAll(step.Body, "{lab_url}", r.cfg.BaseURL)
	payload = expandFiller(payload)
	ex.request = path + " " + payload
	var body io.Reader
	if payload != "" {
		body = bytes.NewReader([]byte(payload))
	}
	req, err := http.NewRequestWithContext(ctx, step.Method, r.cfg.BaseURL+path, body)
	if err != nil {
		return ex, true
	}
	if payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range step.Headers {
		req.Header.Set(k, v)
	}
	for _, h := range step.ExtraHeaders {
		req.Header.Add(h.Name, h.Value)
	}
	if tag, ok := ctx.Value(runTagKey{}).(string); ok && tag != "" {
		req.Header.Set("X-BAS-Run", tag)
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
	ex.headers = resp.Header.Clone()
	ex.raw = raw

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

// oversizedHits counts the bounds one attack response exceeds: the granted page size, the accepted bytes,
// the item count and the response depth. Each check is independent, so a response can exceed several.
func oversizedHits(s contract.Scenario, raw []byte) int {
	n := 0
	if s.MaxGrantedPageSize > 0 && reportedField(raw, "page_size") > s.MaxGrantedPageSize {
		n++
	}
	if s.MaxAcceptedBytes > 0 && reportedField(raw, "accepted_bytes") > s.MaxAcceptedBytes {
		n++
	}
	if s.MaxItemsReturned > 0 && reportedArrayLen(raw, "items") > s.MaxItemsReturned {
		n++
	}
	if s.MaxResponseDepth > 0 && jsonDepth(raw) > s.MaxResponseDepth {
		n++
	}
	return n
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

// attemptStep returns the step with each "{n}" in its header values and body replaced by the
// attempt number, so repeated attempts can carry a different value (a source IP, a new email).
func attemptStep(step contract.Step, n int) contract.Step {
	if len(step.Headers) == 0 && len(step.ExtraHeaders) == 0 && !strings.Contains(step.Body, "{n}") {
		return step
	}
	num := strconv.Itoa(n)
	out := step
	out.Body = strings.ReplaceAll(step.Body, "{n}", num)
	out.Headers = make(map[string]string, len(step.Headers))
	for k, v := range step.Headers {
		out.Headers[k] = strings.ReplaceAll(v, "{n}", num)
	}
	out.ExtraHeaders = make([]contract.HeaderPair, len(step.ExtraHeaders))
	for i, h := range step.ExtraHeaders {
		out.ExtraHeaders[i] = contract.HeaderPair{Name: h.Name, Value: strings.ReplaceAll(h.Value, "{n}", num)}
	}
	return out
}

// runAttack sends the final step Repeat times and folds the exchanges into one
// attack record. It counts accepted attempts and stops early on a server fault.
func (r *Runner) runAttack(ctx context.Context, rep *Report, step contract.Step, s contract.Scenario, token string, obj fixture.Object) (grade.Exchange, bool) {
	reps := max(step.Repeat, 1)
	if step.Parallel {
		return r.runAttackParallel(ctx, rep, step, s, token, obj, reps)
	}
	var agg grade.Exchange
	for k := 0; k < reps; k++ {
		exch, transport := r.do(ctx, attemptStep(step, k+1), token, obj, &obj)
		rep.Exchanges = append(rep.Exchanges, exch)
		if transport {
			return agg, true
		}
		hits, inspectable := forbiddenScan(exch.raw, exch.headers.Get("Content-Encoding"), s.ForbiddenValues, exch.request)
		agg.ForbiddenValues += hits
		if !inspectable {
			agg.Uninspectable++
		}
		if agg.Status < 500 {
			agg.Status = exch.Status
		}
		agg.LeakedProtected += exch.Leaked
		agg.ForbiddenHeaders += forbiddenHeaderHits(exch, s.ForbiddenResponseHeaders)
		agg.Oversized += oversizedHits(s, exch.raw)
		if exch.Status < 500 && !slices.Contains(s.DeniedStatuses, exch.Status) {
			agg.Accepted++
		}
		if exch.Status >= 500 {
			break
		}
	}
	return agg, false
}

// latencyBaselineBatch is how many baseline requests are sent back to back per
// trial. A single cheap request is below the timer's resolution on Windows, so the
// baseline sample is the mean of a batch.
const latencyBaselineBatch = 50

// runLatency runs a timing scenario. The calibration record is checked before any
// traffic is sent. Each round sends warm-up requests, then paired baseline and attack
// samples. Grading is latency.Assess, and the resource limit is applied by timingOutcome.
func (r *Runner) runLatency(ctx context.Context, rep Report, s contract.Scenario, obj fixture.Object, ownerToken, attackToken string) Report {
	if reason, detail := calibrationCheck(s, r.cfg.Machine); reason != "" {
		rep.TimingVerdict = "ERROR/" + reason
		return r.errorOut(rep, reason, detail)
	}
	baseline, attack := s.Steps[0], s.Steps[len(s.Steps)-1]
	pol := s.Latency
	var rounds []latency.Round
	total, faults, resource := 0, 0, 0
	for round := 0; round < pol.Rounds; round++ {
		for i := 0; i < pol.Warmup; i++ {
			if _, transport := r.do(ctx, attack, attackToken, obj, &obj); transport {
				return r.errorOut(rep, grade.ReasonTargetUnreachable, "warm-up request failed")
			}
		}
		var rd latency.Round
		for i := 0; i < pol.Trials; i++ {
			start := time.Now()
			for k := 0; k < latencyBaselineBatch; k++ {
				if _, transport := r.do(ctx, baseline, ownerToken, obj, &obj); transport {
					return r.errorOut(rep, grade.ReasonTargetUnreachable, "baseline request failed")
				}
			}
			rd.Baseline = append(rd.Baseline, time.Since(start)/latencyBaselineBatch)
			start = time.Now()
			aex, transport := r.do(ctx, attack, attackToken, obj, &obj)
			rd.Attack = append(rd.Attack, time.Since(start))
			if transport {
				return r.errorOut(rep, grade.ReasonTargetUnreachable, "attack request failed")
			}
			total++
			if aex.Status >= 500 {
				faults++
			}
			if s.MaxWorkUnits > 0 && reportedField(aex.raw, "work_units") > s.MaxWorkUnits {
				resource++
			}
		}
		rounds = append(rounds, rd)
	}
	if faults > 0 {
		return r.errorOut(rep, grade.ReasonTargetFault, "attack returned a server fault")
	}

	verdict := latency.Assess(rounds, timingPolicy(s))
	rep.Latency = verdict.Rounds
	rep.TimingVerdict = fmt.Sprintf("%s:%s/%s", verdict.Stage, verdict.Outcome.Result, verdict.Outcome.Reason)
	rep.Outcome = timingOutcome(verdict.Outcome, resource > 0)
	return rep
}

// timingPolicy builds the grading policy from the scenario's declared values.
func timingPolicy(s contract.Scenario) latency.Policy {
	return latency.Policy{
		CeilingMs:    float64(s.Latency.CeilingMs),
		MinRatio:     s.Latency.MinRatio,
		MaxCV:        s.Latency.MaxCV,
		MinSamples:   s.Latency.Trials,
		BaselineMs:   s.Calibration.BaselineMs,
		Tolerance:    s.Calibration.Tolerance,
		AttackMaxMs:  s.Calibration.AttackMaxMs,
		NoiseFloorMs: s.Calibration.NoiseFloorMs,
	}
}

// timingOutcome maps a graded timing verdict and the resource check to the scenario
// outcome. A security PASS is reachable only from a PASS verdict with no resource
// breach. A work-unit breach is a deterministic fact counted by the lab, so it is a
// FAIL whenever the timing verdict is not ERROR. An ERROR is never overridden.
func timingOutcome(v grade.Outcome, resourceBreach bool) grade.Outcome {
	if v.Result == grade.ERROR {
		return v
	}
	if resourceBreach {
		return grade.Outcome{Result: grade.FAIL, Exploitability: grade.Exploited, Control: grade.Failed, Detection: "not_evaluated", Confidence: grade.ConfidenceEvidenceBacked}
	}
	return v
}

// calibrationCheck decides whether this environment may produce a timing verdict. Any
// reason returned is an ERROR: an unqualified, unmatched or tampered environment yields no
// security verdict. The reason says which check refused it.
func calibrationCheck(s contract.Scenario, machine string) (string, string) {
	if s.Calibration == nil {
		return grade.ReasonCalibrationMissing, "a timing scenario declares no calibration"
	}
	rec, err := calibration.Get(s.ID, s.Calibration.Version)
	switch {
	case errors.Is(err, calibration.ErrMissing):
		return grade.ReasonCalibrationMissing, err.Error()
	case errors.Is(err, calibration.ErrIntegrity):
		return grade.ReasonCalibrationMismatch, err.Error()
	case err != nil:
		return grade.ReasonCalibrationMissing, err.Error()
	}
	if !rec.Qualified {
		return grade.ReasonCalibrationNotQualified, "record v" + strconv.Itoa(rec.Version) + " reasons: " + strings.Join(rec.QualificationReasons, ",")
	}
	declared := calibration.Thresholds{
		DeclaredBaselineMs: s.Calibration.BaselineMs,
		Tolerance:          s.Calibration.Tolerance,
		CeilingMs:          float64(s.Latency.CeilingMs),
		MinRatio:           s.Latency.MinRatio,
		MaxCV:              s.Latency.MaxCV,
		AttackMaxMs:        s.Calibration.AttackMaxMs,
		NoiseFloorMs:       s.Calibration.NoiseFloorMs,
		Alpha:              s.Calibration.Alpha,
		MinSeparationRatio: s.Calibration.MinSeparationRatio,
		MinPooledSamples:   s.Calibration.MinPooledSamples,
		Warmup:             s.Latency.Warmup,
		Trials:             s.Latency.Trials,
		Rounds:             s.Latency.Rounds,
	}
	if rec.Thresholds != declared {
		return grade.ReasonCalibrationMismatch, fmt.Sprintf("declared values differ from calibration version %d", rec.Version)
	}
	if rec.Workload != workloadFor(s) {
		return grade.ReasonRequalificationRequired, "workload differs from calibration version " + strconv.Itoa(rec.Version)
	}
	if !rec.Profile.Matches(calibration.CurrentProfile(machine)) {
		return grade.ReasonRequalificationRequired, "environment fingerprint differs from calibration version " + strconv.Itoa(rec.Version)
	}
	return "", ""
}

// workloadFor describes the measured workload. Calibration and the runtime gate both use
// it, so a change to the workload requalifies the environment.
func workloadFor(s contract.Scenario) string {
	return fmt.Sprintf("%s: %d rounds, %d interleaved trials per round, baseline = %d-request batch, attack = one request per build, %d warm-up requests per build per round",
		s.ID, s.Latency.Rounds, s.Latency.Trials, latencyBaselineBatch, s.Latency.Warmup)
}

// timingInputs resolves what a timing scenario needs from this runner's fixture and
// secrets: the object, the owner's token and the attacker's token.
func (r *Runner) timingInputs(s contract.Scenario) (fixture.Object, string, string, error) {
	if s.Preconditions.Fixture != r.cfg.Fixture.Name {
		return fixture.Object{}, "", "", fmt.Errorf("scenario fixture %s is not loaded", s.Preconditions.Fixture)
	}
	obj, ok := r.cfg.Fixture.Object(s.Preconditions.Object)
	if !ok {
		return fixture.Object{}, "", "", fmt.Errorf("object %s not in fixture", s.Preconditions.Object)
	}
	baseline, attack := s.Steps[0], s.Steps[len(s.Steps)-1]
	owner, ok := r.cfg.Fixture.Identity(baseline.Identity)
	if !ok || owner.CustomerID != obj.OwnerID {
		return fixture.Object{}, "", "", errors.New("baseline identity is not the object owner")
	}
	ownerToken, err := r.cfg.Secrets.Resolve(owner.TokenRef)
	if err != nil {
		return fixture.Object{}, "", "", errors.New("owner credential unavailable")
	}
	attacker := fixture.Identity{}
	if attackAuth(attack) != "none" {
		var known bool
		attacker, known = r.cfg.Fixture.Identity(attack.Identity)
		if !known {
			return fixture.Object{}, "", "", fmt.Errorf("attack identity %s not in fixture", attack.Identity)
		}
	}
	attackToken, err := r.attackCredential(attack, attacker)
	if err != nil {
		return fixture.Object{}, "", "", err
	}
	return obj, ownerToken, attackToken, nil
}

// Calibrate measures the vulnerable build (this runner) and the fixed build (fixed) on
// this machine. The two are interleaved within every trial, with the order alternating,
// so both see the same conditions. It returns the next calibration record with its
// qualification verdict. It writes nothing: the caller stores the record with
// calibration.Write, so a calibration is always an explicit, reviewable act.
func (r *Runner) Calibrate(ctx context.Context, s contract.Scenario, fixed *Runner, machine, dir string) (calibration.Record, error) {
	if s.Latency == nil || s.Calibration == nil {
		return calibration.Record{}, fmt.Errorf("%s is not a timing scenario with a calibration block", s.ID)
	}
	if fixed == nil {
		return calibration.Record{}, errors.New("calibration needs a runner for the fixed build")
	}
	baseline, attack := s.Steps[0], s.Steps[len(s.Steps)-1]
	pol := s.Latency

	type target struct {
		rn     *Runner
		obj    fixture.Object
		owner  string
		attack string
		build  *calibration.Build
	}
	vObj, vOwner, vAttack, err := r.timingInputs(s)
	if err != nil {
		return calibration.Record{}, fmt.Errorf("vulnerable build: %w", err)
	}
	fObj, fOwner, fAttack, err := fixed.timingInputs(s)
	if err != nil {
		return calibration.Record{}, fmt.Errorf("fixed build: %w", err)
	}
	var vBuild, fBuild calibration.Build
	targets := []target{
		{r, vObj, vOwner, vAttack, &vBuild},
		{fixed, fObj, fOwner, fAttack, &fBuild},
	}

	measure := func(t target, rs *calibration.RoundSamples) error {
		start := time.Now()
		for k := 0; k < latencyBaselineBatch; k++ {
			if _, transport := t.rn.do(ctx, baseline, t.owner, t.obj, &t.obj); transport {
				return errors.New("baseline request failed during calibration")
			}
		}
		rs.BaselineMs = append(rs.BaselineMs, msOf(time.Since(start)/latencyBaselineBatch))
		start = time.Now()
		aex, transport := t.rn.do(ctx, attack, t.attack, t.obj, &t.obj)
		rs.AttackMs = append(rs.AttackMs, msOf(time.Since(start)))
		if transport {
			return errors.New("attack request failed during calibration")
		}
		if w := reportedField(aex.raw, "work_units"); w > t.build.WorkUnitsMax {
			t.build.WorkUnitsMax = w
		}
		return nil
	}

	for round := 0; round < pol.Rounds; round++ {
		for _, t := range targets {
			for i := 0; i < pol.Warmup; i++ {
				if _, transport := t.rn.do(ctx, attack, t.attack, t.obj, &t.obj); transport {
					return calibration.Record{}, errors.New("warm-up request failed during calibration")
				}
			}
		}
		rounds := make([]calibration.RoundSamples, len(targets))
		for trial := 0; trial < pol.Trials; trial++ {
			order := []int{0, 1}
			if trial%2 == 1 {
				order = []int{1, 0}
			}
			for _, idx := range order {
				if err := measure(targets[idx], &rounds[idx]); err != nil {
					return calibration.Record{}, err
				}
			}
		}
		vBuild.Rounds = append(vBuild.Rounds, rounds[0])
		fBuild.Rounds = append(fBuild.Rounds, rounds[1])
	}

	th := calibration.Thresholds{
		DeclaredBaselineMs: roundCentis(medianOf(append(baselinesOf(vBuild), baselinesOf(fBuild)...))),
		Tolerance:          s.Calibration.Tolerance,
		CeilingMs:          float64(pol.CeilingMs),
		MinRatio:           pol.MinRatio,
		MaxCV:              pol.MaxCV,
		AttackMaxMs:        s.Calibration.AttackMaxMs,
		NoiseFloorMs:       s.Calibration.NoiseFloorMs,
		Alpha:              s.Calibration.Alpha,
		MinSeparationRatio: s.Calibration.MinSeparationRatio,
		MinPooledSamples:   s.Calibration.MinPooledSamples,
		Warmup:             pol.Warmup,
		Trials:             pol.Trials,
		Rounds:             pol.Rounds,
	}
	q := calibration.Evaluate(th, vBuild.Rounds, fBuild.Rounds)
	version, err := calibration.NextVersion(dir, s.ID)
	if err != nil {
		return calibration.Record{}, err
	}
	return calibration.Record{
		ScenarioID:           s.ID,
		Version:              version,
		Supersedes:           version - 1,
		Profile:              calibration.CurrentProfile(machine),
		Workload:             workloadFor(s),
		Thresholds:           th,
		Vulnerable:           vBuild,
		Fixed:                fBuild,
		Qualified:            q.Qualified,
		QualificationReasons: q.Reasons,
		Separation:           calibration.Separation{P: q.P, Ratio: q.Ratio, VulnMedianMs: q.VulnMedianMs, FixedMedianMs: q.FixedMedianMs},
	}, nil
}

func msOf(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func baselinesOf(b calibration.Build) []float64 {
	var out []float64
	for _, r := range b.Rounds {
		out = append(out, r.BaselineMs...)
	}
	return out
}

func medianOf(xs []float64) float64 {
	c := slices.Clone(xs)
	slices.Sort(c)
	n := len(c)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

func roundCentis(v float64) float64 {
	return math.Round(v*100) / 100
}

// forbiddenHeaderHits counts the response headers of an exchange that match a
// scenario's forbidden name and value.
func forbiddenHeaderHits(ex Exchange, rules []contract.HeaderRule) int {
	n := 0
	for _, rule := range rules {
		for _, v := range ex.headers.Values(rule.Name) {
			if headerMatches(v, rule) {
				n++
			}
		}
	}
	return n
}

// reportedField reads an integer field a response reports. Anything that is not a
// JSON object with an integer under key counts as zero.
func reportedField(raw []byte, key string) int {
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return 0
	}
	n, ok := fields[key].(float64)
	if !ok {
		return 0
	}
	return int(n)
}

// jsonDepth returns the deepest nesting of objects and arrays in a JSON document. It is 0 when the
// document is not JSON, so a non-JSON response is never counted as deep.
func jsonDepth(raw []byte) int {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return 0
	}
	return valueDepth(v)
}

func valueDepth(v any) int {
	best := 0
	switch t := v.(type) {
	case map[string]any:
		for _, x := range t {
			if d := valueDepth(x); d > best {
				best = d
			}
		}
		return 1 + best
	case []any:
		for _, x := range t {
			if d := valueDepth(x); d > best {
				best = d
			}
		}
		return 1 + best
	}
	return 0
}

// expandFiller replaces each filler placeholder with that many bytes.
func expandFiller(body string) string {
	return contract.FillerToken.ReplaceAllStringFunc(body, func(tok string) string {
		m := contract.FillerToken.FindStringSubmatch(tok)
		n, err := strconv.Atoi(m[1])
		if err != nil || n > contract.MaxFillerBytes {
			return tok
		}
		return strings.Repeat("A", n)
	})
}

// headerMatches reports whether one header value matches a rule, exactly or as a
// case-insensitive substring.
func headerMatches(v string, rule contract.HeaderRule) bool {
	if rule.Match == "contains" {
		return strings.Contains(strings.ToLower(v), strings.ToLower(rule.Value))
	}
	return v == rule.Value
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

// runAttackParallel sends the attack's repeats concurrently. The requests race on the server, so the server's
// check-then-act window decides how many are accepted. Exchanges are folded in send order, so the verdict does
// not depend on the order in which responses arrive.
func (r *Runner) runAttackParallel(ctx context.Context, rep *Report, step contract.Step, s contract.Scenario, token string, obj fixture.Object, reps int) (grade.Exchange, bool) {
	type result struct {
		exch      Exchange
		transport bool
	}
	results := make([]result, reps)
	var wg sync.WaitGroup
	for k := 0; k < reps; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			exch, transport := r.do(ctx, attemptStep(step, k+1), token, obj, &obj)
			results[k] = result{exch: exch, transport: transport}
		}(k)
	}
	wg.Wait()
	var agg grade.Exchange
	denied := 0
	for _, res := range results {
		rep.Exchanges = append(rep.Exchanges, res.exch)
		if res.transport {
			return agg, true
		}
		hits, inspectable := forbiddenScan(res.exch.raw, res.exch.headers.Get("Content-Encoding"), s.ForbiddenValues, res.exch.request)
		agg.ForbiddenValues += hits
		if !inspectable {
			agg.Uninspectable++
		}
		if agg.Status < 500 {
			agg.Status = res.exch.Status
		}
		if slices.Contains(s.DeniedStatuses, res.exch.Status) {
			denied = res.exch.Status
		}
		agg.LeakedProtected += res.exch.Leaked
		agg.ForbiddenHeaders += forbiddenHeaderHits(res.exch, s.ForbiddenResponseHeaders)
		agg.Oversized += oversizedHits(s, res.exch.raw)
		if res.exch.Status < 500 && !slices.Contains(s.DeniedStatuses, res.exch.Status) {
			agg.Accepted++
		}
	}
	// Which concurrent request the server accepts is not fixed, so the last status in send order is not
	// meaningful. A refusal is the control's answer to the race; report it rather than whichever accept came last.
	if denied != 0 {
		agg.Status = denied
	}
	return agg, false
}
