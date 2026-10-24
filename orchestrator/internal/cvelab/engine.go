package cvelab

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/cvecatalog"
	"github.com/audspect/bas/internal/cveval"
)

// Prober performs one controlled runtime check against an isolated-lab
// target. An implementation MUST NOT introduce an external callback (e.g. a
// JNDI/LDAP listener reachable outside the lab) or uncontrolled command
// execution -- it may only probe the one named Target, must respect ctx's
// deadline/cancellation, and must send no more than MaxRequests requests.
// No implementation of this interface ships in this package; Config.Prober
// being nil is the safe default, and makes every live-execution request
// fail regardless of what else a RunRequest asks for.
type Prober interface {
	Probe(ctx context.Context, req ProbeRequest) (ProbeResult, error)
}

// ProbeRequest is what the engine hands a Prober for one live assessment.
type ProbeRequest struct {
	CVEID       string
	Target      string
	MaxRequests int
}

// ProbeResult is what a Prober reports back. Detail must describe the real
// evidence observed (e.g. "received a JNDI callback from the target
// process" or "no callback observed before timeout") -- never a bare
// verdict with no explanation.
type ProbeResult struct {
	Verdict cveval.Verdict
	Detail  string
}

// Audit records one step of a CVE assessment. Recording is fail-closed:
// if Record returns an error, the engine aborts before doing any further
// work, matching internal/k8sscenario's own audit discipline.
type Audit interface {
	Record(ctx context.Context, event AuditEvent) error
}

// AuditEvent is one recorded step.
type AuditEvent struct {
	CVEID  string
	Action string // "requested" | "fixture_evaluated" | "live_refused" | "live_executed" | "outcome"
	Fields map[string]string
}

// RunRequest is one request to assess a single cataloged CVE. The zero
// value is the safe default: Live false means a fixture-only comparison,
// which performs no network I/O at all.
type RunRequest struct {
	CVEID string
	// ObservedConfig is the configuration indicator to compare against the
	// catalog entry's two fixtures. Required for a fixture result other
	// than SKIPPED.
	ObservedConfig string
	// Live requests a real runtime probe. False by default.
	Live bool
	// Authorized must be explicitly set true by the caller for a Live
	// request to proceed. It is never inferred, and is not itself
	// evidence of authorization -- the engine only checks that the caller
	// claims it; obtaining real authorization is the caller's own
	// integration concern, the same discipline as wafval.Expectation's
	// caller-supplied PolicyVerified field.
	Authorized bool
	// LabTarget is required for a Live request: it must be on
	// Config.Allowed and must not be a public address.
	LabTarget string
	// Timeout bounds how long a live probe may run. Required (> 0) for a
	// Live request.
	Timeout time.Duration
	// MaxRequests bounds how many requests a live probe may send. Required
	// (> 0) for a Live request.
	MaxRequests int
}

// Config configures an Engine. Audit is required: a nil Audit is a
// construction error, matching internal/k8sscenario's fail-closed
// discipline -- there is no such thing as an unaudited CVE assessment.
type Config struct {
	Allowed AllowedLabTargets
	Prober  Prober
	Audit   Audit
}

// Engine assesses one CVE per call to Assess.
type Engine struct {
	cfg Config
}

// NewEngine validates cfg before returning a usable Engine.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.Audit == nil {
		return nil, fmt.Errorf("cvelab: Config.Audit must not be nil")
	}
	return &Engine{cfg: cfg}, nil
}

func (e *Engine) record(ctx context.Context, cveID, action string, fields map[string]string) error {
	return e.cfg.Audit.Record(ctx, AuditEvent{CVEID: cveID, Action: action, Fields: fields})
}

// Assess runs one CVE assessment by looking req.CVEID up in the real
// catalog. It never returns a Result that fails cveval.ValidateResult.
func (e *Engine) Assess(ctx context.Context, req RunRequest) (cveval.Result, error) {
	entry, ok, err := cvecatalog.Lookup(req.CVEID)
	if err != nil {
		return cveval.Result{}, fmt.Errorf("cvelab: catalog lookup failed: %w", err)
	}
	if !ok {
		// Still audited: a lookup miss is itself a real, reportable event,
		// not a silent short-circuit before the audit trail starts.
		if req.CVEID == "" {
			return cveval.Result{}, fmt.Errorf("cvelab: RunRequest.CVEID must not be empty")
		}
		if auditErr := e.record(ctx, req.CVEID, "requested", map[string]string{"live": fmt.Sprint(req.Live)}); auditErr != nil {
			return cveval.Result{}, fmt.Errorf("cvelab: audit refused the request, aborting before any assessment: %w", auditErr)
		}
		return cveval.Result{
			CVEID:   req.CVEID,
			Verdict: cveval.VerdictError,
			Detail:  "no catalog entry exists for " + req.CVEID + "; refusing to report a verdict for an uncataloged CVE",
		}, nil
	}
	return e.AssessEntry(ctx, entry, req)
}

// AssessEntry assesses req against an already-resolved catalog entry,
// skipping Assess's own Lookup. It exists so a caller iterating a known
// set of entries (e.g. a batch run over the whole catalog) need not
// re-resolve each one by ID, and so tests can exercise every gate below
// against an entry built directly with cvecatalog.NewCVEEntry. It carries
// the same fail-closed "requested" audit guarantee as Assess -- there is
// no entry point into this engine that skips the audit trail.
func (e *Engine) AssessEntry(ctx context.Context, entry cvecatalog.CVEEntry, req RunRequest) (cveval.Result, error) {
	if req.CVEID == "" {
		return cveval.Result{}, fmt.Errorf("cvelab: RunRequest.CVEID must not be empty")
	}
	if err := e.record(ctx, req.CVEID, "requested", map[string]string{"live": fmt.Sprint(req.Live)}); err != nil {
		return cveval.Result{}, fmt.Errorf("cvelab: audit refused the request, aborting before any assessment: %w", err)
	}
	if !req.Live {
		return e.assessFixture(ctx, entry, req)
	}
	return e.assessLive(ctx, entry, req)
}

func (e *Engine) assessFixture(ctx context.Context, entry cvecatalog.CVEEntry, req RunRequest) (cveval.Result, error) {
	result := entry.EvaluateConfigIndicator(req.ObservedConfig, time.Now())
	if err := e.record(ctx, req.CVEID, "fixture_evaluated", map[string]string{"verdict": string(result.Verdict)}); err != nil {
		return cveval.Result{}, fmt.Errorf("cvelab: audit refused to record the fixture evaluation: %w", err)
	}
	return result, nil
}

// assessLive enforces every live-execution safeguard before touching
// cfg.Prober. Each refusal reason is recorded and returned as its own
// ERROR detail, never a generic failure -- the caller must be able to tell
// which specific control refused the request.
func (e *Engine) assessLive(ctx context.Context, entry cvecatalog.CVEEntry, req RunRequest) (cveval.Result, error) {
	refuse := func(reason string) (cveval.Result, error) {
		if err := e.record(ctx, req.CVEID, "live_refused", map[string]string{"reason": reason}); err != nil {
			return cveval.Result{}, fmt.Errorf("cvelab: audit refused to record the live-execution refusal: %w", err)
		}
		return cveval.Result{CVEID: req.CVEID, Verdict: cveval.VerdictError, Detail: "live execution refused: " + reason}, nil
	}

	if entry.ExecutionProfile != cveval.ProfileLabCapable {
		return refuse(entry.ID + " has no lab-capable runtime check; only a fixture comparison is supported")
	}
	if !req.Authorized {
		return refuse("the request did not claim explicit authorization for live execution")
	}
	if req.LabTarget == "" {
		return refuse("no LabTarget was supplied")
	}
	if !e.cfg.Allowed.IsAllowed(req.LabTarget) {
		return refuse("target " + req.LabTarget + " is not on the configured lab allow-list")
	}
	if pub, err := IsPublicAddress(req.LabTarget); err != nil {
		return refuse("target " + req.LabTarget + " could not be classified as private (" + err.Error() + "); refusing rather than assuming it is safe")
	} else if pub {
		return refuse("target " + req.LabTarget + " is a public address; live execution against public destinations is never permitted")
	}
	if req.Timeout <= 0 {
		return refuse("no positive Timeout was supplied")
	}
	if req.MaxRequests <= 0 {
		return refuse("no positive MaxRequests was supplied")
	}
	if e.cfg.Prober == nil {
		return refuse("no Prober is configured in this deployment; live execution is impossible")
	}

	if err := e.record(ctx, req.CVEID, "live_executed", map[string]string{"target": req.LabTarget}); err != nil {
		return cveval.Result{}, fmt.Errorf("cvelab: audit refused to record live execution starting: %w", err)
	}

	probeCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	probeResult, err := e.cfg.Prober.Probe(probeCtx, ProbeRequest{CVEID: req.CVEID, Target: req.LabTarget, MaxRequests: req.MaxRequests})

	var result cveval.Result
	switch {
	case err != nil && probeCtx.Err() != nil:
		result = cveval.Result{
			CVEID:   req.CVEID,
			Verdict: cveval.VerdictInconclusive,
			Detail:  "the lab probe did not complete within the configured timeout (" + req.Timeout.String() + ")",
		}
	case err != nil:
		result = cveval.Result{CVEID: req.CVEID, Verdict: cveval.VerdictError, Detail: "the lab probe returned an error: " + err.Error()}
	default:
		result = cveval.Result{
			CVEID:   req.CVEID,
			Verdict: probeResult.Verdict,
			Detail:  probeResult.Detail,
			Evidence: cveval.Evidence{
				Source:     cveval.SourceLabRuntime,
				Detail:     probeResult.Detail,
				ObservedAt: time.Now(),
				Target:     req.LabTarget,
			},
		}
	}

	// A Prober is external, pluggable code: a buggy implementation could
	// hand back a Verdict/Evidence combination ValidateResult would
	// reject. Never pass that through -- downgrade to ERROR instead of
	// returning a Result the engine's own contract promises never to.
	if vErr := cveval.ValidateResult(result); vErr != nil {
		result = cveval.Result{CVEID: req.CVEID, Verdict: cveval.VerdictError, Detail: "the lab probe returned an invalid result: " + vErr.Error()}
	}

	if auditErr := e.record(ctx, req.CVEID, "outcome", map[string]string{"verdict": string(result.Verdict)}); auditErr != nil {
		return cveval.Result{}, fmt.Errorf("cvelab: audit refused to record the outcome: %w", auditErr)
	}
	return result, nil
}
