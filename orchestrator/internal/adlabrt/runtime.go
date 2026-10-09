// Package adlabrt is the controlled AD lab-runtime: it provisions a controlled
// environment, independently verifies its isolation, mints run-bound provenance,
// gates the action (adgate requires BOTH a verified-lab environment AND operator
// authorization), executes an already-reusable validation case, collects
// lab-local evidence, and guarantees teardown on every path. Infrastructure is
// reached only through Substrate; Phase A uses a fake, Phase B (deferred) adds a
// real disposable-VM adapter. It does not touch dispatchRun.
package adlabrt

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/adgate"
	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/scenario"
)

// teardownTimeout bounds the independent cleanup context so teardown cannot
// hang forever yet always runs regardless of the request context's state.
const teardownTimeout = 2 * time.Minute

// Substrate is the only seam to real infrastructure. Phase A: a fake. Phase B:
// a disposable-VM adapter (deferred).
type Substrate interface {
	Provision(ctx context.Context, spec LabSpec) (Target, error)
	VerifyIsolation(ctx context.Context, t Target) (IsolationResult, error)
	Execute(ctx context.Context, t Target, vc ValidationCase) (Observation, error)
	Teardown(ctx context.Context, t Target) error
}

// LabSpec names the lab to stand up.
type LabSpec struct{ Name string }

// Target is an opaque handle to a provisioned environment.
type Target struct{ ID string }

// IsolationResult is the outcome of the independent isolation check.
type IsolationResult struct {
	Verified bool
	Method   string
	Detail   string
}

// ValidationCase is the action to validate and its expected postcondition.
type ValidationCase struct {
	Name                string
	Primitive           adprimitive.Primitive
	ExpectPostcondition adprimitive.Capability
}

// Observation is the substrate's raw execution result; the runtime interprets it.
type Observation struct {
	PostconditionObserved bool
	Complete              bool // false => inconclusive
	Detail                string
}

// Evidence is the lab-local record. A telemetry adapter is a future boundary.
type Evidence struct {
	RunID                 string
	LabName               string
	TargetID              string
	CaseName              string
	PostconditionObserved bool
	Complete              bool
	Detail                string
	StartedAt             time.Time
	EndedAt               time.Time
}

// Status is the terminal outcome of a Validate run.
type Status string

const (
	StatusValidated            Status = "validated"
	StatusProvisionFailed      Status = "provision_failed"
	StatusIsolationUnverified  Status = "isolation_unverified"
	StatusGateDenied           Status = "gate_denied"
	StatusExecutionErrored     Status = "execution_errored"
	StatusEvidenceInconclusive Status = "evidence_inconclusive"
	StatusNotValidated         Status = "not_validated"
)

// Result is the outcome of one Validate run.
type Result struct {
	Status      Status
	Decision    adgate.Decision // zero if the gate was not reached
	Evidence    Evidence
	TeardownErr error
}

// Request is one validation request.
type Request struct {
	RunID         string
	Lab           LabSpec
	Case          ValidationCase
	Authorization adgate.Authorization
}

// Runtime orchestrates the lifecycle. Now is injectable for deterministic tests.
type Runtime struct {
	Sub Substrate
	Now func() time.Time
}

func (r *Runtime) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Validate runs the full controlled lifecycle for one authorized case and
// guarantees teardown on every path (success, error, panic). It mints lab
// provenance only after isolation is verified, and reaches Execute only when
// adgate.Decide allows (verified-lab env AND authorization).
func (r *Runtime) Validate(ctx context.Context, req Request) (res Result) {
	ev := Evidence{RunID: req.RunID, LabName: req.Lab.Name, CaseName: req.Case.Name, StartedAt: r.now()}

	target, err := r.Sub.Provision(ctx, req.Lab)
	if err != nil {
		ev.Detail = "provision: " + err.Error()
		ev.EndedAt = r.now()
		return Result{Status: StatusProvisionFailed, Evidence: ev}
	}
	ev.TargetID = target.ID

	// Teardown is guaranteed from here on -- success, error, or panic. The
	// deferred closure writes the final Evidence and any teardown error into the
	// named return value. Cleanup runs on a context DETACHED from the request's
	// cancellation (context.WithoutCancel) but bounded by teardownTimeout, so a
	// cancelled or timed-out run can never silently leak a provisioned lab.
	defer func() {
		if rec := recover(); rec != nil {
			res.Status = StatusExecutionErrored
			ev.Detail = fmt.Sprintf("panic: %v", rec)
		}
		tctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), teardownTimeout)
		defer cancel()
		if e := r.Sub.Teardown(tctx, target); e != nil {
			res.TeardownErr = e
		}
		ev.EndedAt = r.now()
		res.Evidence = ev
	}()

	iso, err := r.Sub.VerifyIsolation(ctx, target)
	if err != nil || !iso.Verified {
		// Unverifiable isolation is treated as NOT isolated: fail closed, no
		// provenance minted, no execution.
		if err != nil {
			ev.Detail = "isolation probe: " + err.Error()
		} else {
			ev.Detail = "isolation unverified: " + iso.Detail
		}
		res.Status = StatusIsolationUnverified
		return res
	}

	// Provenance is minted ONLY after verification, bound to this run + target.
	prov := adgate.VerifiedControlledLabProvenance(req.RunID, target.ID)
	decision := adgate.Decide(adgate.Request{
		Class: scenario.ExecutionClass(req.Case.Primitive.RiskClass),
		Env:   prov,
		Auth:  req.Authorization,
	})
	res.Decision = decision
	if !decision.Allowed {
		ev.Detail = "gate: " + string(decision.Reason)
		res.Status = StatusGateDenied
		return res
	}

	obs, err := r.Sub.Execute(ctx, target, req.Case)
	if err != nil {
		ev.Detail = "execute: " + err.Error()
		res.Status = StatusExecutionErrored
		return res
	}
	ev.PostconditionObserved = obs.PostconditionObserved
	ev.Complete = obs.Complete
	if obs.Detail != "" {
		ev.Detail = obs.Detail
	}

	switch {
	case !obs.Complete:
		res.Status = StatusEvidenceInconclusive
	case !obs.PostconditionObserved:
		res.Status = StatusNotValidated
	default:
		res.Status = StatusValidated
	}
	return res
}
