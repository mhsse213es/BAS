// Package k8sscenario runs fixed, labelled, state-changing Kubernetes actions on allow-listed sandbox namespaces.
//
// Gates, in order (see docs/superpowers/specs/2026-10-23-k8s-state-changing-scenarios-design.md):
//  1. registry: the action must be one of the fixed registry entries, with valid parameters
//  2. cluster and namespace allow-lists, enforced here, not taken from the request
//  3. dry-run is the default; a live run must be requested explicitly
//  4. the namespace must carry the sandbox label on the cluster
//  5. the credential must be the scenario identity
//  6. an approval by a different, permitted operator, bound to this exact run, cluster, namespace, action and
//     parameters, unexpired and unused
//  7. audit "requested" is written before anything is applied; if it cannot be written, nothing runs
//
// After apply, the engine verifies the result, then always runs the registry rollback and verifies the restore.
// A run is reported as CLEANED only when restoration is verified. A failed rollback ends in CLEANUP_FAILED,
// keeps the audit evidence, and alerts the operator.
package k8sscenario

import (
	"context"
	"fmt"
	"time"
)

// SandboxLabel must be set to "true" on a namespace before any live write is allowed there.
const SandboxLabel = "bas.audspect.io/scenario-sandbox"

// FixtureLabel marks a ConfigMap that the configmap-patch action may modify.
const FixtureLabel = "bas.audspect.io/sandbox-fixture"

// RunLabel marks every object a run creates, so cleanup can find it.
const RunLabel = "bas.audspect.io/run"

// ScenarioIdentity is the only credential identity a live run may use.
const ScenarioIdentity = "system:serviceaccount:bas-scenario:bas-scenario-runner"

// States of a run. CLEANUP_FAILED is terminal and never reported as a clean run.
type State string

const (
	StateRefused       State = "REFUSED"
	StateDryRunPlanned State = "DRY_RUN_PLANNED"
	StateFailed        State = "FAILED"
	StateCleaned       State = "CLEANED"
	StateCleanupFailed State = "CLEANUP_FAILED"
)

// Audit event types written by the engine.
const (
	EventRequested = "k8s.scenario.requested"
	EventRefused   = "k8s.scenario.refused"
	EventOutcome   = "k8s.scenario.outcome"
)

// ObjectRef identifies a Kubernetes object.
type ObjectRef struct {
	Kind      string
	Namespace string
	Name      string
}

// Object is the subset of an object the engine reads and writes.
type Object struct {
	Ref    ObjectRef
	Labels map[string]string
	Data   map[string]string
	Spec   map[string]any
}

// ClusterRef names the cluster a run targets. The server URL is checked against the allow-list.
type ClusterRef struct {
	Name   string
	Server string
}

// RunRequest is one requested run.
type RunRequest struct {
	RunID      string
	Requester  string
	Cluster    ClusterRef
	Namespace  string
	ActionID   string
	Params     map[string]string
	Live       bool
	ApprovalID string
}

// Result reports what happened. Withheld means the outcome could not be recorded, so it must not be shown.
type Result struct {
	State    State
	Plan     []string
	Verified bool
	Error    string
	Withheld bool
}

// Client is the cluster surface the engine needs. The real implementation is a separate, reviewed write client.
type Client interface {
	NamespaceLabels(ctx context.Context, ns string) (map[string]string, bool, error)
	CurrentIdentity(ctx context.Context) (string, error)
	Get(ctx context.Context, ref ObjectRef) (Object, bool, error)
	Create(ctx context.Context, obj Object) error
	SetData(ctx context.Context, ref ObjectRef, data map[string]string) error
	Delete(ctx context.Context, ref ObjectRef) error
}

// Event is one audit record. It never carries credentials.
type Event struct {
	Type   string
	RunID  string
	Fields map[string]string
}

// Audit writes audit events. A write error means the event was not recorded.
type Audit interface {
	Write(ctx context.Context, e Event) error
}

// Alerter notifies an operator. Used when cleanup cannot be verified.
type Alerter interface {
	Alert(ctx context.Context, msg string)
}

// Config is the engine's fixed, server-side configuration.
type Config struct {
	AllowedClusters   map[string]string // cluster name -> API server URL
	AllowedNamespaces []string
	Client            Client
	Audit             Audit
	Alert             Alerter
	Approvals         ApprovalStore
	ApproverPermitted func(operatorID string) bool
	Now               func() time.Time
}

// Engine runs requests against a Config. It has no UI dependency.
type Engine struct {
	cfg Config
}

// NewEngine returns an engine for the configuration.
func NewEngine(cfg Config) *Engine {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{cfg: cfg}
}

// Run executes one request. It never writes unless every gate passes.
func (e *Engine) Run(ctx context.Context, req RunRequest) Result {
	action, ok := registry[req.ActionID]
	if !ok {
		return e.refuse(ctx, req, "unknown action")
	}
	if err := action.validate(req.Params); err != nil {
		return e.refuse(ctx, req, "invalid parameters: "+err.Error())
	}
	if server, ok := e.cfg.AllowedClusters[req.Cluster.Name]; !ok || server != req.Cluster.Server {
		return e.refuse(ctx, req, "cluster not on the allow-list")
	}
	if !contains(e.cfg.AllowedNamespaces, req.Namespace) {
		return e.refuse(ctx, req, "namespace not on the allow-list")
	}
	plan := action.plan(req.Namespace, req.Params)
	if !req.Live {
		return Result{State: StateDryRunPlanned, Plan: plan}
	}

	labels, exists, err := e.cfg.Client.NamespaceLabels(ctx, req.Namespace)
	if err != nil {
		return e.refuse(ctx, req, "cannot read namespace: "+err.Error())
	}
	if !exists || labels[SandboxLabel] != "true" {
		return e.refuse(ctx, req, "namespace is not labelled as a scenario sandbox")
	}
	identity, err := e.cfg.Client.CurrentIdentity(ctx)
	if err != nil {
		return e.refuse(ctx, req, "cannot read credential identity: "+err.Error())
	}
	if identity != ScenarioIdentity {
		return e.refuse(ctx, req, "credential is not the scenario identity")
	}
	if reason := e.checkApproval(req); reason != "" {
		return e.refuse(ctx, req, "approval: "+reason)
	}

	// Gate 7: audit "requested" must be recorded before anything is applied.
	if err := e.cfg.Audit.Write(ctx, Event{Type: EventRequested, RunID: req.RunID, Fields: runFields(req)}); err != nil {
		return Result{State: StateRefused, Plan: plan, Error: "audit unavailable; nothing was applied"}
	}
	if err := e.cfg.Approvals.MarkUsed(req.ApprovalID); err != nil {
		return e.refuse(ctx, req, "approval could not be consumed: "+err.Error())
	}
	return e.execute(ctx, req, action, plan)
}

// execute runs snapshot, apply, verify, then rollback and verify the restore.
func (e *Engine) execute(ctx context.Context, req RunRequest, a *Action, plan []string) Result {
	snap, err := a.snapshot(ctx, e.cfg.Client, req)
	if err != nil {
		return e.finish(ctx, req, plan, StateFailed, false, "snapshot: "+err.Error())
	}

	applyErr := a.apply(ctx, e.cfg.Client, req, snap)
	verified := false
	if applyErr == nil {
		verified = a.verify(ctx, e.cfg.Client, req, snap) == nil && !a.forceVerifyFail
	}

	// Rollback always runs once anything may have been applied, and its result is verified.
	rollbackErr := a.rollback(ctx, e.cfg.Client, req, snap)
	if rollbackErr == nil {
		rollbackErr = a.verifyRolledBack(ctx, e.cfg.Client, req, snap)
	}
	if rollbackErr != nil {
		msg := "rollback not verified: " + rollbackErr.Error()
		return e.finish(ctx, req, plan, StateCleanupFailed, verified, msg)
	}

	state := StateCleaned
	msg := ""
	if applyErr != nil {
		state = StateFailed
		msg = "apply: " + applyErr.Error()
	} else if !verified {
		msg = "verification failed; the change was rolled back and verified"
	}
	return e.finish(ctx, req, plan, state, verified, msg)
}

// finish records the outcome. A failed outcome write withholds the result. CLEANUP_FAILED always alerts.
func (e *Engine) finish(ctx context.Context, req RunRequest, plan []string, state State, verified bool, msg string) Result {
	res := Result{State: state, Plan: plan, Verified: verified, Error: msg}
	fields := runFields(req)
	fields["state"] = string(state)
	fields["verified"] = fmt.Sprint(verified)
	if msg != "" {
		fields["detail"] = msg
	}
	if err := e.cfg.Audit.Write(ctx, Event{Type: EventOutcome, RunID: req.RunID, Fields: fields}); err != nil {
		res.Withheld = true
		res.Error = "outcome could not be recorded; result withheld"
		if e.cfg.Alert != nil {
			e.cfg.Alert.Alert(ctx, fmt.Sprintf("run %s: outcome audit failed; manual review required", req.RunID))
		}
	}
	if state == StateCleanupFailed && e.cfg.Alert != nil {
		e.cfg.Alert.Alert(ctx, fmt.Sprintf("run %s: CLEANUP_FAILED in %s/%s; objects labelled %s=%s may remain", req.RunID, req.Cluster.Name, req.Namespace, RunLabel, req.RunID))
	}
	return res
}

// refuse returns a refusal. It writes a best-effort audit record and never touches the cluster.
func (e *Engine) refuse(ctx context.Context, req RunRequest, reason string) Result {
	if e.cfg.Audit != nil {
		fields := runFields(req)
		fields["reason"] = reason
		_ = e.cfg.Audit.Write(ctx, Event{Type: EventRefused, RunID: req.RunID, Fields: fields})
	}
	return Result{State: StateRefused, Error: reason}
}

// checkApproval returns "" when the approval is valid for exactly this request, otherwise the reason.
func (e *Engine) checkApproval(req RunRequest) string {
	if req.ApprovalID == "" {
		return "no approval supplied"
	}
	a, ok, err := e.cfg.Approvals.Get(req.ApprovalID)
	if err != nil {
		return "store unavailable"
	}
	if !ok {
		return "not found"
	}
	switch {
	case a.ApproverID == req.Requester:
		return "self-approval is not allowed"
	case e.cfg.ApproverPermitted == nil || !e.cfg.ApproverPermitted(a.ApproverID):
		return "approver lacks the approval permission"
	case a.RunID != req.RunID:
		return "approval is for a different run"
	case a.Cluster != req.Cluster.Name:
		return "approval is for a different cluster"
	case a.Namespace != req.Namespace:
		return "approval is for a different namespace"
	case a.ActionID != req.ActionID:
		return "approval is for a different action"
	case a.ParamsHash != HashParams(req.Params):
		return "approval does not match the parameters"
	case a.Used:
		return "approval was already used"
	case !e.cfg.Now().Before(a.ExpiresAt):
		return "approval has expired"
	}
	return ""
}

func runFields(req RunRequest) map[string]string {
	return map[string]string{
		"requester":  req.Requester,
		"cluster":    req.Cluster.Name,
		"namespace":  req.Namespace,
		"action":     req.ActionID,
		"approval":   req.ApprovalID,
		"paramsHash": HashParams(req.Params),
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
