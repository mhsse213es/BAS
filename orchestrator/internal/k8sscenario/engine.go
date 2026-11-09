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
	"sync"
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
	// StateDiscardedNotRevoked: a credential was minted, verified and discarded locally. It stays valid until
	// it expires because the TokenRequest API cannot revoke it. Never reported as CLEANED.
	StateDiscardedNotRevoked State = "DISCARDED_NOT_REVOKED"
	// StateCancelled is defined in lifecycle.go.
)

// Audit event types written by the engine.
const (
	EventRequested = "k8s.scenario.requested"
	EventRefused   = "k8s.scenario.refused"
	EventOutcome   = "k8s.scenario.outcome"
	EventSnapshot  = "k8s.scenario.snapshot"
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
	// ClusterID, AuthorizationID and CustomerRef are the execution context persisted with the run. They are recorded
	// in every audit event, so the customer and cluster identifiers always appear in the trail.
	ClusterID       string
	AuthorizationID string
	CustomerRef     string
}

// Result reports what happened. Withheld means the outcome could not be recorded, so it must not be shown.
type Result struct {
	State    State
	Plan     []string
	Verified bool
	Error    string
	Withheld bool
	// Observation is the read result of an action that has one (see ObservationSucceeded and friends). It is
	// recorded apart from State: a denied read is a finding, not a failed run.
	Observation string
}

// Client is the cluster surface the engine needs. The real implementation is a separate, reviewed write client.
type Client interface {
	NamespaceLabels(ctx context.Context, ns string) (map[string]string, bool, error)
	CurrentIdentity(ctx context.Context) (string, error)
	Get(ctx context.Context, ref ObjectRef) (Object, bool, error)
	Create(ctx context.Context, obj Object) error
	SetData(ctx context.Context, ref ObjectRef, data map[string]string) error
	Delete(ctx context.Context, ref ObjectRef) error
	// IssueToken mints a short-lived token for one ServiceAccount. The caller clears the bytes when done.
	IssueToken(ctx context.Context, namespace, serviceAccount string, ttlSeconds int64) (IssuedToken, error)
	// IdentityWithToken reports the username a token authenticates as.
	IdentityWithToken(ctx context.Context, token []byte) (string, error)
	// ReadSecretAs reads a secret authenticated as the given token. allowed is false only for a refusal (403); any
	// other failure is an error. The value goes to the caller only and is never logged or audited.
	ReadSecretAs(ctx context.Context, token []byte, namespace, name string) (value string, allowed bool, err error)
	// SyntheticSecretLabels reads only the labels of the synthetic secret, never its data.
	SyntheticSecretLabels(ctx context.Context, namespace, name string) (map[string]string, bool, error)
	// GetBinding reads a RoleBinding's roleRef name and subjects. Subjects are "Kind/namespace/name".
	GetBinding(ctx context.Context, namespace, name string) (BindingState, bool, error)
	// SetBindingSubjects replaces a RoleBinding's subjects. Only the synthetic binding may be changed.
	SetBindingSubjects(ctx context.Context, namespace, name string, subjects []string) error
	// SetSecretValue replaces the value of one synthetic secret. Only the synthetic secret may be changed.
	SetSecretValue(ctx context.Context, namespace, name, value string) error
}

// BindingState is what the engine reads from a RoleBinding.
type BindingState struct {
	RoleName string
	Subjects []string
}

// IssuedToken is a minted credential. Token is never logged, audited, returned or placed in an error.
type IssuedToken struct {
	Token   []byte
	Expires time.Time
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
	// ControlledGate is checked before a Controlled run starts and again immediately before its first write. It
	// denies unless the global switch is on and the customer authorization still matches the run. Nil fails closed.
	ControlledGate func(ctx context.Context, req RunRequest) error
	// MaxRunDuration bounds a live run. Zero means DefaultMaxRun.
	MaxRunDuration time.Duration
}

// Engine runs requests against a Config. It has no UI dependency.
type Engine struct {
	cfg    Config
	mu     sync.Mutex
	active map[string]activeRun
}

// NewEngine returns an engine for the configuration.
func NewEngine(cfg Config) *Engine {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{cfg: cfg, active: map[string]activeRun{}}
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

	// A live run is stopped by Cancel, CancelControlled or the time limit. The gate for Controlled work is checked
	// here, before the cluster is read, and again before the first write.
	ctx, done := e.track(ctx, req)
	defer done()
	if ActionProfile(req.ActionID) == ProfileControlled {
		if err := e.gate(ctx, req); err != nil {
			return e.refuse(ctx, req, "controlled gate: "+err.Error())
		}
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

// execute runs snapshot, gate, apply, verify, then rollback and verify the restore. A stop (cancel, time limit or the
// kill switch) ends further writes. Rollback runs on a context the stop cannot cancel, with its own bound. The run is
// reported CANCELLED only when the restore is verified; a failed restore is CLEANUP_FAILED.
func (e *Engine) execute(ctx context.Context, req RunRequest, a *Action, plan []string) Result {
	snap, err := a.snapshot(ctx, e.cfg.Client, req)
	if err != nil {
		return e.finish(context.WithoutCancel(ctx), req, plan, StateFailed, false, "snapshot: "+err.Error(), "", "not attempted", "")
	}
	observed := func() string {
		if a.observation == nil {
			return ""
		}
		return a.observation(snap)
	}

	// A Controlled action records its pre-run state durably before the first write. If that record cannot be written,
	// nothing is applied: a change without a recorded prior state could not be attributed or rolled back by hand.
	if ActionProfile(req.ActionID) == ProfileControlled {
		fields := runFields(req)
		fields["approvalId"] = req.ApprovalID
		if a.snapshotFields != nil {
			for k, v := range a.snapshotFields(snap) {
				fields[k] = v
			}
		}
		if err := e.cfg.Audit.Write(ctx, Event{Type: EventSnapshot, RunID: req.RunID, Fields: fields}); err != nil {
			return Result{State: StateRefused, Plan: plan, Error: "snapshot could not be recorded; nothing was applied"}
		}
	}

	// The last check before the first write: a stop already requested, or the gate, which rechecks the switch and the
	// authorization at this moment. If either fails, nothing is written.
	var applyErr error
	if cause := context.Cause(ctx); cause != nil {
		applyErr = cause
	} else if ActionProfile(req.ActionID) == ProfileControlled {
		applyErr = e.gate(ctx, req)
	}
	if applyErr == nil {
		applyErr = a.apply(ctx, e.cfg.Client, req, snap)
	}
	verified := false
	if applyErr == nil {
		verified = a.verify(ctx, e.cfg.Client, req, snap) == nil && !a.forceVerifyFail
	}

	// Rollback runs once anything may have been applied. It uses a context the stop cannot cancel.
	rbCtx, cancelRB := context.WithTimeout(context.WithoutCancel(ctx), rollbackBudget)
	defer cancelRB()
	rollbackErr := a.rollback(rbCtx, e.cfg.Client, req, snap)
	if rollbackErr == nil {
		rollbackErr = a.verifyRolledBack(rbCtx, e.cfg.Client, req, snap)
	}

	// Outcome and alert writes use a context the stop cannot cancel, so the record is kept even when the run was stopped.
	fctx := context.WithoutCancel(ctx)
	stop := context.Cause(ctx)
	stopText := ""
	if stop != nil {
		stopText = stop.Error()
	}
	if rollbackErr != nil {
		msg := "rollback not verified: " + rollbackErr.Error()
		if stop != nil {
			msg = "stopped: " + stop.Error() + "; " + msg
		}
		return e.finish(fctx, req, plan, StateCleanupFailed, verified, msg, observed(), "failed", stopText)
	}

	state := StateCleaned
	msg := ""
	if applyErr != nil {
		state = StateFailed
		msg = "apply: " + applyErr.Error()
	} else if !verified {
		msg = "verification failed; the change was rolled back and verified"
	}
	if stop != nil {
		state = StateCancelled
		msg = "stopped: " + stop.Error() + "; rollback verified"
	}
	// An unrevocable effect (a minted credential) is never reported as cleaned up, even when rollback verified.
	if a.unrevocable && applyErr == nil {
		state = StateDiscardedNotRevoked
		if a.summary != nil {
			msg = a.summary(snap)
		}
		if !verified {
			msg = "verification failed; " + msg
		}
		if stop != nil {
			msg = "stopped: " + stop.Error() + "; " + msg
		}
	}
	return e.finish(fctx, req, plan, state, verified, msg, observed(), "verified", stopText)
}

// finish records the outcome. A failed outcome write withholds the result. CLEANUP_FAILED always alerts.
// rollback is the verified restore result ("verified", "failed", "not attempted") and stop is why the run was stopped,
// empty when it was not. Both are separate audit fields, so the trail can be queried without parsing the message.
func (e *Engine) finish(ctx context.Context, req RunRequest, plan []string, state State, verified bool, msg, observation, rollback, stop string) Result {
	res := Result{State: state, Plan: plan, Verified: verified, Error: msg, Observation: observation}
	fields := runFields(req)
	fields["state"] = string(state)
	fields["verified"] = fmt.Sprint(verified)
	if msg != "" {
		fields["detail"] = msg
	}
	if observation != "" {
		fields["observation"] = observation
	}
	fields["rollback"] = rollback
	if stop != "" {
		fields["stop"] = stop
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
	case a.ClusterID == "" || a.ClusterID != req.ClusterID:
		return "approval is for a different cluster"
	case a.AuthorizationID != req.AuthorizationID:
		return "approval is for a different customer authorization"
	case a.CustomerRef != req.CustomerRef:
		return "approval is for a different customer"
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
		"requester":       req.Requester,
		"cluster":         req.Cluster.Name,
		"clusterId":       req.ClusterID,
		"authorizationId": req.AuthorizationID,
		"customerRef":     req.CustomerRef,
		"namespace":       req.Namespace,
		"action":          req.ActionID,
		"approval":        req.ApprovalID,
		"paramsHash":      HashParams(req.Params),
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
