package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"audspect/agent/dbprobe"
	_ "audspect/agent/dbprobe/mysql"    // registers the "mysql" adapter
	_ "audspect/agent/dbprobe/postgres" // registers the "postgresql" adapter
	"audspect/agent/protocol"
)

// Agent-local dbprobe policy (spec 8, R8). Read ONLY from the agent's own
// environment (service config / EnvironmentFile / service Environment), never
// from a server payload, and default OFF:
//
//	BAS_DBPROBE_CLIENT_ENABLED=1|true        permit client-mode (read-only) probes
//	BAS_DBPROBE_LAB_MUTATION_ALLOWED=1|true  permit non-read_only probes in lab mode
//
// Credential references resolve via BAS_DBCRED_<NAME> or the local protected
// store; see dbcred.go.
const (
	envDBProbeClientEnabled     = "BAS_DBPROBE_CLIENT_ENABLED"
	envDBProbeLabMutationAllows = "BAS_DBPROBE_LAB_MUTATION_ALLOWED"
)

func envFlagTrue(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return v == "1" || v == "true"
}

// dbprobePolicyFromEnv builds the agent-local dbprobe.Policy.
func dbprobePolicyFromEnv() dbprobe.Policy {
	return dbprobe.Policy{
		ClientEnabled:      envFlagTrue(envDBProbeClientEnabled),
		LabMutationAllowed: envFlagTrue(envDBProbeLabMutationAllows),
	}
}

// dbprobeNewAdapter is the adapter factory seam (tests substitute a fake; the
// real registry is populated by the blank imports above).
var dbprobeNewAdapter = dbprobe.New

// Error classes carried in protocol.DBProbeResult.ErrorClass for outcomes that
// are not a probe observation. The agent never scores; the orchestrator maps
// these (credential_unresolved / adapter_unsupported -> SKIPPED, the rest ->
// ERROR/vetoed).
const (
	dbErrGateRefused          = "gate_refused"
	dbErrCredentialUnresolved = "credential_unresolved"
	dbErrAdapterUnsupported   = "adapter_unsupported"
	dbErrConnect              = "connect_error"
	dbErrIdentity             = "identity_error"
	dbErrProbe                = "probe_error"
	dbErrCancelled            = "cancelled"
	dbErrTimeout              = "timeout"
)

// DBProbeOutcome is the result of executing one dbprobe step. GateRefusal is
// non-empty when the step was refused before any probe SQL ran; Audit is
// reserved for the audit-collection task and is empty here.
type DBProbeOutcome struct {
	Result      protocol.DBProbeResult
	GateRefusal string
	Audit       []dbprobe.AuditEvent
}

func refusal(class, reason string) DBProbeOutcome {
	return DBProbeOutcome{
		Result:      protocol.DBProbeResult{ErrorClass: class, Notes: []string{reason}, AgentTime: time.Now()},
		GateRefusal: reason,
	}
}

// scrub removes the secret and bounds the length of text derived from driver
// errors before it reaches a log, a result or an error value.
func scrub(msg, secret string) string {
	if secret != "" {
		msg = strings.ReplaceAll(msg, secret, "[redacted]")
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}

func classifyDBErr(ctx context.Context, err error, fallback string) string {
	switch {
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return dbErrCancelled
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded):
		return dbErrTimeout
	}
	return fallback
}

// dbprobeStepShapeRefusal checks the step-level shape of a dbprobe step that
// is independent of the spec's content: it must carry a spec, no shell
// baggage (payloads, cleanup script) and a Command that is exactly the probe
// id (non-executable text, so B5's local backstop sees nothing to execute).
// Returns "" for a well-formed dbprobe step and for every non-dbprobe step.
func dbprobeStepShapeRefusal(step ScenarioStep) string {
	if !strings.EqualFold(step.Executor, "dbprobe") {
		return ""
	}
	switch {
	case step.DBProbe == nil:
		return "dbprobe step has no probe spec"
	case len(step.Payloads) > 0:
		return "dbprobe step must not carry payloads"
	case step.Cleanup != "":
		return "dbprobe step must not carry a cleanup script"
	case step.Command != step.DBProbe.ProbeID:
		return "dbprobe step command must equal the probe id"
	}
	return ""
}

// executeDBProbe runs one named database probe. Order of operations:
//
//	shape -> ValidateSpec -> catalog lookup -> engine support -> local policy
//	  -> credential ref resolution -> adapter lookup (+ capability check)
//	  ---- no connection is opened by any stage above ----
//	  -> Connect -> Identity -> CheckSpec(identity gate, before any probe SQL)
//	  -> RunProbe -> Close
//
// Refusals return (outcome-with-GateRefusal, nil). Runtime failures (connect,
// identity read, probe, cancel, deadline) return the outcome plus a non-nil
// error and an ErrorClass: they are never a pass.
func executeDBProbe(ctx context.Context, step ScenarioStep) (DBProbeOutcome, error) {
	fail := func(class, reason string) (DBProbeOutcome, error) {
		log.Printf("[dbprobe] %s refused: %s", step.TaskID, reason)
		return refusal(class, reason), nil
	}
	if msg := dbprobeStepShapeRefusal(step); msg != "" {
		return fail(dbErrGateRefused, msg)
	}
	if !strings.EqualFold(step.Executor, "dbprobe") {
		return fail(dbErrGateRefused, "step executor is not dbprobe")
	}
	spec := *step.DBProbe

	// 1. Validate (catalog membership, engine, mode, limits, host, identity).
	if err := dbprobe.ValidateSpec(spec); err != nil {
		return fail(dbErrGateRefused, err.Error())
	}
	// 2. Catalog lookup: the only source of a probe's class.
	def, ok := dbprobe.LookupProbe(spec.ProbeID)
	if !ok {
		return fail(dbErrGateRefused, fmt.Sprintf("unknown probe %q", spec.ProbeID))
	}
	// 3. Probe supports this engine.
	engineOK := false
	for _, e := range def.Engines {
		if e == spec.Engine {
			engineOK = true
		}
	}
	if !engineOK {
		return fail(dbErrAdapterUnsupported, fmt.Sprintf("probe %q does not support engine %q", spec.ProbeID, spec.Engine))
	}
	// 4. Agent-local policy. CheckSpec is the single implementation of the
	// mode/class rules; identities are pre-matched with a placeholder here so
	// only the policy half can fail. The real identity gate runs after Connect.
	policy := dbprobePolicyFromEnv()
	if err := dbprobe.CheckSpec(spec, def, "policy-precheck", "policy-precheck", policy); err != nil {
		return fail(dbErrGateRefused, err.Error())
	}
	// 5. Credential reference -> secret (local variable only).
	cred, err := resolveDBCredential(spec.CredentialRef)
	if err != nil {
		class := dbErrCredentialUnresolved
		if errors.Is(err, errDBCredBadRef) {
			class = dbErrGateRefused
		}
		return fail(class, err.Error())
	}
	// 6. Adapter for the engine, and it must offer this probe.
	ad, ok := dbprobeNewAdapter(spec.Engine)
	if !ok {
		return fail(dbErrAdapterUnsupported, fmt.Sprintf("no adapter registered for engine %q", spec.Engine))
	}
	offered := false
	for _, id := range ad.Capabilities().ProbeIDs {
		if id == spec.ProbeID {
			offered = true
		}
	}
	if !offered {
		return fail(dbErrAdapterUnsupported, fmt.Sprintf("adapter for %q does not offer probe %q", spec.Engine, spec.ProbeID))
	}

	// Everything from here on is bounded by the spec's own limits.
	cctx, cancel := dbprobe.WithDeadline(ctx, spec.Limits)
	defer cancel()
	// ad.Close runs with its own ctx-free semantics; it must always happen.
	defer func() { _ = ad.Close() }()

	runtimeErr := func(class, what string, err error) (DBProbeOutcome, error) {
		class = classifyDBErr(cctx, err, class)
		msg := scrub(err.Error(), cred.Password)
		log.Printf("[dbprobe] %s %s failed (%s): %s", step.TaskID, what, class, msg)
		return DBProbeOutcome{
			Result: protocol.DBProbeResult{ErrorClass: class, Notes: []string{what + ": " + msg}, AgentTime: time.Now()},
		}, fmt.Errorf("dbprobe %s: %s: %s", what, class, msg)
	}

	cfg := dbprobe.ConnectionConfig{
		Engine: spec.Engine, Host: spec.Host, Port: spec.Port, Database: spec.Database,
		CredentialRef: spec.CredentialRef, TLSMode: spec.TLSMode, TargetID: spec.TargetID,
		User: cred.User, Password: cred.Password, Mode: spec.Mode,
	}
	if err := ad.Connect(cctx, cfg); err != nil {
		return runtimeErr(dbErrConnect, "connect", err)
	}
	observed, err := ad.Identity(cctx)
	if err != nil {
		return runtimeErr(dbErrIdentity, "identity", err)
	}
	// Identity gate: after Connect (the identity needs a connection) but
	// strictly before any probe SQL.
	if err := dbprobe.CheckSpec(spec, def, observed, spec.ExpectedIdentity, policy); err != nil {
		return fail(dbErrGateRefused, err.Error())
	}

	res, err := ad.RunProbe(cctx, def, spec)
	if err != nil {
		return runtimeErr(dbErrProbe, "probe", err)
	}
	if res.AgentTime.IsZero() {
		res.AgentTime = time.Now()
	}
	return DBProbeOutcome{Result: res}, nil
}

// execDBProbeStep adapts executeDBProbe to the executor's ExecResult. The typed
// DBProbe field carries the observation; nothing is serialised through Stdout.
// Results are never retryable (isRetryableResult): re-trying a failed
// authentication can lock out the customer's database account.
func execDBProbeStep(parentCtx context.Context, step ScenarioStep) protocol.ExecResult {
	start := time.Now()
	out, err := executeDBProbe(parentCtx, step)
	r := protocol.ExecResult{
		TaskID: step.TaskID, StartedAt: start, ExecutedAt: start,
		DurationMs: time.Since(start).Milliseconds(),
	}
	res := out.Result
	r.DBProbe = &res
	switch {
	case out.GateRefusal != "":
		r.ExitCode = -1
		r.Stderr = "dbprobe refused: " + out.GateRefusal
		if res.ErrorClass == dbErrGateRefused {
			r.Vetoed = true
			r.VetoedActionKey = step.ActionKey
			r.VetoedExecutionClass = step.ExecutionClass
			r.VetoedBlockSource = "dbsim_gate"
		}
	case err != nil:
		r.ExitCode = -1
		r.Stderr = err.Error()
		r.TimedOut = res.ErrorClass == dbErrTimeout
	}
	return r
}
