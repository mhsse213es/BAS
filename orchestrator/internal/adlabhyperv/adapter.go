package adlabhyperv

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/adlabrt"
)

// HyperV implements adlabrt.Substrate against a Commander. It holds no Hyper-V
// specifics itself: topology comes from the catalog, host ops go through Cmd.
type HyperV struct {
	Cmd Commander
}

// compile-time proof HyperV satisfies the substrate seam (interface unchanged).
var _ adlabrt.Substrate = (*HyperV)(nil)

// Provision resolves the topology and asks the Commander to stand it up on the
// topology's dedicated private switch. An unknown topology errors rather than
// provisioning an empty environment.
func (h *HyperV) Provision(ctx context.Context, spec adlabrt.LabSpec) (adlabrt.Target, error) {
	topo, ok := LookupTopology(spec.Name)
	if !ok {
		return adlabrt.Target{}, fmt.Errorf("unknown lab topology %q", spec.Name)
	}
	out, err := h.Cmd.Run(ctx, Command{Kind: CmdProvision, Args: map[string]string{
		"topology": topo.Name,
		"switch":   topo.Switch,
	}})
	if err != nil {
		return adlabrt.Target{}, fmt.Errorf("provision %q: %w", topo.Name, err)
	}
	if !out.OK {
		return adlabrt.Target{}, fmt.Errorf("provision %q did not complete: %s", topo.Name, out.Detail)
	}
	// The Commander must return a run-unique handle. Defaulting to the topology
	// name would hand concurrent runs the same Target, so one run's teardown
	// could revert another's live lab -- fail closed instead.
	if out.TargetID == "" {
		return adlabrt.Target{}, fmt.Errorf("provision %q returned no target handle", topo.Name)
	}
	return adlabrt.Target{ID: out.TargetID}, nil
}

// Teardown asks the Commander to revert and destroy the run's VMs. It is
// idempotent: a commander that reports the target already gone returns OK, and
// an empty target id is a no-op success.
func (h *HyperV) Teardown(ctx context.Context, t adlabrt.Target) error {
	// An empty target handle means nothing was provisioned (or already gone):
	// a no-op success, with no command sent to the Commander.
	if t.ID == "" {
		return nil
	}
	out, err := h.Cmd.Run(ctx, Command{Kind: CmdTeardown, Args: map[string]string{"target": t.ID}})
	if err != nil {
		return fmt.Errorf("teardown %q: %w", t.ID, err)
	}
	if !out.OK {
		return fmt.Errorf("teardown %q did not complete: %s", t.ID, out.Detail)
	}
	return nil
}

// VerifyIsolation runs each required isolation check through the Commander and
// aggregates them fail-closed. A probe that errors is recorded as an
// indeterminate result (never isolated), so a failed probe can never be
// mistaken for a verified-isolated lab.
func (h *HyperV) VerifyIsolation(ctx context.Context, t adlabrt.Target) (adlabrt.IsolationResult, error) {
	required := RequiredChecks()
	results := make(map[CheckKind]ProbeResult, len(required))
	for _, c := range required {
		out, err := h.Cmd.Run(ctx, Command{Kind: CmdProbe, Args: map[string]string{"target": t.ID, "check": string(c)}})
		if err != nil {
			results[c] = ProbeResult{Passed: false, Determinate: false, Detail: "probe error: " + err.Error()}
			continue
		}
		results[c] = ProbeResult{Passed: out.Passed, Determinate: out.Determinate, Detail: out.Detail}
	}
	return EvaluateIsolation(required, results), nil
}

// Execute runs the validation case through the Commander and maps its output to
// an Observation. It authors no attack content: it passes the case/primitive
// identity to the Commander (the lab-gated real runner resolves it to existing
// reusable content). An incomplete output stays Complete=false (inconclusive).
func (h *HyperV) Execute(ctx context.Context, t adlabrt.Target, vc adlabrt.ValidationCase) (adlabrt.Observation, error) {
	out, err := h.Cmd.Run(ctx, Command{Kind: CmdExecuteCase, Args: map[string]string{
		"target":    t.ID,
		"case":      vc.Name,
		"primitive": vc.Primitive.ID,
	}})
	if err != nil {
		return adlabrt.Observation{}, fmt.Errorf("execute case %q: %w", vc.Name, err)
	}
	return adlabrt.Observation{
		PostconditionObserved: out.PostconditionObserved,
		Complete:              out.Complete,
		Detail:                out.Detail,
	}, nil
}
