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
	id := out.TargetID
	if id == "" {
		id = topo.Name
	}
	return adlabrt.Target{ID: id}, nil
}

// Teardown asks the Commander to revert and destroy the run's VMs. It is
// idempotent: a commander that reports the target already gone returns OK, and
// an empty target id is a no-op success.
func (h *HyperV) Teardown(ctx context.Context, t adlabrt.Target) error {
	out, err := h.Cmd.Run(ctx, Command{Kind: CmdTeardown, Args: map[string]string{"target": t.ID}})
	if err != nil {
		return fmt.Errorf("teardown %q: %w", t.ID, err)
	}
	if !out.OK {
		return fmt.Errorf("teardown %q did not complete: %s", t.ID, out.Detail)
	}
	return nil
}
