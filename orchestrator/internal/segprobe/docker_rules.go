package segprobe

import (
	"context"
	"fmt"
)

// ApplyRules replaces the firewall rule set with one registered pack's rules.
// The name must be a registered rules file: arbitrary names never reach the
// container. The lab's apply.sh resets the chain and reinstalls default-deny,
// so every run starts from a known state.
func (p *DockerProvider) ApplyRules(ctx context.Context, rulesFile string) error {
	if !isRegisteredRulesFile(rulesFile) {
		return fmt.Errorf("%w: rules file %q", ErrUnknownPack, rulesFile)
	}
	if _, err := p.compose(ctx, "exec", "-T", "seg-fw", "/rules/apply.sh", "/rules/"+rulesFile); err != nil {
		return fmt.Errorf("apply rules %s: %w", rulesFile, err)
	}
	return nil
}
