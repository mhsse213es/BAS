package cloudgraph

import (
	"context"
	"fmt"
	"strings"
)

// Preflighter is implemented by a discoverer that can check its prerequisites
// without reading inventory. A run calls it before discovery, so a missing
// permission stops the run with every gap named instead of failing mid-pass.
type Preflighter interface {
	Preflight(ctx context.Context) []PreflightCheck
}

// PreflightFailures returns the checks that FAIL. SKIPPED is not a failure: an
// optional client may be unconfigured by design, and the run still goes ahead.
func PreflightFailures(checks []PreflightCheck) []PreflightCheck {
	var failed []PreflightCheck
	for _, c := range checks {
		if c.Status == "FAIL" {
			failed = append(failed, c)
		}
	}
	return failed
}

// PreflightBlockError names every failed check in one error. Each Detail is
// already redacted by the check that produced it.
func PreflightBlockError(failed []PreflightCheck) error {
	parts := make([]string, 0, len(failed))
	for _, c := range failed {
		parts = append(parts, c.Name+": "+c.Detail)
	}
	return fmt.Errorf("preflight failed: %s", strings.Join(parts, "; "))
}
