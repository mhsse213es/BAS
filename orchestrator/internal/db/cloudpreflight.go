package db

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/cloudgraph"
)

// runPreflight checks a discovery source's prerequisites before any inventory is
// read. It returns every check, and an error when any check FAILs. A source that
// cannot be preflighted is refused, so discovery never runs unchecked.
func runPreflight(ctx context.Context, d cloudgraph.Discoverer) ([]cloudgraph.PreflightCheck, error) {
	p, ok := d.(cloudgraph.Preflighter)
	if !ok {
		return nil, fmt.Errorf("discovery source cannot be preflighted")
	}
	checks := p.Preflight(ctx)
	if failed := cloudgraph.PreflightFailures(checks); len(failed) > 0 {
		return checks, cloudgraph.PreflightBlockError(failed)
	}
	return checks, nil
}
