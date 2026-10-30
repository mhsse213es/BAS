package rwevidence

import (
	"context"

	"github.com/audspect/bas/internal/controlval"
)

// PreventionObserver supplies the Prevention observation for one attempt. It
// takes the full AttemptKey, not only a CorrelationKey, because a real source
// needs the technique to resolve the attempt's host and time.
type PreventionObserver interface {
	ObservePrevention(ctx context.Context, key AttemptKey) (controlval.Observation, error)
}

// ProviderPrevention adapts a controlval.Provider, such as the canned
// FakeProvider, to PreventionObserver. It keeps the run and action correlation
// the provider has always used.
type ProviderPrevention struct {
	Provider controlval.Provider
}

// ObservePrevention implements PreventionObserver.
func (p ProviderPrevention) ObservePrevention(ctx context.Context, key AttemptKey) (controlval.Observation, error) {
	return p.Provider.Observe(ctx, controlval.CorrelationKey{RunID: key.RunID, Action: key.Action})
}
