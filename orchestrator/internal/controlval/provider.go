package controlval

import "context"

// Provider observes a DEPLOYED security control's response to an already-
// executed attack attempt. It does NOT execute the attack (execution is a
// separate evidence stream). When it cannot correlate a response it returns an
// Outcome=unknown observation (NOT an error); error is reserved for a technical
// failure of the observation operation itself.
type Provider interface {
	Name() string
	Observe(ctx context.Context, key CorrelationKey) (Observation, error)
}

// FakeProvider is the only provider in this slice. It returns canned
// observations by Action, a configured technical error, or -- for an uncaptured
// Action -- an Unknown observation with no fabricated outcome, confidence or
// evidence. It never reuses another action's canned observation. Real adapters
// are deferred (spec section 7).
//
// Stamping the requested key here proves the SEAM works; it does NOT prove a
// real provider correctly correlated its observation to the attempt. The three
// unresolved Task 1 contract decisions (correlation-enforcement location,
// unset-MinConfidence default, two-prevention-outcome match) remain open and
// are tracked in the spec, not settled by this fake.
type FakeProvider struct {
	ProviderName string
	Obs          map[string]Observation
	Err          map[string]error
}

// Name identifies the provider on every observation it returns.
func (f *FakeProvider) Name() string { return f.ProviderName }

// Observe returns, in precedence order: a configured technical error; the
// canned observation for key.Action (with the requested key stamped); otherwise
// an Unknown observation for the uncaptured action.
func (f *FakeProvider) Observe(_ context.Context, key CorrelationKey) (Observation, error) {
	if err, ok := f.Err[key.Action]; ok {
		return Observation{}, err
	}
	if o, ok := f.Obs[key.Action]; ok {
		o.Key = key
		if o.Provider == "" {
			o.Provider = f.ProviderName
		}
		return o, nil
	}
	return Observation{
		Key:        key,
		Provider:   f.ProviderName,
		Outcome:    OutcomeUnknown,
		Confidence: ConfidenceNone,
		Detail:     "no correlated control response",
	}, nil
}
