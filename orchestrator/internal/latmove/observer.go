package latmove

import "context"

// ExecutionObserver observes a lateral-movement attempt's evidence. It does
// NOT perform the attempt itself. No real implementation ships in this slice.
type ExecutionObserver interface {
	Observe(ctx context.Context, key AttemptKey) (Observation, error)
}

// FakeObserver is the only observer in this slice, keyed by RunID+"/"+Technique.
// An uncaptured key returns an uncorrelated, Call=Unknown observation -- never
// reusing another key's canned data and never fabricating a positive or
// negative result.
type FakeObserver struct {
	Obs map[string]Observation
	Err map[string]error
}

func (f *FakeObserver) key(k AttemptKey) string { return k.RunID + "/" + k.Technique }

func (f *FakeObserver) Observe(_ context.Context, key AttemptKey) (Observation, error) {
	lk := f.key(key)
	if err, ok := f.Err[lk]; ok {
		return Observation{}, err
	}
	if o, ok := f.Obs[lk]; ok {
		o.Key = key
		return o, nil
	}
	return Observation{
		Key:    key,
		Call:   CallUnknown,
		Marker: MarkerCheck{Correlated: false, Found: false},
		Detail: "no correlated observation for this attempt",
	}, nil
}
