package runner

import "context"

// NoState is the state reader for a target that offers no independent view of its state, which is every customer API: only the
// lab has an administrative endpoint that reports records. It returns an empty snapshot, so it can never show that state changed.
//
// That makes it safe for READ_ONLY scenarios only, where the response is the evidence and no state change is expected. The runner
// refuses to run any other scenario with it (see Run), because an attack that changed state would otherwise grade as if it had
// not.
type NoState struct{}

// Snapshot returns an empty snapshot.
func (NoState) Snapshot(context.Context) (map[string]StateRecord, error) {
	return map[string]StateRecord{}, nil
}
