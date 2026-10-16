package avval

// EvaluateTelemetryCompleteness reports whether the evidence-collection
// pipeline itself worked for a test -- complete, partial, or unavailable --
// independent of any finding. av.txt §4: "No alert found" is not
// automatically a confirmed detection failure; the integration may be
// broken, the event may be delayed, or the test may not have triggered the
// intended behavior. This function answers "did telemetry collection work",
// never "did the control work".
func EvaluateTelemetryCompleteness(results []CollectionResult) (TelemetryState, string) {
	if len(results) == 0 {
		return TelemetryUnavailable, "no telemetry source reported any result"
	}
	var anyPresent, anyIncomplete bool
	for _, r := range results {
		switch {
		case r.Coverage.Present():
			anyPresent = true
		case r.Coverage == CoverageSearchIncomplete:
			anyIncomplete = true
		}
	}
	switch {
	case anyPresent && !anyIncomplete:
		return TelemetryComplete, "every contributing telemetry source established complete coverage"
	case anyPresent && anyIncomplete:
		return TelemetryPartial, "at least one telemetry source established coverage, but another did not complete"
	case anyIncomplete:
		return TelemetryPartial, "telemetry collection was attempted but did not complete"
	default:
		return TelemetryUnavailable, "no telemetry source established any coverage"
	}
}
