package avval

// AxisState is the resolved state of one evidence axis after correlation
// across all control sources for one key.
type AxisState string

const (
	AxisAgree         AxisState = "agree"         // all contributing control sources agree; value carried
	AxisContradictory AxisState = "contradictory" // two DIFFERENT control sources disagree
	AxisAmbiguous     AxisState = "ambiguous"     // same control source, distinct events, disagree
	AxisUnknown       AxisState = "unknown"       // no contributing control source had a known value
)

// AxisResolution is one axis's resolved state. The value fields are
// meaningful only when State == AxisAgree.
type AxisResolution struct {
	State      AxisState
	Prevention PreventionOutcome
	Detection  DetectionOutcome
	Execution  ExecutionObservation
	Response   ResponseOutcome
}

// CorrelatedView is the per-axis resolved view for one key. Raw preserves
// every observation that fed the view, never discarded.
type CorrelatedView struct {
	Key          CorrelationKey
	PreventionAx AxisResolution
	DetectionAx  AxisResolution
	ExecutionAx  AxisResolution
	ResponseAx   AxisResolution
	Raw          []Observation
}

// Correlate merges collection results for one key into a per-axis resolved
// view. It never discards raw observations; it dedups same-control-source
// events by EventID and distinguishes within-control-source ambiguity from
// cross-control-source contradiction.
func Correlate(key CorrelationKey, results []CollectionResult) CorrelatedView {
	var raw []Observation
	for _, r := range results {
		raw = append(raw, r.Observations...)
	}
	view := CorrelatedView{Key: key, Raw: raw}
	view.PreventionAx = resolvePrevention(results)
	view.DetectionAx = resolveDetection(results)
	view.ExecutionAx = resolveExecution(results)
	view.ResponseAx = resolveResponse(results)
	return view
}

// axisAgg holds, per control source, the distinct known values seen on one
// axis (already deduped by EventID within each control source).
type axisAgg struct {
	perSource map[ControlSource]map[string]bool
}

// collect builds an axisAgg for one axis. valueOf returns ("", false) for the
// axis's unknown value, else (value, true). Same-control-source events
// sharing an EventID are deduped so a duplicate is never independent
// corroboration.
func collect(results []CollectionResult, valueOf func(Observation) (string, bool)) axisAgg {
	agg := axisAgg{perSource: map[ControlSource]map[string]bool{}}
	for _, r := range results {
		// A search that did not verifiably complete establishes nothing: its
		// observations never contribute to axis resolution, so a negative
		// (e.g. not_observed_within_window) carried under incomplete/
		// unavailable coverage can never assert a value. Raw still preserves
		// them.
		if !r.Coverage.Present() {
			continue
		}
		seenEvent := map[string]bool{}
		for _, o := range r.Observations {
			// Defensive: an observation whose control source disagrees with
			// its carrying result is malformed; do not count it under either.
			if o.ControlSource != r.ControlSource {
				continue
			}
			// Dedup same-control-source events by EventID so a duplicate is
			// never independent corroboration. Empty EventIDs are NOT an
			// identity: distinct empty-id observations stay distinct so they
			// can surface ambiguity instead of silently collapsing to the
			// first.
			if o.EventID != "" {
				if seenEvent[o.EventID] {
					continue
				}
				seenEvent[o.EventID] = true
			}
			val, known := valueOf(o)
			if !known {
				continue
			}
			if agg.perSource[r.ControlSource] == nil {
				agg.perSource[r.ControlSource] = map[string]bool{}
			}
			agg.perSource[r.ControlSource][val] = true
		}
	}
	return agg
}

// resolveState turns an axisAgg into an AxisState + the agreed value string.
// Cross-control-source contradiction outranks within-control-source
// ambiguity.
func resolveState(agg axisAgg) (AxisState, string) {
	allValues := map[string]bool{}
	for _, vals := range agg.perSource {
		for v := range vals {
			allValues[v] = true
		}
	}
	sourceCount := len(agg.perSource)
	switch {
	case sourceCount == 0:
		return AxisUnknown, ""
	case len(allValues) == 1:
		for v := range allValues {
			return AxisAgree, v
		}
		return AxisUnknown, "" // unreachable; len==1 always yields a value
	case sourceCount == 1:
		return AxisAmbiguous, "" // one control source, multiple distinct values
	default:
		return AxisContradictory, "" // multiple control sources disagree
	}
}

func resolvePrevention(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Prevention == PreventionUnknown || o.Prevention == "" {
			return "", false
		}
		return string(o.Prevention), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Prevention: PreventionOutcome(val)}
}

func resolveDetection(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Detection == DetectionUnknown || o.Detection == "" {
			return "", false
		}
		return string(o.Detection), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Detection: DetectionOutcome(val)}
}

func resolveExecution(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Execution == ExecutionUnknown || o.Execution == "" {
			return "", false
		}
		return string(o.Execution), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Execution: ExecutionObservation(val)}
}

func resolveResponse(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Response == ResponseUnknown || o.Response == "" {
			return "", false
		}
		return string(o.Response), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Response: ResponseOutcome(val)}
}
