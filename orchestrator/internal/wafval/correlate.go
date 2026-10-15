package wafval

// AxisState is the resolved state of one evidence axis after correlation
// across all mechanisms for one key.
type AxisState string

const (
	AxisAgree         AxisState = "agree"         // all contributing mechanisms agree; value carried
	AxisContradictory AxisState = "contradictory" // two DIFFERENT mechanisms disagree
	AxisAmbiguous     AxisState = "ambiguous"     // same mechanism, distinct events, disagree
	AxisUnknown       AxisState = "unknown"       // no contributing mechanism had a known value
)

// AxisResolution is one axis's resolved state. The value fields are meaningful
// only when State == AxisAgree.
type AxisResolution struct {
	State       AxisState
	Enforcement EnforcementAction
	Detection   DetectionOutcome
	Origin      OriginObservation
}

// CorrelatedView is the per-axis resolved view for one key. Raw preserves every
// observation that fed the view, never discarded.
type CorrelatedView struct {
	Key           CorrelationKey
	EnforcementAx AxisResolution
	DetectionAx   AxisResolution
	OriginAx      AxisResolution
	Raw           []Observation
}

// Correlate merges collection results for one key into a per-axis resolved
// view. It never discards raw observations; it dedups same-mechanism events by
// EventID and distinguishes within-mechanism ambiguity from cross-mechanism
// contradiction.
func Correlate(key CorrelationKey, results []CollectionResult) CorrelatedView {
	var raw []Observation
	for _, r := range results {
		raw = append(raw, r.Observations...)
	}
	view := CorrelatedView{Key: key, Raw: raw}
	view.EnforcementAx = resolveEnforcement(results)
	view.DetectionAx = resolveDetection(results)
	view.OriginAx = resolveOrigin(results)
	return view
}

// axisAgg holds, per mechanism, the distinct known values seen on one axis
// (already deduped by EventID within each mechanism).
type axisAgg struct {
	perMech map[Mechanism]map[string]bool // mechanism -> set of distinct known values
}

// collect builds an axisAgg for one axis. valueOf returns ("", false) for the
// axis's unknown value, else (value, true). Same-mechanism events sharing an
// EventID are deduped so a duplicate is never independent corroboration.
func collect(results []CollectionResult, valueOf func(Observation) (string, bool)) axisAgg {
	agg := axisAgg{perMech: map[Mechanism]map[string]bool{}}
	for _, r := range results {
		// A search that did not verifiably complete establishes nothing: its
		// observations never contribute to axis resolution, so a negative
		// (e.g. not_matched) carried under incomplete/unavailable coverage can
		// never assert a value (spec §5, §8). Raw still preserves them.
		if !r.Coverage.Present() {
			continue
		}
		seenEvent := map[string]bool{}
		for _, o := range r.Observations {
			// Defensive: an observation whose mechanism disagrees with its
			// carrying result is malformed; do not count it under either.
			if o.Mechanism != r.Mechanism {
				continue
			}
			// Dedup same-mechanism events by EventID so a duplicate is never
			// independent corroboration. Empty EventIDs are NOT an identity:
			// distinct empty-id observations stay distinct so they can surface
			// ambiguity instead of silently collapsing to the first.
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
			if agg.perMech[r.Mechanism] == nil {
				agg.perMech[r.Mechanism] = map[string]bool{}
			}
			agg.perMech[r.Mechanism][val] = true
		}
	}
	return agg
}

// resolveState turns an axisAgg into an AxisState + the agreed value string.
// Cross-mechanism contradiction outranks within-mechanism ambiguity.
func resolveState(agg axisAgg) (AxisState, string) {
	allValues := map[string]bool{}
	for _, vals := range agg.perMech {
		for v := range vals {
			allValues[v] = true
		}
	}
	mechCount := len(agg.perMech)
	switch {
	case mechCount == 0:
		return AxisUnknown, ""
	case len(allValues) == 1:
		for v := range allValues {
			return AxisAgree, v
		}
		return AxisUnknown, "" // unreachable; len==1 always yields a value
	case mechCount == 1:
		return AxisAmbiguous, "" // one mechanism, multiple distinct values
	default:
		return AxisContradictory, "" // multiple mechanisms disagree
	}
}

func resolveEnforcement(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Enforcement == EnforcementUnknown {
			return "", false
		}
		return string(o.Enforcement), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Enforcement: EnforcementAction(val)}
}

func resolveDetection(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Detection == DetectionUnknown {
			return "", false
		}
		return string(o.Detection), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Detection: DetectionOutcome(val)}
}

func resolveOrigin(results []CollectionResult) AxisResolution {
	agg := collect(results, func(o Observation) (string, bool) {
		if o.Origin == OriginUnknown {
			return "", false
		}
		return string(o.Origin), true
	})
	st, val := resolveState(agg)
	return AxisResolution{State: st, Origin: OriginObservation(val)}
}
