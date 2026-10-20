package killchain

// Observation outcomes a provider check can reduce to.
const (
	ObservationDetected    = "detected"
	ObservationNotDetected = "not_detected"
	ObservationError       = "error"
)

// DetectionObservation is one provider check, already reduced to plain fields.
// TelemetryHealth and WindowComplete are set only when the caller holds evidence
// for them. Left empty, they count as unknown.
type DetectionObservation struct {
	Verdict         string
	Provider        string
	AlertID         string
	TelemetryHealth TelemetryHealth
	WindowComplete  Tri
}

// AggregateDetection combines a stage's observations into one detection
// evidence value. Any detection makes the stage DETECTED. Checks that fail
// count for nothing. With no detection, a stage with no usable observation is
// INCONCLUSIVE. A not-detected result keeps the health and window the caller
// actually knew, so the verdict engine can refuse to score it when they are
// unknown.
func AggregateDetection(obs []DetectionObservation) DetectionEvidence {
	for _, o := range obs {
		if o.Verdict == ObservationDetected {
			return DetectionEvidence{
				Value:           DetectionDetected,
				AlertID:         o.AlertID,
				TelemetrySource: o.Provider,
			}
		}
	}
	var notDetected []DetectionObservation
	for _, o := range obs {
		if o.Verdict == ObservationNotDetected {
			notDetected = append(notDetected, o)
		}
	}
	if len(notDetected) > 0 {
		return DetectionEvidence{
			Value:           DetectionNotDetected,
			TelemetryHealth: combinedHealth(notDetected),
			WindowComplete:  combinedWindow(notDetected),
			TelemetrySource: notDetected[0].Provider,
		}
	}
	return DetectionEvidence{Value: DetectionInconclusive}
}

// combinedHealth is healthy only when every provider was healthy. Any
// unhealthy provider makes it unhealthy. Anything unknown stays unknown.
func combinedHealth(obs []DetectionObservation) TelemetryHealth {
	all := true
	for _, o := range obs {
		switch o.TelemetryHealth {
		case TelemetryUnhealthy:
			return TelemetryUnhealthy
		case TelemetryHealthy:
		default:
			all = false
		}
	}
	if all {
		return TelemetryHealthy
	}
	return ""
}

// combinedWindow is complete only when every provider's window was complete.
// Any incomplete window makes it incomplete. Anything unknown stays unknown.
func combinedWindow(obs []DetectionObservation) Tri {
	all := true
	for _, o := range obs {
		switch o.WindowComplete {
		case TriNo:
			return TriNo
		case TriYes:
		default:
			all = false
		}
	}
	if all {
		return TriYes
	}
	return TriUnknown
}
