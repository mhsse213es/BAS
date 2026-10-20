package killchain

import "strings"

// Mapping functions translate each domain's own enum values into the shared
// contract. Each domain keeps its enum as evidence. A source value that is not
// listed here, or is ambiguous, maps to the unknown value. That makes the
// engine report INCONCLUSIVE, never a pass.

// MapPrevention maps an enforcement value from any domain. Only an explicit
// "blocked" or "allowed" is a prevention outcome. "quarantined", "terminated",
// "challenged" and the like are ambiguous about whether the action executed,
// so they are unknown.
func MapPrevention(source string) PreventionValue {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "blocked":
		return PreventionBlocked
	case "allowed":
		return PreventionAllowed
	case "not_applicable":
		return PreventionNotApplicable
	default:
		return PreventionUnknown
	}
}

// MapTelemetryHealth maps a DLP telemetry value. Only "Present" confirms the
// telemetry source is operational. Absent, Delayed, Incomplete and Unverifiable
// are all unhealthy, because none of them confirms the source saw the event.
// An unrecognised value returns "" so that it counts as missing evidence.
func MapTelemetryHealth(source string) TelemetryHealth {
	switch source {
	case "Present":
		return TelemetryHealthy
	case "Absent", "Delayed", "Incomplete", "Unverifiable":
		return TelemetryUnhealthy
	default:
		return ""
	}
}

// MapDetection maps a detection outcome. Only an explicit "detected" or
// "not_detected" is taken at face value. Anything else is inconclusive,
// because a telemetry presence check is not a detection.
func MapDetection(source string) DetectionValue {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "detected", "alerted":
		return DetectionDetected
	case "not_detected":
		return DetectionNotDetected
	case "not_applicable":
		return DetectionNotApplicable
	default:
		return DetectionInconclusive
	}
}
