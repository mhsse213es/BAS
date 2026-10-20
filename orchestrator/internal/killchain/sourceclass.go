package killchain

// SourceClass is the kind of independent evidence behind a ground-truth record.
type SourceClass string

const (
	SourceEventLog            SourceClass = "host_event_log"
	SourceNetworkSensor       SourceClass = "network_sensor"
	SourceEDRTelemetry        SourceClass = "edr_telemetry"
	SourceOperatorObservation SourceClass = "operator_observation"
)

// knownSourceClasses are the only classes a record may carry.
var knownSourceClasses = map[SourceClass]bool{
	SourceEventLog: true, SourceNetworkSensor: true, SourceEDRTelemetry: true, SourceOperatorObservation: true,
}

// sourcePolicy lists, per scenario, the classes that can prove execution.
// Operator observation is never accepted for these scenarios. A human's
// statement is not a host record, so it cannot close an identity or lateral stage.
// A scenario with no entry accepts no class. Only the scenarios listed here can
// carry ground truth until their policy is written.
var sourcePolicy = map[string][]SourceClass{
	"credential-access":        {SourceEventLog, SourceEDRTelemetry},
	"caldera-lateral-movement": {SourceEventLog, SourceNetworkSensor, SourceEDRTelemetry},
}

// SourceClassAllowed reports whether a class may prove execution for a scenario.
func SourceClassAllowed(scenarioID string, class SourceClass) bool {
	if !knownSourceClasses[class] {
		return false
	}
	for _, c := range sourcePolicy[scenarioID] {
		if c == class {
			return true
		}
	}
	return false
}
