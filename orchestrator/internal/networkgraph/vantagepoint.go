package networkgraph

import (
	"fmt"
	"os"
)

const (
	envVantagePointID       = "NETWORK_VANTAGE_POINT_ID"
	envVantagePointPosition = "NETWORK_VANTAGE_POINT_POSITION"
)

// LoadVantagePoint reads the vantage point's identity from environment
// configuration. It returns an error if either value is unset or empty --
// there is no default, because a default would be exactly the "declare a
// network position we don't actually occupy" failure mode Network BAS
// Phase 1 rules out. Call this once at server startup; the resolved
// VantagePoint is held by the caller for the life of the process, never
// re-read per request.
func LoadVantagePoint() (VantagePoint, error) {
	id := os.Getenv(envVantagePointID)
	position := os.Getenv(envVantagePointPosition)
	if id == "" || position == "" {
		return VantagePoint{}, fmt.Errorf("networkgraph: both %s and %s must be set to a non-empty value", envVantagePointID, envVantagePointPosition)
	}
	return VantagePoint{ID: id, NetworkPosition: position}, nil
}
