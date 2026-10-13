// Package networkgraph models network-connectivity evidence for Network
// BAS Mastery Phase 1. It deliberately reuses cloudgraph.PathState and
// cloudgraph.Provenance rather than redefining them -- see
// docs/superpowers/specs/2026-10-13-network-bas-phase1-evidence-foundation-design.md.
package networkgraph

import (
	"github.com/audspect/bas/internal/cloudgraph"
)

// Target is a single, explicitly authorized probe destination. There is no
// discovery-of-targets in this phase -- every Target is supplied by an
// authenticated, permissioned caller, never derived from scanning.
type Target struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"`
	Label    string `json:"label,omitempty"`
}

// VantagePoint identifies where probes actually originate. Populated once,
// at server startup, from operator configuration -- never from a request
// body. The zero value is never a valid, usable vantage point; callers
// must check Configured() before using one.
type VantagePoint struct {
	ID              string `json:"id"`
	NetworkPosition string `json:"networkPosition"`
}

// Configured reports whether vp was actually resolved from configuration.
func (vp VantagePoint) Configured() bool {
	return vp.ID != "" && vp.NetworkPosition != ""
}

// NetworkObservation is one probe's result against one Target, from one
// VantagePoint, at one point in time.
type NetworkObservation struct {
	ID             string                `json:"id,omitempty"`
	RunID          string                `json:"runId,omitempty"`
	Target         Target                `json:"target"`
	VantagePointID string                `json:"vantagePointId"`
	State          cloudgraph.PathState  `json:"state"`
	ErrorDetail    string                `json:"errorDetail,omitempty"`
	Provenance     cloudgraph.Provenance `json:"provenance"`
}

// NetworkFinding is the reporting-layer unit: one Target's final
// classification for a run, derived from its NetworkObservation, never
// invented. Limitations is a human-readable caveat (e.g. "a timeout is not
// proof of a block"), computed, never persisted as its own column.
type NetworkFinding struct {
	Target      Target               `json:"target"`
	State       cloudgraph.PathState `json:"state"`
	Limitations string               `json:"limitations,omitempty"`
}
