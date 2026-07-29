package connector

import "github.com/audspect/bas/internal/intelligence"

// Source is one threat-intel provider. Live providers (MISP, OpenCTI) fetch over
// HTTP; the air-gapped BundleSource reads a signed local bundle. The Scheduler
// treats them uniformly so a deployment can run bundle-only, live-only, or layered.
type Source interface {
	// Fetch returns normalised threat-actor profiles from this provider.
	Fetch() ([]ThreatActor, error)
	// Name is a short stable identifier: "misp" | "opencti" | "bundle".
	Name() string
}

// IntelligenceSource is an optional Source capability: providers that can
// also extract Campaign/Malware/Tool intelligence beyond actor-technique
// profiles implement this. Both MISPClient and OpenCTIClient implement it
// as of Intelligence Expansion Phase 4 -- see
// docs/superpowers/specs/2026-07-29-intelligence-expansion-phase4-design.md.
type IntelligenceSource interface {
	FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, []intelligence.Tool, error)
}
