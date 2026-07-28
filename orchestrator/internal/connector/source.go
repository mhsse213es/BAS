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
// also extract Campaign/Malware intelligence beyond actor-technique
// profiles implement this. Only MISPClient does today -- see
// docs/superpowers/specs/2026-07-28-intelligence-expansion-design.md.
// OpenCTI/OTX/Bundle are unaffected until a later phase extends them.
type IntelligenceSource interface {
	FetchIntelligence() ([]intelligence.Campaign, []intelligence.Malware, error)
}
