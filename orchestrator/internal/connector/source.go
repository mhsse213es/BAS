package connector

import (
	"time"

	"github.com/audspect/bas/internal/intelligence"
)

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

// ActivitySource performs a periodic sync producing activity evidence
// about already-known/identifiable actors -- e.g. "this MITRE group was
// mentioned in N currently-subscribed pulses" -- never curated attribution.
// Deliberately a separate interface from Source: an ActivitySource's data
// doesn't belong in threat_actor_profiles/threat_actor_sources' curated
// fields (Confidence, Sectors, Regions, LastSeen), only in its own
// threat_actor_activity table. See
// docs/superpowers/specs/2026-08-12-otx-activity-signal-design.md.
type ActivitySource interface {
	Name() string
	FetchActivity() ([]ActivitySignal, error)
}

// ActivitySignal is one actor's activity evidence gathered in a single
// sync -- PulseCount/FirstObserved/LastObserved all describe pulses
// examined THIS sync (a snapshot, not a cross-sync cumulative count; no
// pulse carries a stable ID to dedupe against across syncs).
type ActivitySignal struct {
	ActorName     string
	PulseCount    int
	FirstObserved time.Time
	LastObserved  time.Time
}
