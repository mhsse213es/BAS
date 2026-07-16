package connector

// Source is one threat-intel provider. Live providers (MISP, OpenCTI) fetch over
// HTTP; the air-gapped BundleSource reads a signed local bundle. The Scheduler
// treats them uniformly so a deployment can run bundle-only, live-only, or layered.
type Source interface {
	// Fetch returns normalised threat-actor profiles from this provider.
	Fetch() ([]ThreatActor, error)
	// Name is a short stable identifier: "misp" | "opencti" | "bundle".
	Name() string
}
