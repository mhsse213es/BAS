package evidence

import "time"

type TrustState string

const (
	TrustTrusted   TrustState = "trusted"
	TrustUntrusted TrustState = "untrusted"
)

type ObservationMode string

const (
	ModeSnapshot       ObservationMode = "snapshot"
	ModeActivityWindow ObservationMode = "activity_window"
)

// Completeness is the source adapter's own assessment of how much of its
// data this sync actually captured (spec §5.2) — never inferred from HTTP
// success alone.
type Completeness string

const (
	Complete  Completeness = "complete"
	Partial   Completeness = "partial"
	Truncated Completeness = "truncated"
	Failed    Completeness = "failed"
)

type ClaimKind string

const (
	ClaimAsserted  ClaimKind = "claim"
	ClaimRetracted ClaimKind = "retraction"
)

// RawClaim is one (actor, technique) assertion exactly as a source adapter
// saw it, captured before any downstream actor-merge or technique-count
// filter (spec §6.2). ActorName is matched against the resolved threat
// roster by the scheduler, the same way upsertActorSources already does.
type RawClaim struct {
	ActorName     string
	TechniqueID   string
	Via           string
	ViaName       string
	ExternalID    string // the event/object id this claim came from
	ObservedAt    time.Time
	StartTime     time.Time
	StopTime      time.Time
	RawConfidence string
	Raw           map[string]any // the full raw record, stored as source_observations.raw
}

// SyncReport is what a source adapter computed about its own most recent
// Fetch() call — read by Scheduler.sync() via the CompletenessSource
// interface (internal/connector/types.go), the same pattern as StatsSource.
type SyncReport struct {
	Completeness Completeness
	Diagnostic   string
}
