// Package sched runs scenario steps concurrently while guaranteeing that the
// observable per-step outcome is identical to a strictly sequential run.
//
// Safety is enforced by execution constraints — resource locks acquired in a
// canonical order — NOT by trusting a step's classification. A step's
// ResourceProfile only widens parallelism: a step runs concurrently with another
// solely when their resource locks do not conflict. Any unlabeled, global-scope,
// or unrecognised profile resolves to an exclusive global lock (fully serial),
// which is always correct. Labels can therefore only make execution faster, never
// less accurate.
package sched

// ResourceProfile declares the resources a step touches. It is resolved
// server-side from curated per-technique metadata and shipped with the step.
//
//   - Domains: the resource domains the step reads or writes.
//   - Scope:   "local" (a specific path/key) or "global" (system-wide state).
//   - Risk:    "observation" (read-only), "modification", or "persistence".
//
// A nil profile, an empty Domains list, Scope=="global", or an unrecognised Risk
// all resolve to an exclusive global lock — i.e. the step runs serially.
type ResourceProfile struct {
	Domains []ResourceLock `json:"domains,omitempty"`
	Scope   string         `json:"scope,omitempty"`
	Risk    string         `json:"risk,omitempty"`

	// ObservesFootprint marks a step whose EVIDENCE observes the surface that
	// BAS's own execution perturbs — the process table, shared temp dirs, the
	// auth log, the kernel ring buffer. Such a step needs the surface quiet, so
	// it takes the footprint barrier exclusively. See footprintKey.
	ObservesFootprint bool `json:"observesFootprint,omitempty"`
}

// ResourceLock names one resource the step touches. Key optionally narrows the
// lock to a sub-scope (e.g. a specific registry hive path); an empty Key locks
// the whole domain.
type ResourceLock struct {
	Domain string `json:"domain"`
	Key    string `json:"key,omitempty"`
}

// TimeoutProfile bounds a step's lifecycle across three layers. It is resolved
// server-side from curated per-technique metadata and shipped with the step. Any
// zero field falls back to an engine default (see the agent runner/executor), so
// an absent profile is always safe — it just means "use defaults".
//
//   - ScheduleSec: max time a step may wait for its resource locks before the
//     scheduler records a schedule timeout instead of blocking forever.
//   - ExecuteSec:  max command runtime before the executor kills it and returns an
//     explicit timeout verdict (never a silent skip).
//   - GraceSec:    window after a kill for an in-flight command to finish/clean up
//     before the host is recycled.
type TimeoutProfile struct {
	ScheduleSec int `json:"scheduleSec,omitempty"`
	ExecuteSec  int `json:"executeSec,omitempty"`
	GraceSec    int `json:"graceSec,omitempty"`
}

// globalKey is the synthetic barrier lock every step participates in: scoped
// steps hold it shared (read), global/unlabeled steps hold it exclusive (write).
// This makes a global step mutually exclusive with every other step without the
// scheduler needing an explicit dependency graph.
const globalKey = "*global*"

// footprintKey is the quiescence barrier for BAS's own execution footprint —
// the process table, temp files, auth log and kernel ring buffer that every
// running step perturbs simply by existing. A step observing that surface
// cannot get a stable reading while other steps run, and no declared resource
// expresses this: nothing else declares "I write the process table", yet
// everything does.
//
// POLARITY IS INVERTED FROM ORDINARY READS AND MUST NOT BE "SIMPLIFIED":
//
//	ordinary step      -> SHARED    ("I perturb the surface")
//	footprint observer -> EXCLUSIVE ("I require the surface quiet")
//
// Modelling this the intuitive way — everyone *writes* the footprint, the
// observer *reads* it — gives every step an exclusive hold, so every pair
// conflicts, and parallelism is disabled entirely while still appearing
// correct. TestFootprint_TwoOrdinaryStepsDoNotConflictOnFootprint guards it.
const footprintKey = "*footprint*"

// Recognised risk levels. Observation maps to a read lock; modification and
// persistence map to a write lock.
const (
	RiskObservation  = "observation"
	RiskModification = "modification"
	RiskPersistence  = "persistence"
)

func knownRisk(r string) bool {
	switch r {
	case RiskObservation, RiskModification, RiskPersistence:
		return true
	}
	return false
}
