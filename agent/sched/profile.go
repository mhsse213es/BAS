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
}

// ResourceLock names one resource the step touches. Key optionally narrows the
// lock to a sub-scope (e.g. a specific registry hive path); an empty Key locks
// the whole domain.
type ResourceLock struct {
	Domain string `json:"domain"`
	Key    string `json:"key,omitempty"`
}

// globalKey is the synthetic barrier lock every step participates in: scoped
// steps hold it shared (read), global/unlabeled steps hold it exclusive (write).
// This makes a global step mutually exclusive with every other step without the
// scheduler needing an explicit dependency graph.
const globalKey = "*global*"

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
