package scenario

import "strings"

// ResourceProfile declares the resources a step touches so the agent's scheduler
// can decide which steps may run concurrently. Its JSON shape MUST match the
// agent's sched.ResourceProfile exactly — it is serialised onto the wire as the
// step's "resource" field and resolved into locks on the endpoint.
//
// Safety does not depend on these labels being correct: the agent resolves any
// nil/empty/global/unrecognised profile to an exclusive global lock (fully
// serial), which is always accurate. A label can therefore only widen
// parallelism, never change a verdict — and the agent's equivalence harness
// gates that invariant. We label conservatively: only unambiguously read-only
// discovery techniques get a profile; everything else stays unlabeled (serial).
type ResourceProfile struct {
	Domains []ResourceLock `json:"domains,omitempty"`
	Scope   string         `json:"scope,omitempty"`
	Risk    string         `json:"risk,omitempty"`
}

// ResourceLock names one resource domain a step touches. Key optionally narrows
// the lock to a sub-scope; empty Key locks the whole domain.
type ResourceLock struct {
	Domain string `json:"domain"`
	Key    string `json:"key,omitempty"`
}

// TimeoutProfile bounds a step's schedule/execute/grace windows. Its JSON shape
// MUST match the agent's sched.TimeoutProfile. We attach it only to fast
// read-only discovery steps; every other step keeps a nil profile so the agent
// honours that step's own configured timeout (never silently overridden).
type TimeoutProfile struct {
	ScheduleSec int `json:"scheduleSec,omitempty"`
	ExecuteSec  int `json:"executeSec,omitempty"`
	GraceSec    int `json:"graceSec,omitempty"`
}

// discoveryTimeout: discovery atomics enumerate host state and return in well
// under a second. A tight execute bound makes a hung discovery step fail fast
// instead of stalling the sweep for the old blanket 120s; the schedule bound
// keeps a parallel step from waiting forever on a wedged sibling's locks.
var discoveryTimeout = &TimeoutProfile{ScheduleSec: 30, ExecuteSec: 20, GraceSec: 3}

// TimeoutProfileFor returns the curated timeout for a technique, or nil when the
// technique is not in the conservative discovery set (→ the agent uses the step's
// own timeout / engine default).
func TimeoutProfileFor(techniqueID string) *TimeoutProfile {
	if ResourceProfileFor(techniqueID) != nil {
		return discoveryTimeout
	}
	return nil
}

// Resource domains and risk levels — kept in sync with the agent's sched package.
const (
	domRegistry   = "registry"
	domFilesystem = "filesystem"
	domProcess    = "process"
	domNetwork    = "network"
	domSecPolicy  = "wmi-secpolicy"

	riskObservation = "observation"
)

// observe builds a read-only, locally-scoped profile on a single domain. Steps
// labelled this way hold a shared lock, so they run concurrently with each other
// (and with any other observation) while still serialising behind unlabeled
// (write/global) steps via the agent's global barrier.
func observe(domain string) *ResourceProfile {
	return &ResourceProfile{
		Domains: []ResourceLock{{Domain: domain}},
		Scope:   "local",
		Risk:    riskObservation,
	}
}

// discoveryProfiles is the conservative first label set: well-known ATT&CK
// discovery techniques that only enumerate/read host state and never modify it.
// These dominate the full ART sweep, so labelling them read-only is where the
// safe speedup comes from. Add to this map only after the equivalence harness
// confirms a technique is genuinely non-mutating.
var discoveryProfiles = map[string]*ResourceProfile{
	"T1012": observe(domRegistry),   // Query Registry
	"T1083": observe(domFilesystem), // File and Directory Discovery
	"T1057": observe(domProcess),    // Process Discovery
	"T1007": observe(domProcess),    // System Service Discovery
	"T1518": observe(domProcess),    // Software Discovery
	"T1010": observe(domProcess),    // Application Window Discovery
	"T1082": observe(domProcess),    // System Information Discovery
	"T1033": observe(domProcess),    // System Owner/User Discovery
	"T1124": observe(domProcess),    // System Time Discovery
	"T1614": observe(domProcess),    // System Location Discovery
	"T1016": observe(domNetwork),    // System Network Configuration Discovery
	"T1049": observe(domNetwork),    // System Network Connections Discovery
	"T1018": observe(domNetwork),    // Remote System Discovery
	"T1046": observe(domNetwork),    // Network Service Discovery
	"T1087": observe(domSecPolicy),  // Account Discovery
	"T1069": observe(domSecPolicy),  // Permission Groups Discovery
}

// ResourceProfileFor returns the curated profile for an ATT&CK technique, or nil
// if the technique is not in the conservative label set (→ the agent runs it
// serially). Sub-techniques (e.g. T1518.001) inherit their parent's profile when
// no exact entry exists.
func ResourceProfileFor(techniqueID string) *ResourceProfile {
	id := strings.ToUpper(strings.TrimSpace(techniqueID))
	if p, ok := discoveryProfiles[id]; ok {
		return p
	}
	if base, _, found := strings.Cut(id, "."); found {
		if p, ok := discoveryProfiles[base]; ok {
			return p
		}
	}
	return nil
}

// AttachProfiles labels every step with its curated resource and timeout profiles
// in place. Steps with no curated entry keep nil profiles: they run serially and
// the agent honours their own configured timeout.
func AttachProfiles(steps []ScenarioStep) {
	for i := range steps {
		steps[i].Resource = ResourceProfileFor(steps[i].TechniqueID)
		steps[i].Timeout = TimeoutProfileFor(steps[i].TechniqueID)
	}
}
