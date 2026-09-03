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
	// Reads/Writes declare direction PER RESOURCE, for per-atomic profiles. When
	// either is non-empty the agent ignores Domains/Scope/Risk. A single Risk
	// cannot express "reads process, writes filesystem" — observation
	// under-locks the write, modification over-locks the read.
	Reads  []ResourceLock `json:"reads,omitempty"`
	Writes []ResourceLock `json:"writes,omitempty"`

	// Domains/Scope/Risk are the per-technique form the curated map below still
	// uses; profiles migrate to Reads/Writes incrementally.
	Domains []ResourceLock `json:"domains,omitempty"`
	Scope   string         `json:"scope,omitempty"`
	Risk    string         `json:"risk,omitempty"`

	// ObservesFootprint marks a technique whose EVIDENCE observes the surface
	// BAS's own execution perturbs — the process table, shared temp dirs, the
	// auth log, the kernel ring buffer. No step declares "I write the process
	// table", yet every step does simply by running, so no ordinary resource can
	// express this hazard.
	//
	// The agent turns this into an EXCLUSIVE hold on its footprint barrier while
	// ordinary steps hold it shared — see sched.footprintKey. The polarity is
	// inverted from an ordinary read and must not be "simplified" back.
	ObservesFootprint bool `json:"observesFootprint,omitempty"`
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
// domFilesystem currently has no consumer in discoveryProfiles below (T1083,
// its only user, was removed 2026-08-20 -- see that map's doc comment) but
// stays defined: it's a real domain the agent's sched package still
// recognises (agent/sched's own tests reference it), so a future
// genuinely-fast filesystem-reading technique can reuse it directly.
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

// observeFootprint is observe() for a technique whose evidence reads the surface
// BAS's own execution perturbs. Such a step needs the host quiet to get a stable
// reading, so the agent gives it an exclusive hold on the footprint barrier —
// it runs alongside nothing, even though it writes nothing.
//
// Reach for this whenever a technique enumerates processes, tails an auth log,
// reads the kernel ring buffer, or lists a shared temp directory: under
// concurrency those all return the agent's own in-flight atomics.
func observeFootprint(domain string) *ResourceProfile {
	p := observe(domain)
	p.ObservesFootprint = true
	return p
}

// discoveryProfiles is the conservative first label set: well-known ATT&CK
// discovery techniques that only enumerate/read host state and never modify it.
// These dominate the full ART sweep, so labelling them read-only is where the
// safe speedup comes from. Add to this map only after the equivalence harness
// confirms a technique is genuinely non-mutating.
//
// This map also drives TimeoutProfileFor's aggressive 20s execute-timeout
// override (below) -- the two concerns are coupled by design, since both rest
// on the same "enumerates host state and returns in well under a second"
// assumption.
//
// **2026-08-20 audit**: every technique below was checked against real
// production ART command text for exactly that assumption. Two
// (T1046, T1614) were removed entirely -- the MAJORITY of their real atomics
// are active network operations (port scans; an external HTTPS geolocation
// call with no timeout flag), not sub-second local reads, so the 20s cap was
// producing false TIMEOUT verdicts. A few others (T1012, T1016, T1018, T1049)
// keep a single documented exception each -- see their inline comments --
// where only a minority of atomics share that problem; the map is keyed by
// technique, not by individual atomic/test_index, so removing the whole
// technique to fix one atomic would trade away legitimate fast/parallel
// treatment for the rest. Everything else checked clean. Re-verify any
// technique added here later the same way before trusting the 20s bound.
//
// **2026-08-26 expansion audit**: evaluated 5 more discovery-tactic
// candidates (T1120, T1201, T1217, T1652, T1654) against real production
// command text. Added T1652 (clean) and T1120 (kept, one narrow exception --
// see its inline comment). Excluded T1201, T1217, T1654 -- see the comment
// block immediately after this map for why.
var discoveryProfiles = map[string]*ResourceProfile{
	// T1012 (Query Registry) -- Test 3 loops over every registered COM CLSID
	// (often thousands on a real Windows host) and actually instantiates each
	// one via [activator]::CreateInstance(...). The other 5 of 6 atomics are
	// simple, fast reg query/Get-Item reads. Kept; that one atomic is a known
	// narrow exception.
	"T1012": observe(domRegistry), // Query Registry
	// Footprint observer: ps/tasklist returns the agent's own in-flight atomics
	// under concurrency, so its evidence is contaminated by parallelism itself.
	"T1057": observeFootprint(domProcess), // Process Discovery
	"T1007": observe(domProcess),          // System Service Discovery
	"T1518": observe(domProcess),          // Software Discovery
	"T1010": observe(domProcess),          // Application Window Discovery
	"T1082": observe(domProcess),          // System Information Discovery
	"T1033": observe(domProcess),          // System Owner/User Discovery
	"T1124": observe(domProcess),          // System Time Discovery
	// T1016 (System Network Configuration Discovery) -- Test 9's
	// `nslookup -timeout=12` is bounded but borderline: a retry or two could
	// push it past the 20s cap. Only 1 of 9 atomics, and softer risk than the
	// removed techniques since it's at least timeout-capped. Kept.
	"T1016": observe(domNetwork), // System Network Configuration Discovery
	// T1049 (System Network Connections Discovery) -- Test 7 runs SharpView's
	// ACL scanner, Kerberoasting, and domain-share discovery, all known-slow
	// against a live AD domain. Only 1 of 7 atomics. Kept.
	// Footprint observer: netstat/ss list connections BY OWNING PROCESS, so the
	// output includes the agent's own orchestrator socket plus any connection a
	// concurrently running atomic opens. Marked conservatively -- per-atomic
	// command text should confirm it when atomic profiles are authored.
	"T1049": observeFootprint(domNetwork), // System Network Connections Discovery
	// T1018 (Remote System Discovery) -- 5 of 6 Linux atomics are fast local
	// reads (arp -a, ip neighbour/route show, netstat -r, ip tcp_metrics
	// show). Only "Test 7: sweep" (a sequential, unthrottled `ping -c 1` of
	// 254 addresses with no -W deadline) shares T1046's problem. Kept.
	"T1018": observe(domNetwork),   // Remote System Discovery
	"T1087": observe(domSecPolicy), // Account Discovery
	"T1069": observe(domSecPolicy), // Permission Groups Discovery
	"T1652": observe(domProcess),   // Device Driver Discovery
	// T1120 (Peripheral Device Discovery) -- Test 2 "WinPwn - printercheck"
	// downloads and executes an entire third-party script
	// (iex(new-object net.webclient).downloadstring(...)), an unbounded
	// network call sharing T1614's problem. The other 3 of 4 atomics (WMI
	// PnP query, fsutil fsinfo drives, Get-Printer) are simple, fast local
	// reads. Only 1 of 4 atomics. Kept as a documented narrow exception
	// (2026-08-26 expansion audit).
	"T1120": observe(domProcess), // Peripheral Device Discovery
}

// Expansion candidates evaluated 2026-08-26 and deliberately left OUT of
// discoveryProfiles above (real production art_atomic_tests command text
// checked, same methodology as the 2026-08-20 audit):
//   - T1201 (Password Policy Discovery) -- 3 of 11 atomics hit the network/AD
//     (`net accounts /domain`, a PowerSploit `IEX(IWR ...)` download,
//     `get-addefaultdomainpasswordpolicy`), well past the narrow-exception bar.
//   - T1217 (Browser Information Discovery) -- 5 of 11 atomics run a full
//     filesystem `find /` walk (macOS x3, Linux x2), T1083's exact problem.
//   - T1654 (Log Enumeration) -- Test 1 (`Get-EventLog 'Security' | where ...`)
//     is a well-known slow operation against large Security logs, especially
//     on a heavily-audited production host; 1 of 2 atomics.

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
