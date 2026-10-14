# Network BAS Mastery Phase 7A: OT/ICS Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add declared IT/OT boundary-violation detection (extending the existing on-prem path-query endpoint) and a safety-authorization gate in front of every active-network-I/O capability this codebase has (discovery runs, DNS checks, transport checks), so a target resolving into a declared-sensitive OT zone can never be actively probed without explicit, recorded authorization.

**Architecture:** New package `internal/otsafety` declares `SensitiveZone`/`RequiredTransit` by zone name only (never cross-validated against a real topology import), re-implementing a `ValidateRequiredTransits` bypass-detection function structurally identical to — but independent of — Phase 6B's `remoteaccess.ValidateMandatoryTransit`, plus a new `CheckActiveTestAuthorization` function with no 6B precedent. `POST /api/network-paths` (Phase 3) gains one optional field to run boundary detection; `POST /api/network-discovery-runs` (Phase 1), `POST /api/dns-security-checks` (Phase 5A), and `POST /api/transport-security-checks` (Phase 5B) each gain the same three optional fields to run the authorization gate. Every extension is additive and optional — omitting the new fields (every caller today) leaves behavior byte-for-byte unchanged.

**Tech Stack:** Go, PostgreSQL via `pgxpool`, chi router — same as every prior phase this session.

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase7a-ot-ics-safety-design.md`

## Global Constraints

- `internal/otsafety` never modifies `networktopology`, `networkpath`, `networkgraph`, `networkdns`, or `networktransport` — it imports `networktopology.Zone`/`RoutePath`/`TopologyImport`/`ZoneForHost` read-only. (Spec §2.)
- `internal/otsafety` never imports `internal/remoteaccess` or vice versa — `RequiredTransit`/`ValidateRequiredTransits` are re-implemented fresh, structurally identical to `remoteaccess.MandatoryTransit`/`ValidateMandatoryTransit` but an independent copy, per this project's standing cross-phase-isolation discipline. (Spec §2, §4.3.)
- `ValidateRequiredTransits` matches a route's endpoints against a transit's `FromZone`/`ToZone` in **either order** from the very first version — Phase 6B's own final-review finding (direction-blindness) is built in as a day-one requirement here, not discovered later. (Spec §4.3, Review Focus #5.)
- `SensitiveZone.ZoneName` and `RequiredTransit.FromZone`/`ToZone`/`ViaZone` are never cross-validated against a real `networktopology.TopologyImport`'s declared zones — only checked for non-emptiness. Any import with either slice non-empty requires non-empty top-level `Limitations`, enforced at the API validation layer (mirroring `validateRemoteAccessImport`), not inside `internal/otsafety` itself. (Spec §3, §4.2.)
- `TransitViolation` is strictly additive evidence — it is never permitted to alter a `PathResult`'s `State`. (Spec §9.)
- The active-test authorization check (§Task 2) only ever fails *closed* where a target host positively resolves (via `networktopology.ZoneForHost`) to a zone that is itself declared in `OTSafetyImport.SensitiveZones`. A target that fails to resolve to any known zone, or resolves to a zone absent from `SensitiveZones`, is never gated. (Spec §4.4, Review Focus #2.)
- Rejection on a missing/invalid authorization is a hard 400 — never a silent downgrade to a passive/synthetic probe mode. (Spec §9.)
- Every extension to an existing endpoint (`/api/network-paths`, `/api/network-discovery-runs`, `/api/dns-security-checks`, `/api/transport-security-checks`) is an *additive, optional* field. A request that omits the new field(s) entirely must produce byte-for-byte the same behavior as before this plan — verified by the fact that every pre-existing test for these four handlers keeps passing unmodified.
- Host has only ~7.84-8.2GB RAM — never run unscoped `go test ./internal/api/...` or `./internal/db/...`; always `go build ./...` + scoped package tests + a `-run` regex covering every new/changed test together. Check `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` before any `internal/api`/`internal/db` test run; if free memory is below ~1GB, check for (never kill) stray Docker testcontainers or orphaned `*.test.exe` processes before proceeding — this is a known transient pattern on this host, not a real problem by itself.
- Sonnet only for any subagent/fork dispatch, never Opus. `git push` immediately after every single commit. Work happens inline on `main`, no worktree, no feature branch. RED must be watched failing (not assumed) before every GREEN.

## Review Focus

1. A zone marked sensitive with **no** `RequiredTransit` declared at all must still gate active probing against it, but must never manufacture a spurious boundary violation — the two gates (boundary detection, Task 1; active-test authorization, Task 2) are independent and must never be conflated. Each task's own tests prove its half; Task 5/6's end-to-end tests prove they don't leak into each other.
2. A target host that does not resolve to any declared zone at all must fail *open* on the authorization gate — identical to the "no safety import supplied" case — never reject a request solely because the topology import happens not to cover every host named. (Task 2.)
3. A multi-target request where only **one** target resolves to a sensitive zone must still gate the entire request — not require every named target to match before the check applies. (Task 2.)
4. `ActiveTestAuthorization{Authorized: true}` supplied when no target actually touches a sensitive zone must be harmless and must never become an error, and must never generate a misleading audit-log entry claiming an authorization was exercised when nothing needed it. (Task 2, Task 6.)
5. Boundary-bypass detection in the **reverse query direction** gets its own dedicated test from the start (`ValidateRequiredTransits` is direction-agnostic by design). (Task 1.)

---

### Task 1: `internal/otsafety` — Data Model and Boundary-Violation Detection

**Files:**
- Create: `orchestrator/internal/otsafety/types.go`
- Create: `orchestrator/internal/otsafety/transit.go`
- Test: `orchestrator/internal/otsafety/transit_test.go`

**Interfaces:**
- Consumes: `networktopology.RoutePath` (`[]string`, from `orchestrator/internal/networktopology/routes.go:21`), nothing else from existing packages.
- Produces: `otsafety.TierOT`, `otsafety.SensitiveZone{ZoneName,Tier,Note}`, `otsafety.RequiredTransit{CanonicalID,FromZone,ToZone,ViaZone,Note}`, `otsafety.OTSafetyImport{ID,SourceType,ImportedBy,ImportedAt,ConfigVersion,SensitiveZones,RequiredTransits,Limitations}`, `otsafety.MaxSensitiveZonesPerImport`/`MaxRequiredTransitsPerImport` (both `500`), `otsafety.TransitViolation{Transit,Route,Note}`, `otsafety.ValidateRequiredTransits(routes []networktopology.RoutePath, transits []RequiredTransit) []TransitViolation` — consumed by Task 5.

- [ ] **Step 1: Write `types.go`**

```go
package otsafety

import "time"

const (
	// TierOT is the single sensitivity tier for this increment --
	// deliberately not a broader taxonomy until a real need for finer
	// granularity appears.
	TierOT = "ot"

	MaxSensitiveZonesPerImport   = 500
	MaxRequiredTransitsPerImport = 500
)

// SensitiveZone declares that a networktopology zone (referenced by
// name only, never cross-validated against a real
// networktopology.TopologyImport) requires the stricter active-testing
// safeguards of CheckActiveTestAuthorization (authz.go). Tier is
// currently always TierOT; the field exists so a future increment can
// add tiers without a breaking schema change.
type SensitiveZone struct {
	ZoneName string `json:"zoneName"`
	Tier     string `json:"tier"` // TierOT
	Note     string `json:"note,omitempty"`
}

// RequiredTransit declares that any path between FromZone and ToZone,
// in either direction, must visit ViaZone -- e.g. "any path between
// the corporate zone and the OT zone must pass through the DMZ zone."
// This is a declared-architecture constraint, validated against
// whatever the route search actually finds (transit.go), never baked
// into the routing graph itself. Structurally identical to
// remoteaccess.MandatoryTransit, re-implemented fresh here rather than
// imported -- internal/otsafety and internal/remoteaccess never import
// each other.
type RequiredTransit struct {
	CanonicalID string `json:"canonicalId"`
	FromZone    string `json:"fromZone"`
	ToZone      string `json:"toZone"`
	ViaZone     string `json:"viaZone"`
	Note        string `json:"note,omitempty"`
}

// OTSafetyImport is one auditable, versioned snapshot -- the same
// shape discipline as remoteaccess.RemoteAccessImport /
// networktopology.TopologyImport.
type OTSafetyImport struct {
	ID               string            `json:"id,omitempty"`
	SourceType       string            `json:"sourceType"`
	ImportedBy       string            `json:"importedBy,omitempty"`
	ImportedAt       time.Time         `json:"importedAt,omitempty"`
	ConfigVersion    string            `json:"configVersion,omitempty"`
	SensitiveZones   []SensitiveZone   `json:"sensitiveZones"`
	RequiredTransits []RequiredTransit `json:"requiredTransits,omitempty"`
	Limitations      []string          `json:"limitations,omitempty"`
}
```

- [ ] **Step 2: Write the failing test for `ValidateRequiredTransits`**

```go
package otsafety

import (
	"testing"

	"github.com/audspect/bas/internal/networktopology"
)

func TestValidateRequiredTransits_BypassRoute_FlaggedAsViolation(t *testing.T) {
	routes := []networktopology.RoutePath{{"corporate", "ot"}} // skips the DMZ entirely
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 -- the route bypasses the required DMZ zone", violations)
	}
	if violations[0].Transit.CanonicalID != "rt-1" {
		t.Fatalf("violations[0].Transit.CanonicalID = %q, want %q", violations[0].Transit.CanonicalID, "rt-1")
	}
}

func TestValidateRequiredTransits_RouteVisitsViaZone_NoViolation(t *testing.T) {
	routes := []networktopology.RoutePath{{"corporate", "dmz", "ot"}}
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- the route does visit the required DMZ zone", violations)
	}
}

// TestValidateRequiredTransits_NoRouteAtAllForTransitEndpoints_NoViolation
// pins Review Focus #1's "independent gates" half for the detection
// side: a RequiredTransit whose endpoints have no candidate route
// among the ones supplied must produce no violation -- "no route
// found" is a different finding entirely, never force-reported as a
// bypass.
func TestValidateRequiredTransits_NoRouteAtAllForTransitEndpoints_NoViolation(t *testing.T) {
	routes := []networktopology.RoutePath{} // genuinely isolated zones
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- no candidate route exists for this transit's endpoints at all", violations)
	}
}

func TestValidateRequiredTransits_UnrelatedTransit_DoesNotInterfere(t *testing.T) {
	routes := []networktopology.RoutePath{{"corporate", "ot"}}
	transits := []RequiredTransit{
		{CanonicalID: "rt-unrelated", FromZone: "guest", ToZone: "staging", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 0 {
		t.Fatalf("violations = %v, want zero -- a transit rule for a different zone pair must not match this route", violations)
	}
}

// TestValidateRequiredTransits_BypassRoute_ReverseDirection_StillFlagged
// pins Review Focus #5 and this plan's own Global Constraints --
// direction-agnostic matching from the start, incorporating Phase 6B's
// final-review lesson rather than re-learning it.
func TestValidateRequiredTransits_BypassRoute_ReverseDirection_StillFlagged(t *testing.T) {
	routes := []networktopology.RoutePath{{"ot", "corporate"}} // same bypass, reverse direction
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 -- the bypass exists regardless of which direction it was queried from", violations)
	}
}

// TestValidateRequiredTransits_DenseFixture_OnlyNonCompliantRouteFlagged
// mirrors this project's own standing lesson: a flat/trivial fixture
// can mask a real multi-tier bug (DNSSEC, TLS-cert-chain, Phase 5) --
// always test a fixture with more than one candidate route.
func TestValidateRequiredTransits_DenseFixture_OnlyNonCompliantRouteFlagged(t *testing.T) {
	routes := []networktopology.RoutePath{
		{"corporate", "ot"},
		{"corporate", "dmz", "ot"},
	}
	transits := []RequiredTransit{
		{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
	}
	violations := ValidateRequiredTransits(routes, transits)
	if len(violations) != 1 {
		t.Fatalf("violations = %v, want exactly 1 (only the direct route bypasses the DMZ)", violations)
	}
	if len(violations[0].Route) != 2 {
		t.Fatalf("violations[0].Route = %v, want the 2-zone direct route, not the compliant 3-zone one", violations[0].Route)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cd orchestrator && go test ./internal/otsafety/... -v`
Expected: FAIL -- `ValidateRequiredTransits`/`TransitViolation` undefined (compile error).

- [ ] **Step 4: Write `transit.go`**

```go
package otsafety

import "github.com/audspect/bas/internal/networktopology"

// TransitViolation is evidence that a found route between a
// RequiredTransit's FromZone and ToZone (in either direction) never
// visited ViaZone.
type TransitViolation struct {
	Transit RequiredTransit           `json:"transit"`
	Route   networktopology.RoutePath `json:"route"`
	Note    string                    `json:"note"`
}

// ValidateRequiredTransits checks each route against every
// RequiredTransit whose FromZone/ToZone match the route's own
// endpoints (route[0] and route[len(route)-1]) in EITHER order,
// returning one TransitViolation per route that bypasses ViaZone.
// Matching is direction-agnostic because the edges that make a bypass
// possible are themselves usable in both directions unless explicitly
// Directed, so a boundary declared between two zones must hold
// regardless of which zone a given route query started from. A route
// that does not match a transit's endpoints (in either order) at all
// is not a candidate for that rule -- it is not a bypass, it is simply
// unrelated. Purely additive: it never removes a route from the
// caller's own result set, only annotates which ones violate a
// declared constraint.
func ValidateRequiredTransits(routes []networktopology.RoutePath, transits []RequiredTransit) []TransitViolation {
	var violations []TransitViolation
	for _, route := range routes {
		if len(route) == 0 {
			continue
		}
		from, to := route[0], route[len(route)-1]
		for _, transit := range transits {
			matchesForward := transit.FromZone == from && transit.ToZone == to
			matchesReverse := transit.FromZone == to && transit.ToZone == from
			if !matchesForward && !matchesReverse {
				continue
			}
			if routeVisits(route, transit.ViaZone) {
				continue
			}
			violations = append(violations, TransitViolation{
				Transit: transit,
				Route:   route,
				Note:    "this route reaches the declared destination zone without visiting the required transit zone",
			})
		}
	}
	return violations
}

func routeVisits(route networktopology.RoutePath, zone string) bool {
	for _, z := range route {
		if z == zone {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/otsafety/... -v`
Expected: PASS, 6/6.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/otsafety/types.go orchestrator/internal/otsafety/transit.go orchestrator/internal/otsafety/transit_test.go
git commit -m "feat(otsafety): add OT/ICS data model and boundary-violation detection"
git push
```

---

### Task 2: `internal/otsafety` — Active-Test Authorization Check

**Files:**
- Create: `orchestrator/internal/otsafety/authz.go`
- Test: `orchestrator/internal/otsafety/authz_test.go`

**Interfaces:**
- Consumes: `networktopology.ZoneForHost(host string, zones []Zone) (string, error)` (`orchestrator/internal/networktopology/resolve.go:32`), `networktopology.TopologyImport` (for its `Zones` field), `otsafety.OTSafetyImport`/`SensitiveZone` (Task 1).
- Produces: `otsafety.ActiveTestAuthorization{Authorized,SignOff}`, `otsafety.CheckActiveTestAuthorization(targetHosts []string, topo *networktopology.TopologyImport, safety *OTSafetyImport, auth *ActiveTestAuthorization) (matchedZones []string, err error)` -- consumed by Task 6.

  **Note on the return shape:** the design spec's §4.4 describes this function returning only `error`. During this plan's own grounding, a `matchedZones []string` return was added alongside `error` -- Task 6's handlers need to know *whether* a sensitive-zone match actually occurred (to decide whether an audit-log entry recording the sign-off is warranted) separately from whether the check passed. Returning `(nil, nil)` for "no match, nothing to gate" and `(zones, nil)` for "match found, authorization accepted" lets the caller log precisely when an authorization was actually exercised (Review Focus #4), rather than guessing from the presence of `auth.Authorized` alone (which may be true even when it authorized nothing).

- [ ] **Step 1: Write the failing tests**

```go
package otsafety

import (
	"testing"

	"github.com/audspect/bas/internal/networktopology"
)

func zonesFixture() []networktopology.Zone {
	return []networktopology.Zone{
		{Name: "corporate", CIDRs: []string{"10.0.1.0/24"}},
		{Name: "ot", CIDRs: []string{"10.0.2.0/24"}},
	}
}

func TestCheckActiveTestAuthorization_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	_, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, nil)
	if err == nil {
		t.Fatal("want an error -- a target in a declared sensitive zone with no authorization must be rejected")
	}
}

func TestCheckActiveTestAuthorization_TargetInSensitiveZone_AuthorizedWithSignOff_Accepted(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, &ActiveTestAuthorization{Authorized: true, SignOff: "approved by J.Singh, CHG-1234"})
	if err != nil {
		t.Fatalf("want no error with a valid authorization, got %v", err)
	}
	if len(matched) != 1 || matched[0] != "ot" {
		t.Fatalf("matchedZones = %v, want [\"ot\"]", matched)
	}
}

func TestCheckActiveTestAuthorization_AuthorizedButEmptySignOff_Rejected(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	_, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, &ActiveTestAuthorization{Authorized: true, SignOff: ""})
	if err == nil {
		t.Fatal("want an error -- Authorized alone is not sufficient, SignOff must be non-empty")
	}
}

// TestCheckActiveTestAuthorization_UnresolvableTarget_FailsOpen pins
// Review Focus #2: a target that does not resolve to any declared
// zone at all must never be gated.
func TestCheckActiveTestAuthorization_UnresolvableTarget_FailsOpen(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"192.168.99.99"}, topo, safety, nil)
	if err != nil {
		t.Fatalf("want no error -- an unresolvable target must fail open, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty", matched)
	}
}

func TestCheckActiveTestAuthorization_ResolvedZoneNotSensitive_FailsOpen(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"10.0.1.5"}, topo, safety, nil) // resolves to "corporate", not sensitive
	if err != nil {
		t.Fatalf("want no error -- a non-sensitive zone must never be gated, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty", matched)
	}
}

// TestCheckActiveTestAuthorization_OnlyOneOfMultipleTargetsSensitive_StillGated
// pins Review Focus #3.
func TestCheckActiveTestAuthorization_OnlyOneOfMultipleTargetsSensitive_StillGated(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	_, err := CheckActiveTestAuthorization([]string{"10.0.1.5", "10.0.2.5"}, topo, safety, nil)
	if err == nil {
		t.Fatal("want an error -- even one sensitive-zone target among several must gate the whole set")
	}
}

// TestCheckActiveTestAuthorization_AuthorizedButNoSensitiveMatch_Harmless
// pins Review Focus #4: an over-cautious caller is never penalized,
// and matchedZones correctly reports nothing was actually exercised.
func TestCheckActiveTestAuthorization_AuthorizedButNoSensitiveMatch_Harmless(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{SensitiveZones: []SensitiveZone{{ZoneName: "ot", Tier: TierOT}}}
	matched, err := CheckActiveTestAuthorization([]string{"10.0.1.5"}, topo, safety, &ActiveTestAuthorization{Authorized: true, SignOff: "pre-approved just in case"})
	if err != nil {
		t.Fatalf("want no error, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty -- nothing was actually sensitive, so nothing was exercised", matched)
	}
}

func TestCheckActiveTestAuthorization_NoSensitiveZonesDeclaredAtAll_NeverGates(t *testing.T) {
	topo := &networktopology.TopologyImport{Zones: zonesFixture()}
	safety := &OTSafetyImport{} // no SensitiveZones at all
	matched, err := CheckActiveTestAuthorization([]string{"10.0.2.5"}, topo, safety, nil)
	if err != nil {
		t.Fatalf("want no error -- a zone can be undeclared-sensitive even if the topology knows it, got %v", err)
	}
	if len(matched) != 0 {
		t.Fatalf("matchedZones = %v, want empty", matched)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Check free memory first (this package needs no DB, so it's a safe pure-compute run regardless).

Run: `cd orchestrator && go test ./internal/otsafety/... -run TestCheckActiveTestAuthorization -v`
Expected: FAIL -- `CheckActiveTestAuthorization`/`ActiveTestAuthorization` undefined (compile error).

- [ ] **Step 3: Write `authz.go`**

```go
package otsafety

import (
	"fmt"

	"github.com/audspect/bas/internal/networktopology"
)

// ActiveTestAuthorization is the per-request authorization a caller
// must supply when any named target resolves into a declared
// SensitiveZone. Authorized alone is not sufficient -- SignOff must
// also be non-empty, mirroring every other "Limitations must be
// non-empty" discipline in this initiative.
type ActiveTestAuthorization struct {
	Authorized bool   `json:"authorized"`
	SignOff    string `json:"signOff,omitempty"`
}

// CheckActiveTestAuthorization resolves each target host to a zone
// via networktopology.ZoneForHost (reused, unmodified). If any
// resolved zone matches a SensitiveZone.ZoneName in safety, auth must
// have Authorized == true and a non-empty SignOff, or an error naming
// every matching sensitive zone is returned. matchedZones reports
// exactly which sensitive zones were found among the targets --
// empty with a nil error means nothing was gated at all (no target
// touched a declared-sensitive zone), which the caller (Task 6) uses
// to decide whether an authorization was actually exercised and worth
// an audit-log entry, as distinct from merely supplied. A target that
// does not resolve to any known zone at all, or resolves to a zone
// absent from safety.SensitiveZones, is never gated -- this only ever
// fails closed where there is positive evidence of OT-zone
// membership, never as a blanket new requirement on every caller.
func CheckActiveTestAuthorization(targetHosts []string, topo *networktopology.TopologyImport, safety *OTSafetyImport, auth *ActiveTestAuthorization) (matchedZones []string, err error) {
	sensitive := make(map[string]bool, len(safety.SensitiveZones))
	for _, sz := range safety.SensitiveZones {
		sensitive[sz.ZoneName] = true
	}

	seen := make(map[string]bool)
	for _, host := range targetHosts {
		zone, resolveErr := networktopology.ZoneForHost(host, topo.Zones)
		if resolveErr != nil {
			continue // unresolvable target -- fails open, never gated
		}
		if sensitive[zone] && !seen[zone] {
			seen[zone] = true
			matchedZones = append(matchedZones, zone)
		}
	}

	if len(matchedZones) == 0 {
		return nil, nil
	}
	if auth == nil || !auth.Authorized || auth.SignOff == "" {
		return nil, fmt.Errorf("explicit active-test authorization (with a non-empty sign-off) is required: target(s) resolve to declared sensitive zone(s) %v", matchedZones)
	}
	return matchedZones, nil
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd orchestrator && go test ./internal/otsafety/... -v`
Expected: PASS, 14/14 (6 from Task 1 + 8 from this task).

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/otsafety/authz.go orchestrator/internal/otsafety/authz_test.go
git commit -m "feat(otsafety): add active-test authorization check"
git push
```

---

### Task 3: `internal/db` — `OTSafetyImport` Persistence

**Files:**
- Create: `orchestrator/internal/db/otsafety_store.go`
- Test: `orchestrator/internal/db/otsafety_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go:171-175` (immediately after the existing `EnsureRemoteAccessImportSchema` block)
- Modify: `orchestrator/cmd/server/main.go:314-316` (immediately after the existing `EnsureRemoteAccessImportSchema` call)

**Interfaces:**
- Consumes: `otsafety.OTSafetyImport`/`SensitiveZone`/`RequiredTransit` (Task 1).
- Produces: `db.EnsureOTSafetyImportSchema(ctx, pool) error`, `db.InsertOTSafetyImport(ctx, pool, imp *otsafety.OTSafetyImport) error`, `db.GetOTSafetyImport(ctx, pool, id) (*otsafety.OTSafetyImport, error)` (404 via `errors.Is(err, pgx.ErrNoRows)`), `db.ListOTSafetyImports(ctx, pool, limit) ([]*otsafety.OTSafetyImport, error)` -- all consumed by Task 4, 5, 6.

- [ ] **Step 1: Write the failing tests**

```go
package db

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/otsafety"
)

func TestInsertAndGetOTSafetyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &otsafety.OTSafetyImport{
			ID:         newTestID(),
			SourceType: "manual",
			SensitiveZones: []otsafety.SensitiveZone{
				{ZoneName: "ot", Tier: otsafety.TierOT, Note: "engineering workstation zone"},
			},
			RequiredTransits: []otsafety.RequiredTransit{
				{CanonicalID: "rt-1", FromZone: "corporate", ToZone: "ot", ViaZone: "dmz"},
			},
			Limitations: []string{"zone names are not cross-validated against a real network-topology import"},
		}
		if err := InsertOTSafetyImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}
		got, err := GetOTSafetyImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.SensitiveZones) != 1 || got.SensitiveZones[0].ZoneName != "ot" {
			t.Fatalf("SensitiveZones = %v, want 1 entry for zone \"ot\"", got.SensitiveZones)
		}
		if len(got.RequiredTransits) != 1 || got.RequiredTransits[0].CanonicalID != "rt-1" {
			t.Fatalf("RequiredTransits = %v, want 1 entry \"rt-1\"", got.RequiredTransits)
		}
	})
}

func TestGetOTSafetyImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := GetOTSafetyImport(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("err = %v, want errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}

func TestListOTSafetyImports_NewestFirst(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		first := &otsafety.OTSafetyImport{ID: newTestID(), SourceType: "manual"}
		if err := InsertOTSafetyImport(context.Background(), pool, first); err != nil {
			t.Fatalf("insert first: %v", err)
		}
		second := &otsafety.OTSafetyImport{ID: newTestID(), SourceType: "manual"}
		if err := InsertOTSafetyImport(context.Background(), pool, second); err != nil {
			t.Fatalf("insert second: %v", err)
		}
		list, err := ListOTSafetyImports(context.Background(), pool, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(list) < 2 || list[0].ID != second.ID {
			t.Fatalf("list[0].ID = %q, want %q (newest first)", list[0].ID, second.ID)
		}
	})
}
```

(If this test file's package does not already define a `newTestID` helper, grep `orchestrator/internal/db/remoteaccess_store_test.go` and the surrounding `_test.go` files first for whatever ID-generation helper they actually use -- e.g. `newID()`'s db-package-local test equivalent -- and use that instead; do not invent a second helper if one already exists.)

- [ ] **Step 2: Run the tests to verify they fail**

Check free memory first.

Run: `cd orchestrator && go test ./internal/db/... -run "TestInsertAndGetOTSafetyImport|TestGetOTSafetyImport_NotFound|TestListOTSafetyImports" -v`
Expected: FAIL -- `InsertOTSafetyImport`/`GetOTSafetyImport`/`ListOTSafetyImports` undefined (compile error).

- [ ] **Step 3: Write `otsafety_store.go`**

```go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/otsafety"
)

// EnsureOTSafetyImportSchema creates the ot_safety_imports table.
func EnsureOTSafetyImportSchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS ot_safety_imports (
			id              text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type     text        NOT NULL,
			imported_by     text,
			imported_at     timestamptz NOT NULL DEFAULT NOW(),
			config_version  text,
			limitations     text[],
			ot_safety_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("ot_safety_imports: ensure schema: %w", err)
	}
	return nil
}

// otSafetyData is the shape persisted in the ot_safety_data jsonb
// column -- just the two slices that make an import's content, not
// its metadata (which live in their own columns).
type otSafetyData struct {
	SensitiveZones   []otsafety.SensitiveZone   `json:"sensitiveZones"`
	RequiredTransits []otsafety.RequiredTransit `json:"requiredTransits"`
}

// InsertOTSafetyImport writes a new ot_safety_imports row. The caller
// supplies imp.ID already generated.
func InsertOTSafetyImport(ctx context.Context, pool *pgxpool.Pool, imp *otsafety.OTSafetyImport) error {
	data, err := json.Marshal(otSafetyData{SensitiveZones: imp.SensitiveZones, RequiredTransits: imp.RequiredTransits})
	if err != nil {
		return fmt.Errorf("ot_safety_imports: marshal ot safety data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO ot_safety_imports (id, source_type, imported_by, config_version, limitations, ot_safety_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("ot_safety_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanOTSafetyImport(row pgx.Row) (*otsafety.OTSafetyImport, error) {
	imp := &otsafety.OTSafetyImport{}
	var importedBy, configVersion *string
	var data []byte
	if err := row.Scan(&imp.ID, &imp.SourceType, &importedBy, &imp.ImportedAt, &configVersion, &imp.Limitations, &data); err != nil {
		return nil, err
	}
	if importedBy != nil {
		imp.ImportedBy = *importedBy
	}
	if configVersion != nil {
		imp.ConfigVersion = *configVersion
	}
	var sd otSafetyData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("ot_safety_imports: unmarshal ot safety data for %s: %w", imp.ID, err)
	}
	imp.SensitiveZones, imp.RequiredTransits = sd.SensitiveZones, sd.RequiredTransits
	return imp, nil
}

// GetOTSafetyImport returns one import by id. A missing id returns an
// error satisfying errors.Is(err, pgx.ErrNoRows).
func GetOTSafetyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*otsafety.OTSafetyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, ot_safety_data
		 FROM ot_safety_imports WHERE id = $1`, id)
	imp, err := scanOTSafetyImport(row)
	if err != nil {
		return nil, fmt.Errorf("ot_safety_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListOTSafetyImports returns up to limit rows, newest first.
func ListOTSafetyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*otsafety.OTSafetyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, ot_safety_data
		 FROM ot_safety_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("ot_safety_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*otsafety.OTSafetyImport
	for rows.Next() {
		imp, err := scanOTSafetyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("ot_safety_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ot_safety_imports: list rows: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Wire the schema into `testdb.go` and `main.go`**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block ending `return nil, fmt.Errorf("testutil: EnsureRemoteAccessImportSchema: %w", err) }` (currently lines 171-175 -- re-check via `grep -n EnsureRemoteAccessImportSchema` first, since earlier work in this session may have shifted it), add:

```go
	if err := db.EnsureOTSafetyImportSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureOTSafetyImportSchema: %w", err)
	}
```

In `orchestrator/cmd/server/main.go`, immediately after the existing block ending `log.Fatalf("[FATAL] remote access import schema: %v", err) }` (currently lines 314-316 -- re-check via grep first), add:

```go
	if err := db.EnsureOTSafetyImportSchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] ot safety schema: %v", err)
	}
```

- [ ] **Step 5: Run `go build` and the tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -run "TestInsertAndGetOTSafetyImport|TestGetOTSafetyImport_NotFound|TestListOTSafetyImports" -v`
Expected: `go build` clean; tests PASS, 3/3.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/db/otsafety_store.go orchestrator/internal/db/otsafety_store_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(db): add ot_safety_imports persistence"
git push
```

---

### Task 4: `internal/api` — `OTSafetyImport` CRUD Endpoints

**Files:**
- Create: `orchestrator/internal/api/otsafety_handlers.go`
- Test: `orchestrator/internal/api/otsafety_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go` (new permission, re-check current line numbers via `grep -n CanImportRemoteAccessTopology` first -- currently 248/311/327)
- Modify: `orchestrator/internal/api/routes.go` (new GET/POST routes, re-check current line numbers via `grep -n remote-access-imports` first -- currently 260-261/439)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (new rows, re-check current line numbers via `grep -n remote-access-imports` first -- currently 73-74/225)

**Interfaces:**
- Consumes: `db.EnsureOTSafetyImportSchema`/`InsertOTSafetyImport`/`GetOTSafetyImport`/`ListOTSafetyImports` (Task 3); `otsafety.OTSafetyImport`/`SensitiveZone`/`RequiredTransit`/`TierOT`/`MaxSensitiveZonesPerImport`/`MaxRequiredTransitsPerImport` (Task 1).
- Produces: `(h *Handler) CreateOTSafetyImport`/`ListOTSafetyImports`/`GetOTSafetyImport` HTTP handlers; `auth.CanImportOTSafetyConfig` permission -- both consumed by Task 5/6's own tests (which create an `OTSafetyImport` via this HTTP layer, mirroring every prior phase's test helper pattern).

- [ ] **Step 1: Add the permission**

In `orchestrator/internal/auth/permissions.go`, re-grep for the current location of `CanImportRemoteAccessTopology` (do not assume the line numbers above are still exact) and add immediately after its const declaration:

```go
	// ot-safety:import gates importing OT/ICS sensitive-zone and
	// required-transit declarations (Network BAS Phase 7A) -- same
	// placement as CanImportRemoteAccessTopology, for the same reason.
	CanImportOTSafetyConfig Permission = "ot-safety:import"
```

Then add `CanImportOTSafetyConfig: true,` immediately after the existing `CanImportRemoteAccessTopology: true,` line in the `RoleAdmin` map literal, and `, CanImportOTSafetyConfig: true` appended to the `RoleAnalyst` inline list (after its own `CanImportRemoteAccessTopology: true`).

- [ ] **Step 2: Write the failing tests**

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/otsafety"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validOTSafetyImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual",
		"sensitiveZones": []map[string]any{
			{"zoneName": "ot", "tier": "ot", "note": "engineering workstation zone"},
		},
		"requiredTransits": []map[string]any{
			{"canonicalId": "rt-1", "fromZone": "corporate", "toZone": "ot", "viaZone": "dmz"},
		},
		"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
	}
}

func TestCreateOTSafetyImport_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validOTSafetyImportBody())
		userID := seedUser(t, pool, "otsafety-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created otsafety.OTSafetyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" {
			t.Fatal("want non-empty ID")
		}
	})
}

func TestCreateOTSafetyImport_InvalidTier_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		body["sensitiveZones"] = []map[string]any{{"zoneName": "ot", "tier": "critical"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-badtier", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an unknown tier must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateOTSafetyImport_ZonesWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		delete(body, "limitations")
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-nolim", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- any SensitiveZones/RequiredTransits present requires non-empty Limitations", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateOTSafetyImport_EmptyZoneName_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validOTSafetyImportBody()
		body["sensitiveZones"] = []map[string]any{{"zoneName": "", "tier": "ot"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "otsafety-op-emptyzone", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateOTSafetyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an empty zone name must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetOTSafetyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validOTSafetyImportBody())
		userID := seedUser(t, pool, "otsafety-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		createReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateOTSafetyImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created otsafety.OTSafetyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/ot-safety-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListOTSafetyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/ot-safety-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetOTSafetyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestCreateOTSafetyImport|TestListAndGetOTSafetyImport" -v`
Expected: FAIL -- `h.CreateOTSafetyImport` undefined (compile error).

- [ ] **Step 4: Write `otsafety_handlers.go`**

```go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/otsafety"
)

const maxOTSafetyImportRequestBytes = 5 << 20

// CreateOTSafetyImport -- POST /api/ot-safety-imports.
func (h *Handler) CreateOTSafetyImport(w http.ResponseWriter, r *http.Request) {
	var req otsafety.OTSafetyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxOTSafetyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateOTSafetyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertOTSafetyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "otsafety.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "otsafety.import", req.ID, map[string]any{"sensitiveZoneCount": len(req.SensitiveZones), "requiredTransitCount": len(req.RequiredTransits)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateOTSafetyImport(imp *otsafety.OTSafetyImport) error {
	if len(imp.SensitiveZones) > otsafety.MaxSensitiveZonesPerImport {
		return fmt.Errorf("too many sensitive zones — got %d, max %d", len(imp.SensitiveZones), otsafety.MaxSensitiveZonesPerImport)
	}
	if len(imp.RequiredTransits) > otsafety.MaxRequiredTransitsPerImport {
		return fmt.Errorf("too many required transits — got %d, max %d", len(imp.RequiredTransits), otsafety.MaxRequiredTransitsPerImport)
	}

	hasLimitations := len(imp.Limitations) > 0
	if (len(imp.SensitiveZones) > 0 || len(imp.RequiredTransits) > 0) && !hasLimitations {
		return fmt.Errorf("limitations must be non-empty whenever any sensitive zone or required transit is declared — zone names are never cross-validated against a real network-topology import")
	}

	for i, sz := range imp.SensitiveZones {
		if sz.ZoneName == "" {
			return fmt.Errorf("sensitiveZones[%d]: zoneName is required", i)
		}
		if sz.Tier != otsafety.TierOT {
			return fmt.Errorf("sensitiveZones[%d]: unknown tier %q", i, sz.Tier)
		}
	}
	for i, t := range imp.RequiredTransits {
		if t.FromZone == "" || t.ToZone == "" || t.ViaZone == "" {
			return fmt.Errorf("requiredTransits[%d]: fromZone, toZone, and viaZone are all required", i)
		}
	}
	return nil
}

// ListOTSafetyImports -- GET /api/ot-safety-imports.
func (h *Handler) ListOTSafetyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListOTSafetyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*otsafety.OTSafetyImport{}
	}
	respond(w, imports)
}

// GetOTSafetyImport -- GET /api/ot-safety-imports/{id}.
func (h *Handler) GetOTSafetyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetOTSafetyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "ot safety import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
```

- [ ] **Step 5: Wire the routes**

In `orchestrator/internal/api/routes.go`, immediately after the existing `remote-access-imports` GET routes, add:

```go
		r.Get("/api/ot-safety-imports", h.ListOTSafetyImports)
		r.Get("/api/ot-safety-imports/{id}", h.GetOTSafetyImport)
```

Immediately after the existing `remote-access-imports` POST route, add:

```go
		r.With(auth.RequirePermission(auth.CanImportOTSafetyConfig)).Post("/api/ot-safety-imports", h.CreateOTSafetyImport)
```

- [ ] **Step 6: Add the RBAC matrix rows**

In `orchestrator/internal/api/rbac_matrix_test.go`, immediately after the existing `remote-access-imports` GET rows, add:

```go
	{http.MethodGet, "/api/ot-safety-imports", tierAny, ""},
	{http.MethodGet, "/api/ot-safety-imports/{id}", tierAny, ""},
```

Immediately after the existing `remote-access-imports` POST row, add:

```go
	{http.MethodPost, "/api/ot-safety-imports", tierPermission, auth.CanImportOTSafetyConfig},
```

- [ ] **Step 7: Run `go build` and the tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run "TestRBACMatrix|TestCreateOTSafetyImport|TestListAndGetOTSafetyImport" -v`
Expected: `go build` clean; tests PASS, including the no-drift RBAC matrix.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/auth/permissions.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go orchestrator/internal/api/otsafety_handlers.go orchestrator/internal/api/otsafety_handlers_test.go
git commit -m "feat(api): add OT safety import endpoints"
git push
```

---

### Task 5: `internal/api` — Extend `/api/network-paths` with Boundary-Violation Detection

**Files:**
- Modify: `orchestrator/internal/api/networkpath_handlers.go` (read in full first -- its exact current structure, lines 1-192, was already read and quoted verbatim during this plan's own grounding; re-read it anyway, since other work may have touched it since)
- Test: `orchestrator/internal/api/networkpath_handlers_test.go` (add to the existing file; read it first to follow its established test-helper conventions)

**Interfaces:**
- Consumes: `otsafety.ValidateRequiredTransits`/`TransitViolation` (Task 1); `db.GetOTSafetyImport` (Task 3); `h.CreateOTSafetyImport` (Task 4, for the test's own import-creation helper).
- Produces: `FindNetworkPaths`'s request gains `OTSafetyImportID string` json:"otSafetyImportId,omitempty"`; its response gains `TransitViolations []otsafety.TransitViolation` `json:"transitViolations,omitempty"`.

- [ ] **Step 1: Write the failing tests**

Add to `orchestrator/internal/api/networkpath_handlers_test.go` (following whatever topology-import-creation test helper that file already defines -- do not redefine one if it exists):

```go
// TestFindNetworkPaths_BypassRoute_TransitViolationAttached pins
// Phase 7A's boundary-violation detection: a direct route between two
// zones that bypasses a declared RequiredTransit's ViaZone must
// surface as a transitViolation, without altering the path's own
// State.
func TestFindNetworkPaths_BypassRoute_TransitViolationAttached(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpath-op-bypass", "pw12345678", string(auth.RoleAnalyst), true)

		topoBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "ot", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{
				{"fromZone": "corporate", "toZone": "ot"},
			},
		}
		tb, _ := json.Marshal(topoBody)
		tReq := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(tb), auth.RoleAnalyst, userID)
		tRec := callAuthed(h.CreateNetworkTopologyImport, tReq)
		if tRec.Code != http.StatusCreated {
			t.Fatalf("create topology import: status = %d, body = %s", tRec.Code, tRec.Body.String())
		}
		var topoCreated struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(tRec.Body.Bytes(), &topoCreated); err != nil {
			t.Fatalf("decode: %v", err)
		}

		safetyBody := map[string]any{
			"sourceType": "manual",
			"requiredTransits": []map[string]any{
				{"canonicalId": "rt-1", "fromZone": "corporate", "toZone": "ot", "viaZone": "dmz"},
			},
			"limitations": []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		if sRec.Code != http.StatusCreated {
			t.Fatalf("create ot safety import: status = %d, body = %s", sRec.Code, sRec.Body.String())
		}
		var safetyCreated struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(sRec.Body.Bytes(), &safetyCreated); err != nil {
			t.Fatalf("decode: %v", err)
		}

		body := map[string]any{
			"topologyImportId": topoCreated.ID,
			"otSafetyImportId": safetyCreated.ID,
			"sourceHost":       "10.0.1.5",
			"destHost":         "10.0.2.5",
			"port":             443,
			"protocol":         "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results           []networkpath.PathResult        `json:"results"`
			TransitViolations []otsafety.TransitViolation `json:"transitViolations"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.TransitViolations) != 1 {
			t.Fatalf("transitViolations = %v, want exactly 1 -- the direct corporate->ot route bypasses the required dmz zone", resp.TransitViolations)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
	})
}

// TestFindNetworkPaths_OmittingOTSafetyImportID_BehaviorUnchanged pins
// this plan's own Global Constraint: an existing caller that never
// supplies otSafetyImportId gets exactly the pre-Phase-7A response
// shape, with no transitViolations field at all.
func TestFindNetworkPaths_OmittingOTSafetyImportID_BehaviorUnchanged(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpath-op-unchanged", "pw12345678", string(auth.RoleAnalyst), true)

		topoBody := map[string]any{
			"sourceType": "manual",
			"zones": []map[string]any{
				{"name": "corporate", "cidrs": []string{"10.0.1.0/24"}},
				{"name": "ot", "cidrs": []string{"10.0.2.0/24"}},
			},
			"edges": []map[string]any{
				{"fromZone": "corporate", "toZone": "ot"},
			},
		}
		tb, _ := json.Marshal(topoBody)
		tReq := authedRequest(t, http.MethodPost, "/api/network-topology-imports", bytes.NewReader(tb), auth.RoleAnalyst, userID)
		tRec := callAuthed(h.CreateNetworkTopologyImport, tReq)
		var topoCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(tRec.Body.Bytes(), &topoCreated)

		body := map[string]any{
			"topologyImportId": topoCreated.ID,
			"sourceHost":       "10.0.1.5",
			"destHost":         "10.0.2.5",
			"port":             443,
			"protocol":         "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindNetworkPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if _, present := raw["transitViolations"]; present {
			t.Fatalf("response unexpectedly contains transitViolations when otSafetyImportId was never supplied: %s", rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestFindNetworkPaths_BypassRoute_TransitViolationAttached|TestFindNetworkPaths_OmittingOTSafetyImportID_BehaviorUnchanged" -v`
Expected: FAIL -- the request/response types don't yet have the new fields (either a compile error on `otSafetyImportId`/`transitViolations` not existing in the JSON round-trip, or a correctly-passing-for-the-wrong-reason result; confirm by reading the actual failure, not assuming).

- [ ] **Step 3: Extend `networkpath_handlers.go`**

Add `"github.com/audspect/bas/internal/otsafety"` to the import block. Add one field to `networkPathRequest`:

```go
type networkPathRequest struct {
	TopologyImportID string `json:"topologyImportId"`
	PolicyImportID   string `json:"policyImportId,omitempty"`
	DiscoveryRunID   string `json:"discoveryRunId,omitempty"`
	OTSafetyImportID string `json:"otSafetyImportId,omitempty"`
	SourceHost       string `json:"sourceHost"`
	DestHost         string `json:"destHost"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol,omitempty"`
	MaxHops          int    `json:"maxHops,omitempty"`
}
```

Add one field to `networkPathResponse`:

```go
type networkPathResponse struct {
	Results           []networkpath.PathResult        `json:"results"`
	SearchExhausted   bool                             `json:"searchExhausted,omitempty"`
	TransitViolations []otsafety.TransitViolation `json:"transitViolations,omitempty"`
}
```

In `FindNetworkPaths`, after the existing `routes, exhausted, err := networktopology.FindCandidateRoutes(...)` block and before building `results`, add:

```go
	var transitViolations []otsafety.TransitViolation
	if req.OTSafetyImportID != "" {
		safety, err := db.GetOTSafetyImport(r.Context(), h.db, req.OTSafetyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "ot safety import not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		transitViolations = otsafety.ValidateRequiredTransits(routes, safety.RequiredTransits)
	}
```

Change the final `respond(w, networkPathResponse{Results: results, SearchExhausted: exhausted})` to:

```go
	respond(w, networkPathResponse{Results: results, SearchExhausted: exhausted, TransitViolations: transitViolations})
```

Nothing else in the function changes. When `req.OTSafetyImportID == ""` (every caller today), `transitViolations` stays `nil`, and `omitempty` drops the field from the JSON response entirely -- byte-for-byte unchanged from before this task.

- [ ] **Step 4: Run the tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestFindNetworkPaths" -v`
Expected: PASS, including every pre-existing `TestFindNetworkPaths_*` test alongside the two new ones -- proving the extension is genuinely additive.

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/api/networkpath_handlers.go orchestrator/internal/api/networkpath_handlers_test.go
git commit -m "feat(api): add OT boundary-violation detection to network-paths"
git push
```

---

### Task 6: `internal/api` — Active-Test Safety Gating on Discovery/DNS/Transport Checks

**Files:**
- Modify: `orchestrator/internal/api/networkdiscovery_handlers.go` (full current content already read during this plan's grounding, lines 1-160)
- Modify: `orchestrator/internal/api/networkdnscheck_handlers.go` (full current content already read, lines 1-131)
- Modify: `orchestrator/internal/api/networktransportcheck_handlers.go` (full current content already read, lines 1-130)
- Test: `orchestrator/internal/api/networkdiscovery_handlers_test.go`, `orchestrator/internal/api/networkdnscheck_handlers_test.go`, `orchestrator/internal/api/networktransportcheck_handlers_test.go` (add to each existing file)

**Interfaces:**
- Consumes: `otsafety.ActiveTestAuthorization`/`CheckActiveTestAuthorization` (Task 2); `db.GetNetworkTopologyImport` (existing, Phase 3); `db.GetOTSafetyImport` (Task 3); `h.CreateOTSafetyImport`/`h.CreateNetworkTopologyImport` (Task 4/existing, for test helpers).
- Produces: all three `Trigger*` handlers gain the same three optional request fields (`topologyImportId`, `otSafetyImportId`, `activeTestAuthorization`) and the same pre-execution gating behavior.

This task gets full Review-Focus-level test coverage on **one** representative handler (`TriggerNetworkDiscoveryRun`, chosen because it has the simplest, single-shaped target list) and a smaller "the gate is actually wired" smoke test (reject-without-authorization, permit-with-authorization) on the other two -- `otsafety.CheckActiveTestAuthorization`'s own exhaustive edge-case matrix was already proven in Task 2's unit tests, so repeating all of it three times at the handler level would be pure duplication, not additional coverage.

- [ ] **Step 1: Write the failing tests for `TriggerNetworkDiscoveryRun`**

Add to `orchestrator/internal/api/networkdiscovery_handlers_test.go` (read it first for its existing target-fixture conventions):

```go
// TestTriggerNetworkDiscoveryRun_TargetInSensitiveZone_NoAuth_Rejected
// and its sibling tests below pin Task 6's wiring of
// otsafety.CheckActiveTestAuthorization into the discovery-run
// handler -- the exhaustive edge-case matrix itself is Task 2's.
func TestTriggerNetworkDiscoveryRun_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newTestHandlerWithVantagePoint(t, pool) // use whatever existing helper this file's other tests already use to get a Handler with a configured vantage point; do not invent a new one
		userID := seedUser(t, pool, "discovery-op-ot", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createNetworkTopologyImportForTest(t, h, userID,
			[]map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}}, []map[string]any{})
		safetyBody := map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		var safetyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sRec.Body.Bytes(), &safetyCreated)

		body := map[string]any{
			"targets":          []map[string]any{{"host": "10.0.2.5", "port": 502}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- a target in a declared sensitive zone with no authorization must be rejected", rec.Code, rec.Body.String())
		}
	})
}

func TestTriggerNetworkDiscoveryRun_TargetInSensitiveZone_Authorized_Permitted(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newTestHandlerWithVantagePoint(t, pool)
		userID := seedUser(t, pool, "discovery-op-ot-auth", "pw12345678", string(auth.RoleAnalyst), true)

		topoID := createNetworkTopologyImportForTest(t, h, userID,
			[]map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}}, []map[string]any{})
		safetyBody := map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		var safetyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sRec.Body.Bytes(), &safetyCreated)

		body := map[string]any{
			"targets":          []map[string]any{{"host": "10.0.2.5", "port": 502}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
			"activeTestAuthorization": map[string]any{
				"authorized": true,
				"signOff":    "approved by J.Singh, CHG-1234",
			},
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- a valid authorization must permit the run", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerNetworkDiscoveryRun_OmittingSafetyFields_BehaviorUnchanged
// pins this plan's Global Constraint for this handler specifically.
func TestTriggerNetworkDiscoveryRun_OmittingSafetyFields_BehaviorUnchanged(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newTestHandlerWithVantagePoint(t, pool)
		userID := seedUser(t, pool, "discovery-op-plain", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": 1}}}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-discovery-runs", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerNetworkDiscoveryRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- omitting the new safety fields must behave exactly as before this task", rec.Code, rec.Body.String())
		}
	})
}
```

(If this file has no existing `newTestHandlerWithVantagePoint`/`createNetworkTopologyImportForTest`-equivalent helper, grep the file and its siblings first for whatever name the existing `TestTriggerNetworkDiscoveryRun_*` tests actually use to get a vantage-point-configured `Handler` and a topology import, and use those exact names -- do not invent new helpers duplicating existing ones.)

- [ ] **Step 2: Run the tests to verify they fail**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestTriggerNetworkDiscoveryRun_TargetInSensitiveZone|TestTriggerNetworkDiscoveryRun_OmittingSafetyFields" -v`
Expected: FAIL -- compile error (new JSON fields not yet present on the inline request struct) or a wrong-status failure; confirm by reading the actual output.

- [ ] **Step 3: Extend `networkdiscovery_handlers.go`**

Add `"github.com/audspect/bas/internal/otsafety"` and `"github.com/audspect/bas/internal/networktopology"` to the import block. Change the inline request struct and insert the gating check immediately after the existing per-target validation loop and before `opts := networkgraph.DiscoveryOptions{}`:

```go
	var req struct {
		Targets                 []networkgraph.Target             `json:"targets"`
		TimeoutPerTargetMs      int                                `json:"timeoutPerTargetMs,omitempty"`
		TopologyImportID        string                             `json:"topologyImportId,omitempty"`
		OTSafetyImportID        string                             `json:"otSafetyImportId,omitempty"`
		ActiveTestAuthorization *otsafety.ActiveTestAuthorization `json:"activeTestAuthorization,omitempty"`
	}
```

```go
	if req.TopologyImportID != "" && req.OTSafetyImportID != "" {
		topo, err := db.GetNetworkTopologyImport(r.Context(), h.db, req.TopologyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "network topology import not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		safety, err := db.GetOTSafetyImport(r.Context(), h.db, req.OTSafetyImportID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "ot safety import not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hosts := make([]string, 0, len(req.Targets))
		for _, t := range req.Targets {
			hosts = append(hosts, t.Host)
		}
		matchedZones, err := otsafety.CheckActiveTestAuthorization(hosts, topo, safety, req.ActiveTestAuthorization)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(matchedZones) > 0 {
			h.auditLog(r, "networkdiscovery.activeTestAuthorized", "", map[string]any{"sensitiveZones": matchedZones, "signOff": req.ActiveTestAuthorization.SignOff}, "ok")
		}
	}
```

`networktopology` is imported for type clarity even though this snippet only calls `db.GetNetworkTopologyImport`/`otsafety.CheckActiveTestAuthorization`, both of which already return/accept its types by value from `db`/`otsafety` -- add the import only if `go build` actually requires it (it is not referenced by name in this exact snippet); omit it otherwise rather than leaving an unused import.

- [ ] **Step 4: Run the tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestTriggerNetworkDiscoveryRun" -v`
Expected: PASS, including every pre-existing `TestTriggerNetworkDiscoveryRun_*` test alongside the three new ones.

- [ ] **Step 5: Write the failing smoke tests for `TriggerDNSSecurityCheckRun`**

Add to `orchestrator/internal/api/networkdnscheck_handlers_test.go`:

```go
func TestTriggerDNSSecurityCheckRun_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newTestHandlerWithVantagePoint(t, pool)
		userID := seedUser(t, pool, "dnscheck-op-ot", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForTest(t, h, userID,
			[]map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}}, []map[string]any{})
		safetyBody := map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		var safetyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sRec.Body.Bytes(), &safetyCreated)

		body := map[string]any{
			"checks":           []map[string]any{{"checkType": "resolver", "target": map[string]any{"host": "10.0.2.5", "port": 53}, "queryDomain": "example.com"}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

// TestTriggerDNSSecurityCheckRun_DNSSECCheckWithNoTarget_NeverGated
// pins Spec §6's own carve-out: a dnssec-type check carries no IP
// target at all (enforced by existing validation), so it has nothing
// to resolve to a zone and must never be gated even when
// topologyImportId/otSafetyImportId are both supplied.
func TestTriggerDNSSecurityCheckRun_DNSSECCheckWithNoTarget_NeverGated(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newTestHandlerWithVantagePoint(t, pool)
		userID := seedUser(t, pool, "dnscheck-op-dnssec", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForTest(t, h, userID,
			[]map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}}, []map[string]any{})
		safetyBody := map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		var safetyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sRec.Body.Bytes(), &safetyCreated)

		body := map[string]any{
			"checks":           []map[string]any{{"checkType": "dnssec", "queryDomain": "example.com"}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/dns-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerDNSSecurityCheckRun, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s, want 201 -- a dnssec check has no IP target and must never be gated", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 6: Extend `networkdnscheck_handlers.go`**

Same shape as Step 3, adapted to this handler's `Checks []networkdns.DNSCheckRequest` field: add the same three new fields to the inline request struct, and the same gating block after the existing per-check validation loop, except `hosts` is built by iterating `req.Checks` and collecting only non-empty `c.Target.Host` (a `dnssec` check's `Target` is already validated elsewhere to be the zero value, so its `Target.Host` is always `""` and is simply skipped):

```go
		hosts := make([]string, 0, len(req.Checks))
		for _, c := range req.Checks {
			if c.Target.Host != "" {
				hosts = append(hosts, c.Target.Host)
			}
		}
```

Use this file's own existing audit-log action-name convention (`"networkdns.run"`, per its existing `h.auditLog` calls) suffixed `.activeTestAuthorized`, exactly mirroring Step 3's pattern.

- [ ] **Step 7: Run the tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestTriggerDNSSecurityCheckRun" -v`
Expected: PASS, including every pre-existing test for this handler.

- [ ] **Step 8: Write the failing smoke test for `TriggerTransportSecurityCheckRun`, then extend the handler the same way**

Add to `orchestrator/internal/api/networktransportcheck_handlers_test.go`:

```go
func TestTriggerTransportSecurityCheckRun_TargetInSensitiveZone_NoAuth_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newTestHandlerWithVantagePoint(t, pool)
		userID := seedUser(t, pool, "transportcheck-op-ot", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createNetworkTopologyImportForTest(t, h, userID,
			[]map[string]any{{"name": "ot", "cidrs": []string{"10.0.2.0/24"}}}, []map[string]any{})
		safetyBody := map[string]any{
			"sourceType":     "manual",
			"sensitiveZones": []map[string]any{{"zoneName": "ot", "tier": "ot"}},
			"limitations":    []string{"zone names are not cross-validated against a real network-topology import"},
		}
		sb, _ := json.Marshal(safetyBody)
		sReq := authedRequest(t, http.MethodPost, "/api/ot-safety-imports", bytes.NewReader(sb), auth.RoleAnalyst, userID)
		sRec := callAuthed(h.CreateOTSafetyImport, sReq)
		var safetyCreated struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sRec.Body.Bytes(), &safetyCreated)

		body := map[string]any{
			"checks":           []map[string]any{{"checkType": "cleartext", "target": map[string]any{"host": "10.0.2.5", "port": 23}}},
			"topologyImportId": topoID,
			"otSafetyImportId": safetyCreated.ID,
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/transport-security-checks", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.TriggerTransportSecurityCheckRun, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}
```

Extend `networktransportcheck_handlers.go` identically to Step 3/6 -- this handler's `Checks []networktransport.TransportCheckRequest` always has a non-empty `Target.Host` (already enforced by its own existing validation), so `hosts` is simply `for _, c := range req.Checks { hosts = append(hosts, c.Target.Host) }` with no empty-skip needed.

- [ ] **Step 9: Run the tests to verify they pass**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestTriggerTransportSecurityCheckRun" -v`
Expected: PASS, including every pre-existing test for this handler.

- [ ] **Step 10: Run the full scoped suite for this task**

Check free memory first.

Run: `cd orchestrator && go test ./internal/api/... -run "TestTriggerNetworkDiscoveryRun|TestTriggerDNSSecurityCheckRun|TestTriggerTransportSecurityCheckRun|TestRBACMatrix" -v`
Expected: PASS -- all green, including the no-drift RBAC matrix (this task adds no new routes, so the matrix itself should be untouched, but re-running it here confirms nothing regressed).

- [ ] **Step 11: Commit**

```bash
git add orchestrator/internal/api/networkdiscovery_handlers.go orchestrator/internal/api/networkdiscovery_handlers_test.go orchestrator/internal/api/networkdnscheck_handlers.go orchestrator/internal/api/networkdnscheck_handlers_test.go orchestrator/internal/api/networktransportcheck_handlers.go orchestrator/internal/api/networktransportcheck_handlers_test.go
git commit -m "feat(api): add OT active-test safety gating to discovery/dns/transport checks"
git push
```

---

## Final Combined Gate (run once, after Task 6)

Check free memory first.

```bash
cd orchestrator
go build ./...
go vet ./internal/otsafety/... ./internal/db/... ./internal/api/... ./internal/auth/...
go test ./internal/otsafety/... -v
go test ./internal/db/... -run "TestInsertAndGetOTSafetyImport|TestGetOTSafetyImport_NotFound|TestListOTSafetyImports" -v
go test ./internal/api/... -run "TestRBACMatrix|TestCreateOTSafetyImport|TestListAndGetOTSafetyImport|TestFindNetworkPaths|TestTriggerNetworkDiscoveryRun|TestTriggerDNSSecurityCheckRun|TestTriggerTransportSecurityCheckRun" -v
```

Expected: `go build`/`go vet` clean; all scoped test runs green.

## Execution Handoff

This phase is implemented inline (Native execution), the same way every prior phase this session (1, 2A, 3, 4, 5A, 5B, 6A, 6B) was: work happens directly on `main`, no worktree, no feature branch, with `git push` after every commit. This is a standing session convention, carried forward rather than re-selected.

Plan complete and saved to `docs/superpowers/plans/2026-10-14-network-bas-phase7a-ot-ics-safety.md`. Please review the plan — does it capture what you want?
