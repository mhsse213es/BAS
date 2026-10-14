# Network BAS Mastery Phase 7B: Healthcare Network-Isolation Validation — Design Spec

## 1. Goal

Add the second of Phase 7's three sector-specific sub-projects (7A OT/ICS safety gating is done; 7C India/UAE regulatory mapping is next): healthcare network-isolation validation, per the master spec (`docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md`, Phase 7 section) and `network.txt` §2.3.

`network.txt` §2.3 names six healthcare priorities:
1. Medical-device and clinical-system network visibility.
2. Isolation of patient-care, clinical, administrative, guest, and management networks.
3. Restricted access to critical clinical applications and sensitive information systems.
4. Validation of remote vendor access and third-party connectivity.
5. Safe testing that avoids disrupting patient care or medical-device operation.
6. Evidence-backed identification of unnecessary exposure and network access weaknesses.

Priorities 3, 4, and 5 are already covered, essentially unchanged, by existing infrastructure (§2 below). The one genuinely new capability this phase adds is priorities 1, 2, and 6: a declarative "these zone pairs must be isolated" expectation, checked against Phase 3's existing path-classification evidence and reported as a pass/fail per pair — the same shape Phase 4's `network_control_expectations` already uses for firewall/IDS outcomes, applied here to zone-pair isolation instead.

## 2. Relationship to Existing Phases — What's Reused Unchanged

- **`internal/otsafety` (Phase 7A)** gains one new constant, `TierClinical`, alongside the existing `TierOT`. `CheckActiveTestAuthorization` and `ValidateRequiredTransits` are both already tier-agnostic — they operate on `SensitiveZone`/`RequiredTransit` values without caring what `Tier` actually is — so this one-constant change, plus widening `validateOTSafetyImport`'s accepted-tier check, is the *entire* 7A-side change. It covers:
  - Priority 5 (safe testing): a healthcare `OTSafetyImport` declaring clinical/patient-care zones with `Tier: TierClinical` gates `TriggerNetworkDiscoveryRun`/`TriggerDNSSecurityCheckRun`/`TriggerTransportSecurityCheckRun` exactly as an OT import already does.
  - Priority 3 and 4 (restricted/vendor access): a `RequiredTransit` declaring "vendor-remote-access zone → clinical zone must transit the DMZ" reuses `ValidateRequiredTransits` unchanged — `RequiredTransit` was never OT-specific to begin with (just named `FromZone`/`ToZone`/`ViaZone`).
- **`internal/networktopology` (Phase 3)** and **`internal/remoteaccess` (Phase 6B)** are both reused read-only, exactly as `otsafety`/`cloudpath`/`networkpath` already reuse them — this phase adds zero new routing/adjacency logic. `internal/networkpolicy` (Phase 2A) and `internal/networkgraph` (Phase 1) observation evidence are reused unchanged too, via the same composition `networkpath.ComposeHop`/`AggregatePath` already perform for `/api/network-paths`.
- **No new composition package.** Per the master spec's own words for Phase 7: "Does not introduce a second scoring or reporting system." The new `internal/zoneisolation` package (§3) holds only the declarative import type and a pure classification function; it never computes a route or composes evidence itself.

## 3. Package: `internal/zoneisolation`

### 3.1 Data Model

```go
package zoneisolation

const MaxZonePairIsolationsPerImport = 500

// ZonePairIsolation declares that ZoneA and ZoneB (referenced by name
// only, never cross-validated against a real networktopology import --
// same discipline as otsafety.SensitiveZone/RequiredTransit) are
// expected to have no network path between them at all, in either
// direction.
type ZonePairIsolation struct {
	CanonicalID string `json:"canonicalId"`
	ZoneA       string `json:"zoneA"`
	ZoneB       string `json:"zoneB"`
	Note        string `json:"note,omitempty"`
}

// IsolationImport is one auditable, versioned snapshot -- the same
// shape discipline as otsafety.OTSafetyImport / remoteaccess.RemoteAccessImport.
type IsolationImport struct {
	ID                 string              `json:"id,omitempty"`
	SourceType         string              `json:"sourceType"`
	ImportedBy         string              `json:"importedBy,omitempty"`
	ImportedAt         time.Time           `json:"importedAt,omitempty"`
	ConfigVersion      string              `json:"configVersion,omitempty"`
	ZonePairIsolations []ZonePairIsolation `json:"zonePairIsolations"`
	Limitations        []string            `json:"limitations,omitempty"`
}
```

Import validation mirrors `otsafety.validateOTSafetyImport` exactly: `ZoneA`/`ZoneB` non-empty, cap enforcement, and `Limitations` required non-empty whenever any `ZonePairIsolation` is declared (zone names are never cross-validated against a real topology import, so the caller must say so).

### 3.2 Isolation Classification

```go
type IsolationSeverity string

const (
	// SeverityConfirmedViolation: a real observation demonstrates the
	// pair is actually reachable (cloudgraph.Observed). The strongest,
	// least disputable finding.
	SeverityConfirmedViolation IsolationSeverity = "confirmed-violation"

	// SeverityUnconfirmedExposure: policy/routing evidence permits a
	// path but nothing has actually observed it being used
	// (cloudgraph.PolicySupported/Candidate/ConditionallyReachable).
	// Deliberately reported as a DISTINCT, weaker severity from
	// SeverityConfirmedViolation -- never collapsed into it -- per this
	// initiative's standing "never let a weaker signal masquerade as a
	// stronger one" discipline (see Phase 2A's 0.0.0.0/0 lesson and
	// Phase 3's own locked interpretation table).
	SeverityUnconfirmedExposure IsolationSeverity = "unconfirmed-exposure"

	// SeverityNoViolationFound: cloudgraph.Blocked, or cloudgraph.Unknown
	// (no known route at all). These are NOT the same claim and must
	// carry different Limitations text -- "no known route" is never
	// reported as "confirmed isolated" (Phase 3's own locked principle:
	// missing topology data is not proof of isolation).
	SeverityNoViolationFound IsolationSeverity = "no-violation-found"
)

// IsolationCheckResult is one declared pair's classified result,
// carrying the full composed path as its evidence.
type IsolationCheckResult struct {
	ZonePairIsolation ZonePairIsolation      `json:"zonePairIsolation"`
	Severity          IsolationSeverity      `json:"severity"`
	Path              networkpath.PathResult `json:"path"`
	Limitations       string                 `json:"limitations,omitempty"`
}

// ClassifyIsolation is a pure function of an already-composed path --
// it never finds a route or composes evidence itself (mirrors
// otsafety.ValidateRequiredTransits's own decoupling from whichever
// routing engine produced the routes it checks).
func ClassifyIsolation(pair ZonePairIsolation, path networkpath.PathResult) IsolationCheckResult
```

Classification by `path.State` (the real `cloudgraph.PathState` values reachable from `networkpath.ComposeHop`/`AggregatePathState`, confirmed by reading `compose.go`):

| `path.State` | Severity | Limitations |
|---|---|---|
| `Observed` | `confirmed-violation` | (none beyond the path's own) |
| `PolicySupported` / `Candidate` / `ConditionallyReachable` | `unconfirmed-exposure` | (none beyond the path's own) |
| `Blocked` | `no-violation-found` | (none beyond the path's own) |
| `Unknown` | `no-violation-found` | `"no known route was found between these zones -- this is not proof of isolation, only an absence of evidence"` appended |

## 4. Evidence Composition — New Endpoint, No New Composition Package

`POST /api/isolation-checks`:

```go
type isolationCheckRequest struct {
	TopologyImportID      string `json:"topologyImportId"`
	IsolationImportID     string `json:"isolationImportId"`
	PolicyImportID        string `json:"policyImportId,omitempty"`
	DiscoveryRunID        string `json:"discoveryRunId,omitempty"`
	RemoteAccessImportID  string `json:"remoteAccessImportId,omitempty"`
	Port                  int    `json:"port,omitempty"`
	Protocol              string `json:"protocol,omitempty"`
	MaxHops               int    `json:"maxHops,omitempty"`
}

type isolationCheckResponse struct {
	Results         []zoneisolation.IsolationCheckResult `json:"results"`
	SearchExhausted bool                                  `json:"searchExhausted,omitempty"`
}
```

`TopologyImportID` and `IsolationImportID` are both required (400 if either is missing).

**Why `composeNetworkPathHop` cannot be reused verbatim (found during plan-grounding, folded back into this spec):** `composeNetworkPathHop`/`ComposeHop`/`networkcorrelation.findMatchingObservation` are all fundamentally host-and-port-specific — policy evaluation needs a concrete port to check a rule's port range, and `findMatchingObservation`'s own doc comment states outright that "a zone-named destination has no single host to match against an observation's Target.Host." Zone-pair isolation checking has no host, and (per the locked Option B decision) deliberately no per-pair port either. The fix: resolve the **destination zone's declared CIDRs** from the loaded `topo.Zones` (each `networktopology.Zone` already carries `CIDRs []string`) and evaluate policy/observation correlation against each of the zone's CIDRs in turn, using the request-level `Port`/`Protocol` (applied uniformly across the whole batch — omitted, they default to `0`/`""`, which only matches a policy rule with no port restriction at all; this is a documented, honest limitation, not a defect, consistent with this initiative's "never claim more than the evidence shows" discipline).

For each `ZonePairIsolation` in the loaded `IsolationImport`:

1. Resolve routes: if `RemoteAccessImportID` is supplied, load the `RemoteAccessImport` and call `remoteaccess.FindCandidateRemoteAccessRoutes(topo, remote, pair.ZoneA, pair.ZoneB, maxHops)`; otherwise call `networktopology.FindCandidateRoutes(topo, pair.ZoneA, pair.ZoneB, maxHops)`. `remoteaccess.RoutePath` and `networktopology.RoutePath` are both `[]string` underneath (confirmed by reading both `routes.go` files) — the handler normalizes whichever one it gets into a plain `[]string` before composition, same way `FindNetworkPaths` already treats `networktopology.RoutePath` as an iterable `[]string`.
2. Resolve `pair.ZoneB`'s declared CIDRs by scanning `topo.Zones` for the matching zone name. For each candidate route, and for each of `pair.ZoneB`'s CIDRs, build a `networkpolicy.PolicyQuery{SourceZone: route[i], DestCIDR: <the CIDR>, Port: req.Port, Protocol: req.Protocol}`, evaluate it via `networkpolicy.EvaluatePolicyMatrix` (when `policyImportId` was supplied), and build one `networkpath.HopResult` via `networkpath.ComposeHop(fromZone, toZone, routeDeclared, policyEval, observations)` — reusing `ComposeHop` completely unchanged, just called once per (hop × destination-CIDR) pair instead of once per hop. `observations` is the discovery run's observation list (when `discoveryRunId` was supplied), filtered the same way `composeNetworkPathHop` already filters by port before correlation can match. Feed the *entire* resulting slice of per-CIDR `HopResult`s for a route into `networkpath.AggregatePath` — this reuses `AggregatePathState`'s existing worst-state ranking unchanged to pick the most severe result across however many CIDRs the destination zone declares, with zero new ranking logic. When the destination zone has no declared CIDRs at all, this reduces to exactly one `ComposeHop` call with an empty `DestCIDR`, which already correctly falls through to `Unknown` via `ComposeHop`'s existing `policyEval == nil`/`!routeDeclared` branches.
3. When zero candidate routes exist at all, this produces the same "no declared route" `Unknown` `PathResult` `FindNetworkPaths` already produces for its own zero-route case — reused, not reinvented.
4. `zoneisolation.ClassifyIsolation(pair, pathResult)` → one `IsolationCheckResult`.

`SearchExhausted` is true if *any* pair's route search hit its step budget (same "truncated search, absence not proven" meaning `/api/network-paths` already carries, just aggregated across the whole batch rather than per-pair, since a per-pair flag would need its own field on `IsolationCheckResult` that nothing in this phase's acceptance criteria requires yet).

A pair whose `ZoneA`/`ZoneB` doesn't resolve to any declared topology zone is **not** a 400 for the whole request — `FindCandidateRoutes`/`FindCandidateRemoteAccessRoutes` return an error for an unknown zone name; the handler catches that per-pair and reports `SeverityNoViolationFound` with a `"zone name not found in the supplied topology import"` limitation, letting every other pair in the same import still evaluate. This mirrors `otsafety`'s own "zone names are never cross-validated" philosophy: a typo in one pair must not block the rest of the batch.

## 5. Safety-Gating Integration

None required for this endpoint. `/api/isolation-checks` is purely evaluative over already-collected evidence (topology, policy, prior discovery observations, remote-access declarations) — it never triggers a new active probe, so it needs no `otsafety` gate of its own, exactly as `/api/network-paths` and `/api/network-control-verifications` (Phase 4) need none. The `otsafety` gate already applies upstream, at the point where `TriggerNetworkDiscoveryRun`/DNS/transport checks are triggered against a clinical-tier sensitive zone (§2 above).

## 6. Persistence & API

New table `zone_isolation_imports`, store (`EnsureZoneIsolationImportSchema`/`InsertZoneIsolationImport`/`GetZoneIsolationImport`/`ListZoneIsolationImports`), new permission `CanImportZoneIsolationConfig = "zone-isolation:import"` (Admin+Analyst, same placement as `CanImportOTSafetyConfig`), `POST/GET /api/zone-isolation-imports[/{id}]` — all byte-for-byte the same pattern as `ot_safety_imports`/`ot-safety-imports` from Phase 7A. `POST /api/isolation-checks` requires no new permission beyond standard authentication, matching `/api/network-paths`'s own baseline-only gate.

## 7. Review Focus

1. A demonstrated-reachable pair reports `confirmed-violation`; a policy-permitted-but-unobserved pair reports `unconfirmed-exposure`, and the two are never conflated into one severity.
2. A policy-denied pair and a no-known-route pair both report `no-violation-found`, but only the latter carries the "not proof of isolation" limitation — a reasonable reader must never be able to mistake "no evidence found" for "actively confirmed isolated."
3. A multi-pair `IsolationImport` where exactly one pair violates must classify every pair correctly — no cross-pair leakage.
4. A zone pair bridged *only* by an active VPN tunnel (no physical topology edge) must classify as `no-violation-found` when `remoteAccessImportId` is omitted, and as `confirmed-violation`/`unconfirmed-exposure` when it's supplied — this is the one end-to-end test that actually proves tunnel-aware isolation checking works, not just compiles.
5. `otsafety`'s tier validation accepts `TierClinical` exactly as it already accepts `TierOT`, and still rejects any other value — proving the tier extension is additive, not a loosening of the existing check.

## 8. Safety Constraints

Carried forward from `network.txt` §9 and the master spec's Phase 7 section, unchanged from 7A: explicit authorization and defined scope for every run; no destructive actions; stricter safeguards for healthcare environments (now implemented via `TierClinical`); a successful isolation check is never presented as proof of regulatory compliance without qualified review (`network.txt` §3) — this phase produces evidence-backed findings, not a compliance attestation.

## 9. Explicitly Deferred

- Zone-classification taxonomy (patient-care/clinical/administrative/guest/management as a reusable enum + isolation matrix) — deferred per the locked Option B decision; may be revisited if a real customer topology shows explicit pairs don't scale.
- Medical-device-specific protocol visibility (DICOM, HL7, proprietary clinical-device protocols) — out of scope, same category as 7A's deferred industrial-protocol visibility.
- Per-pair `searchExhausted` flags — deferred until an acceptance criterion needs them.
- Healthcare-specific regulatory mapping (HIPAA-equivalent, etc.) — belongs to Phase 7C's regulatory-mapping layer, not this phase.

## 10. Acceptance Criteria

At least one healthcare-safe test executes under `TierClinical`'s stricter safeguards (reusing 7A's existing gate), and at least one declared zone-pair isolation expectation is checked end-to-end and produces a traceable, evidence-backed `IsolationCheckResult` — including the tunnel-aware case (Review Focus #4) — matching the master spec's Phase 7 definition-of-done for the healthcare half of this phase.
