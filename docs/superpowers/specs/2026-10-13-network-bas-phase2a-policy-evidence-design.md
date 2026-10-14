# Network BAS Mastery Phase 2A: Firewall & Segmentation Policy Evidence — Design

## Status

Approved by the user in-chat, section by section, 2026-10-13. This spec covers **Phase 2A only** (normalized policy schema, evaluation, and correlation with Phase 1 evidence). Native vendor parsers (Phase 2B+) are explicitly deferred — see "Deferred" below.

## Context

Parent: `docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md` (master spec, 7-phase roadmap, three-evidence-domain architecture). Phase 1 (`docs/superpowers/specs/2026-10-13-network-bas-phase1-evidence-foundation-design.md`) delivered `internal/networkgraph` — orchestrator-originated TCP reachability evidence. Phase 1 is done, reviewed, and merged (`main`, commits `f3a99ce7`..`9ed95079`).

Phase 2 of the locked roadmap is "real firewall and segmentation validation (test matrices from real policy)." Repo survey (re-verified 2026-10-13, same conclusion as the master spec's original survey): `internal/attackpath.Segment` (`internal/attackpath/graph.go:35`) is a free-form string tag used only for same-segment-skip detection in lateral-movement analytics (`internal/attackpath/analytics.go:265`) — it is not derived from, and must not be treated as, real network policy. Every other "firewall"/"VLAN"/"NACL" reference anywhere in the repo (`internal/models/helpers.go`, `internal/pathcorrelation/remediation.go`, `internal/reporting/engine.go`) is free-form ATT&CK mitigation *prose*, not parsed or modeled policy. No CIDR-parsing helpers or policy package of any kind exist (`internal/slapolicy` is SLA policy, unrelated). This is a clean, new capability.

## Scope

**In scope (this spec, Phase 2A):**
- A vendor-agnostic normalized policy schema (zones, rules, default policy) that an operator exports or hand-translates their real on-prem/enterprise policy into.
- Policy evaluation: given an imported policy and a bounded batch of (source, destination, protocol, port) queries, compute `cloudgraph.PathState` per query via ordered rule matching.
- Evidence correlation: joining a policy evaluation against Phase 1's `networkgraph` observations by host/port, producing honestly-labeled comparisons — never a verdict stronger than the evidence supports.
- Persistence (Postgres) and an HTTP API for importing policy and reading evaluations/comparisons, following the `cloud_run`/`network_discovery` precedent exactly.

**Explicitly out of scope / deferred:**
- **Native vendor parsers** (Palo Alto, Cisco ASA, pfSense, iptables, Windows Firewall, etc.) — Phase 2B+, separate specs, selected by target-customer demand, each translating into the same canonical schema this spec defines. Not committing to any vendor family upfront; even iptables/Windows Firewall have semantics (stateful return traffic, NAT, address/service groups) a naive source/dest/port/action schema would misrepresent, which is exactly why Phase 2A's schema has an explicit `Unresolved` escape hatch (see below) rather than forcing every future parser's edge cases into Allow/Deny now.
- **Cloud security groups / NSGs** — deferred to Phase 6, which already owns extending `cloudgraph` with real cloud network topology. Phase 2A's `networkpolicy` package must not be extended to model cloud constructs; that boundary is deliberate.
- Live API pull from firewall management platforms (Panorama, FMC, etc.) — a possible future ingestion mode, not Phase 2A.
- A persisted 3rd "comparisons" table — correlation is computed on demand from the two already-persisted evidence sources, avoiding a cache that needs invalidation logic.

## Architecture

Three new packages, each with one clear boundary, mirroring the master spec's three-evidence-domain discipline:

- **`internal/networkpolicy`** — pure types + evaluation logic. Imports `cloudgraph.PathState`/`Provenance` (same as `networkgraph`), never imports `networkgraph`.
- **`internal/networkgraph`** — unchanged (Phase 1).
- **`internal/networkcorrelation`** (new) — the only package that imports both `networkpolicy` and `networkgraph`. Pure join/labeling function, no DB, no HTTP. This is where "correlation is reporting-layer only" is enforced structurally, not just by convention: neither evidence package can see the other, so an accidental cross-domain inference can only happen here, in one small, reviewable place.

Persistence and HTTP follow the established `cloud_run`/`network_discovery` pattern (dedicated API + Postgres, `http.MaxBytesReader` from the start, server-controlled actor identity via `auth.ClaimsFrom`, a new granular permission rather than reusing an unrelated one).

## Data Model (`internal/networkpolicy`)

```go
type Zone struct {
    Name  string
    CIDRs []string
}

type RuleAction string
const (
    ActionAllow      RuleAction = "allow"
    ActionDeny       RuleAction = "deny"
    ActionUnresolved RuleAction = "unresolved" // vendor construct the schema can't losslessly represent (NAT, stateful return traffic, service groups, etc.) -- never coerced into allow/deny
)

type Rule struct {
    ID         string
    Order      int        // evaluation walks rules in this order, first match wins -- matches real top-down packet-filter semantics
    SourceZone string     // zone name, OR SourceCIDR set directly
    SourceCIDR string
    DestZone   string
    DestCIDR   string
    Protocol   string     // "tcp", "udp", "" = any
    PortRange  string     // e.g. "443" or "1024-65535", "" = any
    Action     RuleAction
    Note       string     // required when Action == ActionUnresolved -- why this rule couldn't be losslessly translated
}

type DefaultPolicy string
const (
    DefaultAllow DefaultPolicy = "allow"
    DefaultDeny  DefaultPolicy = "deny"
)

type PolicyImport struct {
    ID             string
    SourceType     string    // e.g. "manual-normalized", future: "iptables-save", "windows-firewall-export", etc.
    ImportedBy     string    // server-controlled, never trusted from the request body
    ImportedAt     time.Time
    ConfigVersion  string    // operator-supplied version/hash of the source config, optional
    DefaultPolicy  DefaultPolicy
    Zones          []Zone
    Rules          []Rule
    Limitations    []string  // honest caveats about this translation (required to be non-empty whenever any Rule.Action == ActionUnresolved)
}
```

## Policy Evaluation (`internal/networkpolicy`)

```go
const MaxRulesPerImport = 5000
const MaxZonesPerImport = 500
const MaxPolicyQueriesPerEvaluation = 500

type PolicyQuery struct {
    SourceZone, SourceCIDR string // exactly one of these per side
    DestZone, DestCIDR     string
    Protocol               string
    Port                   int
}

type PolicyEvaluation struct {
    Query       PolicyQuery
    State       cloudgraph.PathState
    MatchedRule *Rule // nil when the default policy applied
    Provenance  cloudgraph.Provenance
    Limitations string
}

func EvaluatePolicyMatrix(imp *PolicyImport, queries []PolicyQuery) ([]PolicyEvaluation, error)
```

Algorithm per query:
1. Resolve `SourceZone`/`DestZone` (if given) to their `CIDRs`; resolve `SourceCIDR`/`DestCIDR` (if given directly) to the zone(s) whose `CIDRs` contain them. A CIDR matching more than one zone ambiguously → `Unknown`, with a limitation note naming the conflicting zones. Never guessed.
2. Walk `imp.Rules` in `Order`. The first rule whose source/dest/protocol/port match the query wins (first-match, not best-match or most-specific-match — matches real firewall semantics). Port matching: a `Rule.PortRange` of `""` matches any `PolicyQuery.Port`; a bare number (`"443"`) matches only that exact port; a `"low-high"` range (`"1024-65535"`) matches any port within `[low, high]` inclusive. A `Rule.PortRange` that fails to parse as either form is rejected at import validation time (see Safety Constraints), never silently treated as "any".
3. Map the outcome to `cloudgraph.PathState`:
   - Matched `ActionAllow`, or no match and `DefaultPolicy == DefaultAllow` → `PolicySupported`.
   - Matched `ActionDeny`, or no match and `DefaultPolicy == DefaultDeny` → `Blocked`. An explicit configured deny is real evidence of a block, held to the same evidentiary standard as Phase 1's actively-refused-connection classification — not a weaker inference.
   - Matched `ActionUnresolved` → `Unknown`, carrying `Rule.Note` into `PolicyEvaluation.Limitations`.
4. `Provenance.Confidence` reflects "policy-only claim, not a live test" (lower than Phase 1's `Observed`/`Blocked` confidence) — the mirror image of Phase 1's "a timeout isn't proof of a block": here, a policy claim isn't proof of live enforcement.
5. `EvaluatePolicyMatrix` rejects (before evaluating anything) an empty `queries`, a `queries` longer than `MaxPolicyQueriesPerEvaluation`, and an `imp` whose `Rules`/`Zones` exceed `MaxRulesPerImport`/`MaxZonesPerImport` (defense in depth — the HTTP import validation below is the primary gate).

## Evidence Correlation (`internal/networkcorrelation`)

```go
type ComparisonLabel string
const (
    ConsistentAllow         ComparisonLabel = "consistent-allow"
    DiscrepancyUnexpectedBlock ComparisonLabel = "discrepancy-unexpected-block"
    DiscrepancyUnenforcedDeny  ComparisonLabel = "discrepancy-unenforced-deny"
    ConsistentDeny           ComparisonLabel = "consistent-deny"
    Untested                ComparisonLabel = "untested"
    PolicyInconclusive      ComparisonLabel = "policy-inconclusive"
)

type ReachabilityComparison struct {
    Evaluation  networkpolicy.PolicyEvaluation
    Observation *networkgraph.NetworkObservation // nil when Untested
    Label       ComparisonLabel
}

func CorrelateReachability(evaluations []networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) []ReachabilityComparison
```

A `PolicyEvaluation` is matched to a `NetworkObservation` when the observation's `Target.Host` falls inside the evaluation's resolved destination CIDR and the ports match. Labeling table (both inputs' own `State` values, never re-derived):

| Policy state | Observed state (or none) | Label |
|---|---|---|
| `PolicySupported` | `Observed` | `consistent-allow` |
| `PolicySupported` | `Blocked` | `discrepancy-unexpected-block` |
| `Blocked` | `Observed` | `discrepancy-unenforced-deny` |
| `Blocked` | `Blocked` | `consistent-deny` |
| `PolicySupported` or `Blocked` | `Unknown` or none | `untested` |
| `Unknown` | anything | `policy-inconclusive` |

None of these labels is a security verdict by itself — `discrepancy-unenforced-deny` is "the parsed policy document and the live test disagree," not "confirmed vulnerability," because the policy input may itself be a stale or imperfect translation. The label names say "discrepancy"/"consistent", never "vulnerable"/"secure".

## HTTP API & Persistence

New permission: `CanImportNetworkPolicy = "network-policy:import"` (mirrors `CanImportOpenAEVBundle`'s naming).

- `POST /api/network-policy-imports` (gated by `CanImportNetworkPolicy`): body `{sourceType, configVersion, defaultPolicy, zones, rules, limitations}`. Validates: ≥1 zone, ≥1 rule, rule counts within caps, every CIDR parses, every `PortRange` is `""`, a bare port number, or a valid `"low-high"` range, every `Action` is a known value, every `ActionUnresolved` rule has a non-empty `Note`, and `Limitations` is non-empty whenever any rule is `ActionUnresolved`. `ImportedBy` set server-side via `auth.ClaimsFrom`, never trusted from the body. `http.MaxBytesReader` wraps the decode from the start (5 MiB cap — larger than Phase 1's 1 MiB, since a real policy document is bigger than a target list). Persists `zones`+`rules` as one `policy_data jsonb` column alongside metadata columns (not exploded into relational rows — a policy import is an atomic, versioned snapshot). Returns `201` with the import's ID.
- `GET /api/network-policy-imports`, `GET /api/network-policy-imports/{id}` — baseline-auth-only reads, same tier as Phase 1's discovery-run GETs.
- `POST /api/network-policy-evaluations` (gated by `CanImportNetworkPolicy` — evaluating is a read of imported policy but the permission boundary follows "who may work with policy data" rather than splitting it further): body `{policyImportId, queries}`, calls `EvaluatePolicyMatrix`, does not persist the evaluation result (computed fresh each call — cheap, pure function, no external I/O).
- `GET /api/network-reachability-comparisons?policyImportId=X&discoveryRunId=Y`: loads the policy import, evaluates it against queries derived from the discovery run's own targets (so the comparison is always apples-to-apples — the same hosts/ports Phase 1 actually probed), loads the discovery run's observations, calls `CorrelateReachability`, returns the comparisons. Baseline-auth-only read.

Table: `network_policy_imports(id, source_type, imported_by, imported_at, config_version, default_policy, limitations text[], policy_data jsonb)`.

## Safety Constraints

- `MaxRulesPerImport = 5000`, `MaxZonesPerImport = 500` — sized for a real enterprise firewall config, not Phase 1's live-probe blast-radius concern (this is pure computation, no network I/O).
- `MaxPolicyQueriesPerEvaluation = 500`.
- Request body cap: 5 MiB, via `http.MaxBytesReader` from the start.
- Malformed CIDRs or unknown `Action` values are rejected at import validation time (`400`), never silently dropped or coerced.
- Ambiguous zone membership and `ActionUnresolved` always surface as `Unknown` with a limitation note, at every layer (evaluation, correlation, API) — never softened into a stronger claim closer to the API boundary.

## Testing Strategy

TDD throughout, same discipline as Phase 1.

- **`networkpolicy` evaluation** — pure-function unit tests, no DB: ordered first-match-wins, default-policy fallback (both allow and deny), `ActionUnresolved` → `Unknown` with the note carried through, ambiguous zone resolution → `Unknown`, and the three reject-before-evaluating guards (empty queries, over-cap queries, over-cap import).
- **`networkcorrelation`** — pure-function unit tests covering **all 6** `ComparisonLabel` values individually (the same "prove the hard-to-reach branch directly" discipline as Phase 1's `RunPartial` test — ordinary fixtures won't incidentally hit all 6), plus the host/CIDR/port matching logic that pairs an evaluation with its observation.
- **Store layer** — round-trip tests mirroring Phase 1's `networkdiscovery_store_test.go` pattern exactly (insert/get/list, `pgx.ErrNoRows` on a missing ID).
- **API layer** — mirrors Phase 1's handler tests: successful import, every validation rejection (empty zones/rules, over-cap, bad CIDR, unknown action, missing `Note`/`Limitations` on `ActionUnresolved`), oversized-body rejection, server-controlled `ImportedBy`, the evaluation and comparison endpoints against a real persisted import + a real Phase 1 discovery run.

## Acceptance Criteria

Given a validated policy import and Phase 1 observations, Audspect produces explainable, evidence-backed reachability discrepancies, identifies unsupported or incomplete policy interpretation, and never presents a manually translated configuration as independently verified live enforcement.

Concretely: every `PolicyEvaluation` and `ReachabilityComparison` is traceable to its source `PolicyImport` (with that import's own `SourceType`/`Limitations` visible), every `Unresolved`/ambiguous case surfaces as `Unknown` rather than a guess at any layer, and no comparison label implies a security verdict stronger than "these two independently-collected pieces of evidence agree" or "disagree."
