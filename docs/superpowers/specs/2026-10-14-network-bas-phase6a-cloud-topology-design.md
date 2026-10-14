# Network BAS Mastery Phase 6A: Cloud Network Topology — Design Spec

## 1. Goal

Model cloud network topology — VPCs, subnets, security groups, route tables, and peering relationships — in a vendor-neutral normalized schema; evaluate security-group-rule policy for a given flow; and compose candidate cross-subnet / cross-VPC paths from routing and peering evidence. Routing and policy are evaluated as two independent evidence questions, exactly as Phase 3 established for on-premises networking: a security-group rule permitting traffic never proves a route exists, a route never proves policy permits traffic, and a modeled path never proves observed connectivity. Missing route or policy data is never interpreted as proof of isolation.

This is the first half of the master spec's Phase 6 ("Cloud & Remote-Access Networking") — VPN/remote-access/bastion boundary validation is Phase 6B, built after this one, as its own spec/plan cycle.

## 2. Relationship to `cloudgraph` and the Held Cloud BAS Initiative

`internal/cloudgraph` models IAM authorization paths (identity → permission → resource) — a materially different edge semantic from VPC/security-group/route-table/peering connectivity (master spec §1.7). This phase does **not** modify `cloudgraph`'s IAM model. It extends the network-connectivity domain with cloud-topology-aware types that reference cloud resources by the same canonical IDs `cloudgraph` already uses (`cloudgraph.CloudResource.CanonicalID`, `cloudgraph.AccountScope`), and reuses `cloudgraph.PathState`/`Provenance` directly — the same deliberate cross-package dependency `internal/networkgraph` already has. No new `PathState` value is introduced.

The separate Cloud BAS Initiative (AWS/Azure/GCP discovery and IAM attack-path evaluation) is currently held. The master spec's Definition of Done for Phase 6 requires a report-layer example correlating a Cloud BAS IAM finding with a network-connectivity finding for the same account, without merging them. Since Cloud BAS has no live evaluation pipeline running, this is satisfied the same way Phase 3 satisfied the analogous identity-domain correlation requirement: a small, purely additive, reporting-layer-only function (§5.3) demonstrated against a synthetic/fixture `cloudgraph.EvaluationResult`, never a live Cloud BAS run. This does not require Cloud BAS to be un-paused, and never changes a path's own `PathState`.

## 3. Why One Shared Schema, Not Two

Phase 2A (`networkpolicy`, firewall-rule evaluation) and Phase 3 (`networktopology`, route-adjacency search) deliberately kept their schemas independent — on-premises firewall configuration and routing configuration are genuinely two separate systems, exported by different tools at different times, correlated only by matching zone-name strings at evaluation time in `networkpath`.

Cloud network topology does not have that same separation in practice: a single provider API snapshot ("describe VPC") naturally returns networks, subnets, security groups, route tables, and peering connections together, as one normalized import. Splitting that into two artificially-independent schemas would not reflect how the data actually arrives, and would force an awkward string-based correlation step for data that is already one coherent object. Phase 6A therefore uses **one shared schema package** (`internal/cloudtopology`) holding the full normalized topology, with both evidence-gathering functions (security-group evaluation and route/peering search) operating on it — and a separate, schema-agnostic composition package (`internal/cloudpath`) that plays exactly the role `internal/networkpath` already plays for on-premises evidence: the one place routing evidence, policy evidence, and direct observation evidence are combined into a classified path, and the one place cloud-topology evidence and Cloud BAS IAM evidence are allowed to meet (additively, in reporting only).

## 4. Package: `internal/cloudtopology`

### 4.1 Data Model

```go
package cloudtopology

import (
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

// CloudNetwork is a VPC/VNet-equivalent construct.
type CloudNetwork struct {
	CanonicalID  string                `json:"canonicalId"`
	AccountScope *cloudgraph.AccountScope `json:"accountScope,omitempty"`
	CIDRBlocks   []string              `json:"cidrBlocks"`
	DisplayName  string                `json:"displayName,omitempty"`
}

// CloudSubnet belongs to exactly one CloudNetwork.
type CloudSubnet struct {
	CanonicalID string `json:"canonicalId"`
	NetworkID   string `json:"networkId"`
	CIDRBlock   string `json:"cidrBlock"`
	DisplayName string `json:"displayName,omitempty"`
}

// GroupScope says how far a SecurityGroup's rules reach. A provider
// whose real attachment model this schema cannot represent faithfully
// (e.g. per-instance/per-ENI attachment) gets ScopeUnresolved, never a
// guessed Network or Subnet scope.
type GroupScope string

const (
	ScopeNetwork    GroupScope = "network"    // rules apply VPC-wide (e.g. a GCP firewall rule's default reach)
	ScopeSubnet     GroupScope = "subnet"     // rules apply only within one subnet
	ScopeUnresolved GroupScope = "unresolved" // attachment is below this model's resolution
)

// SecurityGroup is a named collection of rules, attached at the scope
// GroupScope declares.
type SecurityGroup struct {
	CanonicalID string     `json:"canonicalId"`
	NetworkID   string     `json:"networkId"`
	Scope       GroupScope `json:"scope"`
	SubnetID    string     `json:"subnetId,omitempty"` // set only when Scope == ScopeSubnet
}

// RuleAction mirrors networkpolicy.RuleAction exactly, including
// ActionUnresolved for a vendor construct (NAT, stateful return
// traffic, dynamic security-group references this schema can't
// losslessly represent) that must be represented honestly rather than
// forced into Allow or Deny.
type RuleAction string

const (
	ActionAllow      RuleAction = "allow"
	ActionDeny       RuleAction = "deny"
	ActionUnresolved RuleAction = "unresolved"
)

// SecurityGroupRule is one normalized rule. Exactly one of CIDR or
// ReferencedGroupID is set for the non-local side of the rule (a
// direct CIDR, or a reference to another security group — common in
// AWS/Azure SG-to-SG rules). Order is the rule's evaluation priority,
// lower evaluated first — AWS's allow-only, no-priority-concept shape
// gets a synthetic ascending Order at import time, making it a
// degenerate case of the same ordered first-match-wins model Azure
// NSGs use natively; this is never a translation of meaning, only of
// representation.
type SecurityGroupRule struct {
	ID                string     `json:"id"`
	GroupID           string     `json:"groupId"`
	Order             int        `json:"order"`
	Direction         string     `json:"direction"` // "inbound" | "outbound"
	Action            RuleAction `json:"action"`
	Protocol          string     `json:"protocol,omitempty"`
	PortRange         string     `json:"portRange,omitempty"`
	CIDR              string     `json:"cidr,omitempty"`
	ReferencedGroupID string     `json:"referencedGroupId,omitempty"`
	// Note is required whenever Action == ActionUnresolved — same
	// discipline as networkpolicy.Rule.Note.
	Note string `json:"note,omitempty"`
}

// RouteTableEntry is one route, associated to a subnet.
type RouteTableEntry struct {
	ID               string `json:"id"`
	SubnetID         string `json:"subnetId"`
	DestinationCIDR  string `json:"destinationCidr"`
	Target           string `json:"target"` // "local" | "peering" | "internet-gateway" | "nat-gateway" | "transit-gateway" | "unknown"
	TargetRef        string `json:"targetRef,omitempty"` // e.g. PeeringConnection.CanonicalID when Target == "peering"
}

// PeeringConnection links two CloudNetworks, possibly cross-account.
// Only State == "active" is ever treated as a usable route edge.
type PeeringConnection struct {
	CanonicalID string `json:"canonicalId"`
	NetworkAID  string `json:"networkAId"`
	NetworkBID  string `json:"networkBId"`
	State       string `json:"state"` // "active" | "pending" | "rejected" | "unknown"
}

// CloudTopologyImport is one auditable, versioned topology snapshot —
// the same shape discipline as networkpolicy.PolicyImport and
// networktopology.TopologyImport. Limitations is required to be
// non-empty whenever any SecurityGroup.Scope == ScopeUnresolved or any
// SecurityGroupRule.Action == ActionUnresolved, enforced at the API
// validation layer, not here.
type CloudTopologyImport struct {
	ID            string                `json:"id,omitempty"`
	SourceType    string                `json:"sourceType"`
	ImportedBy    string                `json:"importedBy,omitempty"`
	ImportedAt    time.Time             `json:"importedAt,omitempty"`
	ConfigVersion string                `json:"configVersion,omitempty"`
	Networks      []CloudNetwork        `json:"networks"`
	Subnets       []CloudSubnet         `json:"subnets"`
	Groups        []SecurityGroup       `json:"groups"`
	Rules         []SecurityGroupRule   `json:"rules"`
	Routes        []RouteTableEntry     `json:"routes"`
	Peerings      []PeeringConnection   `json:"peerings"`
	Limitations   []string              `json:"limitations,omitempty"`
}
```

### 4.2 Security-Group Evaluation

```go
// CloudFlow is a candidate flow to evaluate — mirrors
// networkpolicy.PolicyQuery, but keyed to a resolved subnet rather
// than a zone (subnet resolution from a caller-supplied host/resource
// happens one level up, at the API handler, mirroring Phase 3's own
// host-to-zone resolution).
type CloudFlow struct {
	SourceCIDR string
	DestCIDR   string
	Protocol   string
	Port       int
}

// EvaluateSecurityGroupRules evaluates every rule from every security
// group applicable to subnetID against flow, in Order, first match
// wins — exactly networkpolicy.EvaluatePolicyMatrix's evaluation
// discipline. Applicable groups are every ScopeNetwork group on the
// subnet's network, plus every ScopeSubnet group attached to
// subnetID. If any ScopeUnresolved group is also attached to
// subnetID, the result is forced to Unknown regardless of what the
// resolved groups' rules would otherwise decide — an unresolved
// group's rules might apply and might deny traffic the resolved rules
// appear to allow, so it is never silently excluded. No rule matching
// any applicable group falls through to implicit deny, which is safe
// to assume uniformly across providers.
func EvaluateSecurityGroupRules(imp *CloudTopologyImport, subnetID string, flow CloudFlow) SecurityGroupEvaluation
```

`SecurityGroupEvaluation` mirrors `networkpolicy.PolicyEvaluation`'s shape exactly: `Flow`, `State cloudgraph.PathState`, `MatchedRule *SecurityGroupRule` (nil when implicit-deny applied, or when resolution failed before any rule was checked), `Provenance`, `Limitations string` (singular, matching `PolicyEvaluation.Limitations` — not a slice).

### 4.2.1 Safety Caps

Mirrors `networkpolicy`'s and `networktopology`'s own bounds exactly:

```go
const (
	MaxSubnetsPerImport        = 500  // mirrors MaxZonesPerTopologyImport
	MaxRulesPerImport          = 5000 // mirrors networkpolicy.MaxRulesPerImport
	MaxRoutesPerImport         = 5000 // mirrors MaxEdgesPerTopologyImport
	MaxHopsPerPathQuery        = 10   // mirrors MaxHopsPerPathQuery
	MaxCandidateRoutesPerQuery = 20   // mirrors MaxCandidateRoutesPerQuery

	// maxRouteSearchSteps mirrors networktopology's own unexported
	// defensive bound on total search work, independent of the
	// subnet/route caps above -- a dense peering mesh within those
	// caps could still cost more exploration than the candidate-count
	// cap alone would bound. Not a caller-tunable safety knob.
	maxRouteSearchSteps = 20000
)
```

### 4.3 Route and Peering Search

```go
// CloudRoutePath is an ordered sequence of subnet CanonicalIDs from
// source to destination, inclusive of both endpoints -- same shape as
// networktopology.RoutePath.
type CloudRoutePath []string

// FindCandidateCloudRoutes returns up to MaxCandidateRoutesPerQuery
// simple paths (no repeated subnet) from sourceSubnetID to
// destSubnetID, each at most maxHops edges long (clamped to
// MaxHopsPerPathQuery), exactly mirroring
// networktopology.FindCandidateRoutes's discipline: a same-network
// local route (a "local" RouteTableEntry on the current subnet
// covering the destination CIDR) short-circuits immediately; a
// cross-network hop requires BOTH a "peering" RouteTableEntry on the
// current subnet referencing a PeeringConnection, AND that
// connection's State == "active" -- a pending or rejected peering is
// real evidence of no route via that specific connection, but (same
// as Phase 3's "no known route never means blocked" principle) never
// proof no other path exists, since a transit gateway or a different
// peering this import has no visibility into might still connect the
// two networks. sourceSubnetID == destSubnetID always returns one
// trivial route. Zero routes is a valid result, not an error.
//
// exhausted is true when the defensive maxRouteSearchSteps budget was
// hit before the search could either find MaxCandidateRoutesPerQuery
// routes or exhaustively rule out more. A zero-route result with
// exhausted=true means "search was truncated, absence is not
// proven"; exhausted=false means "search space was fully explored, no
// route exists" -- callers must not conflate the two (Phase 3's own
// Important finding from its final review, carried forward here from
// the start).
func FindCandidateCloudRoutes(imp *CloudTopologyImport, sourceSubnetID, destSubnetID string, maxHops int) (routes []CloudRoutePath, exhausted bool, err error)
```

## 5. Package: `internal/cloudpath`

Plays the same role for cloud evidence that `internal/networkpath` plays for on-premises evidence: the one place routing evidence (`cloudtopology.FindCandidateCloudRoutes`), policy evidence (`cloudtopology.EvaluateSecurityGroupRules`), and direct observation evidence (`networkgraph.NetworkObservation`, reused as-is — a Phase 1 vantage point that happened to probe a cloud-hosted target produces evidence just as valid for a cloud hop as for an on-premises one) are combined into a classified, multi-hop path.

### 5.1 Hop Composition

```go
// ComposeCloudHop classifies one hop, in priority order -- identical
// discipline to networkpath.ComposeHop:
//  1. A real NetworkObservation exists for this hop: it wins outright,
//     regardless of routing/policy evidence.
//  2. No observation, route found: the security-group verdict passes
//     through as-is.
//  3. No observation, route not found (or no security-group evaluation
//     at all): forced to Unknown, regardless of what the
//     security-group verdict would otherwise have been.
func ComposeCloudHop(fromSubnet, toSubnet string, routeFound bool, sgEval *cloudtopology.SecurityGroupEvaluation, observations []networkgraph.NetworkObservation) CloudHopResult
```

`CloudHopResult` mirrors `networkpath.HopResult`'s fields (`FromSubnet`, `ToSubnet`, `State cloudgraph.PathState`, `Limitations`, `Provenance`, `Observation`, `SecurityGroupEvaluation`, `RouteFound bool`).

### 5.2 Aggregation

`AggregateCloudPathState`/`AggregateCloudConfidence`/`AggregateCloudPath` re-implement the exact same weakest-link ranking `networkpath.AggregatePathState`/`AggregateConfidence` already use, grounded locally in this package — the same convention Phase 3 established (that function is itself a local re-implementation of `cloudgraph.worstState`'s unexported ranking, not an import of it).

### 5.3 Cloud BAS Correlation (Reporting-Layer Only)

```go
// CloudFindingCorrelation is purely additive context cited from a
// Cloud BAS IAM evaluation. It never changes a CloudPathResult's own
// PathState -- a report may say "this network path and this IAM
// finding both involve account X", never "therefore this IAM finding
// is more or less exploitable".
type CloudFindingCorrelation struct {
	Source  string `json:"source"` // "cloudgraph"
	Account string `json:"account"`
	Note    string `json:"note,omitempty"`
}

// CorrelateCloudFinding cites a Cloud BAS IAM evaluation result
// alongside a cloud path result when both reference the same
// cloudgraph.AccountScope -- matching only on AccountScope, nothing
// deeper (no inference that the IAM path and the network path involve
// the same specific resource unless their CanonicalIDs also match,
// which the caller may check separately and note).
func CorrelateCloudFinding(path CloudPathResult, iamFinding cloudgraph.EvaluationResult, account cloudgraph.AccountScope) *CloudFindingCorrelation
```

## 6. Persistence & API

Mirrors Phase 2A/3's established pattern exactly:

- New table `cloud_topology_imports` (`jsonb`-backed, same shape discipline as `network_policy_imports`/`network_topology_imports`).
- New permission `CanImportCloudTopology` (Admin + Analyst, same placement as `CanImportNetworkTopology`).
- `POST /api/cloud-topology-imports` — create an import, validated the same way `CreateNetworkTopologyImport`/`CreateNetworkPolicyImport` validate (every `ActionUnresolved` rule and every `ScopeUnresolved` group requires a non-empty `Limitations` entry on the import, or the request is rejected).
- `GET /api/cloud-topology-imports[/{id}]` — list/get.
- `POST /api/cloud-paths` — takes one topology import ID, one source/dest host (or subnet ID directly), and one flow (protocol/port) per call — same single-query shape as `POST /api/network-paths`, not a batch. Resolves hosts to subnets, calls `FindCandidateCloudRoutes`, evaluates security groups per hop, composes and aggregates. Not persisted — computed fresh on every call from already-persisted import data, exactly as `FindNetworkPaths` does. Mirrors `POST /api/network-paths`'s response shape (`{results, searchExhausted}`, `searchExhausted` omitted when false, per Phase 3's own final-review fix).

## 7. Review Focus

The five input classes most likely to bite a real person using this, each assigned to the task that should own its test coverage:

1. **A `ScopeUnresolved` security group attached to the subnet in question** — the evaluation must degrade to `Unknown`, never silently exclude that group's potentially-denying rules.
2. **Multiple matching security-group rules at different `Order` values for the same flow** — first-match-wins ordering must actually decide the outcome, not insertion order or a map's iteration order.
3. **A peering connection in a non-`active` state (`pending`/`rejected`)** — must never be treated as a usable route edge, but also must never be read as proof the two networks are isolated (another path this import has no visibility into might exist).
4. **A dense or cyclic peering mesh** (e.g. hub-spoke transit-gateway-style topology) exhausting the step budget — must surface `exhausted`, never silently truncate the result into a false "no route found".
5. **A real `networkgraph.NetworkObservation` exists for a hop that routing/policy evidence alone would classify differently** — the observation must win outright, exactly as Phase 3 requires for on-premises hops.

## 8. Safety Constraints

- Never modifies `internal/cloudgraph`'s IAM-authorization model or any existing evaluator.
- No assumption that a cloud IAM path (identity domain) implies network reachability (network domain), or vice versa — enforced structurally: `cloudtopology`/`cloudpath` never import any `cloudgraph` IAM-evaluation type beyond `PathState`/`Provenance`/`AccountScope`/`CloudResource.CanonicalID`, and `CorrelateCloudFinding` (§5.3) is additive-only by construction.
- Cloud configuration/telemetry visibility limitations are recorded explicitly (per `network.txt` §1.7) via the same `Limitations []string` mechanism Phase 2A/3 already established — never silently omitted.
- No live cloud-provider API calls in this phase; all topology arrives via the normalized import endpoint. Native vendor parsers (AWS/Azure/GCP API response shapes) are explicitly deferred (§9).

## 9. Explicitly Out of Scope / Deferred

- Native AWS/Azure/GCP API parsers — this phase builds and proves the normalized schema and evaluation/composition logic against hand-constructed or hand-translated fixture imports only.
- Public-exposure detection (is a resource reachable from `0.0.0.0/0` inbound) and management-plane-restriction checks — explicit derived queries on top of this phase's model, built in a later increment once the underlying topology/composition model is proven trustworthy, never a second competing reachability mechanism.
- Per-instance/per-ENI security-group attachment resolution — represented honestly as `ScopeUnresolved`, never resolved further in this phase.
- VPN, bastion/jump-host, partner-connectivity, and zero-trust boundary validation — Phase 6B, built after this phase, as its own spec/plan cycle.
- Transit-gateway-specific modeling beyond treating it as one more opaque `RouteTableEntry.Target` value — no dedicated transit-gateway route-propagation logic.

## 10. Acceptance Criteria

Given a normalized `CloudTopologyImport` and a candidate source/dest flow, Audspect can:
1. Classify whether a security-group policy permits, denies, or cannot determine the flow at a given subnet, citing the matched rule or the reason no determination could be made.
2. Classify whether a candidate cross-subnet or cross-VPC route exists (via local routing or active peering), independently of whether policy permits the traffic — citing the specific route-table entries and peering connections involved.
3. Compose the two into a per-hop and path-level `PathState`, preferring a real Phase 1 observation when one exists, and aggregate multi-hop paths using the same weakest-link discipline as Phase 3.
4. Demonstrate — via a fixture/synthetic example, not a live Cloud BAS run — a report-layer correlation between a cloud-topology path result and a Cloud BAS IAM finding for the same account, without merging their verdicts.
5. Record every provider-specific semantic this model cannot faithfully represent (attachment granularity, rule-action translation) as an explicit, non-empty limitation — never a silent guess.
