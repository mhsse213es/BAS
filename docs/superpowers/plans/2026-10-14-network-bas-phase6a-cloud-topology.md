# Network BAS Mastery Phase 6A: Cloud Network Topology Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Model cloud network topology (VPCs, subnets, security groups, route tables, peering) in a vendor-neutral normalized schema; evaluate security-group policy for a flow; compose candidate cross-subnet/cross-VPC paths from routing and security-group evidence as two independent evidence questions; persist imports and expose both over HTTP.

**Architecture:** Two new packages mirror the established Phase 2A/3 split exactly, except collapsed to match cloud's own data shape (one shared schema instead of two independently-sourced ones): `internal/cloudtopology` holds the normalized schema plus both evidence-gathering primitives (`EvaluateSecurityGroupRules`, `FindCandidateCloudRoutes`); `internal/cloudpath` is the one place that evidence, plus Phase 1's `networkgraph.NetworkObservation`, is composed into classified multi-hop paths (`ComposeCloudHop`, `AggregateCloudPath`), and the one place cloud-topology evidence and Cloud BAS IAM evidence are allowed to meet, additively (`CorrelateCloudFinding`). Both packages import `cloudgraph.PathState`/`Provenance`/`AccountScope` directly, the same deliberate cross-package dependency `networkgraph` already has, and never touch `cloudgraph`'s IAM-evaluation types beyond that. Persistence and HTTP follow the identical pattern already used four times (`networkpolicy`, `networktopology`, `networkcontrolexpectation`, `networkdnscheck`/`networktransportcheck`).

**Tech Stack:** Go, PostgreSQL (`pgx/v5`), `go-chi/chi/v5` for routing — same stack as every prior Network BAS phase, no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-14-network-bas-phase6a-cloud-topology-design.md`

## Global Constraints

- Never import any `cloudgraph` type beyond `PathState`, `Provenance`, `AccountScope`, `CloudResource.CanonicalID`, and (only in `cloudpath/correlate.go`) `EvaluationResult` — no IAM-evaluation logic is ever touched (spec §2, §8).
- `cloudtopology`/`cloudpath` never import each other's package in the wrong direction: `cloudpath` imports `cloudtopology` (read-only), `cloudtopology` never imports `cloudpath` (spec §3).
- Safety caps, exact values (spec §4.2.1): `MaxSubnetsPerImport = 500`, `MaxRulesPerImport = 5000`, `MaxRoutesPerImport = 5000`, `MaxHopsPerPathQuery = 10`, `MaxCandidateRoutesPerQuery = 20`, unexported `maxRouteSearchSteps = 20000`.
- `SecurityGroupEvaluation.Limitations` and `networkpolicy.PolicyEvaluation.Limitations`-style fields are a plain `string`, never a slice (spec §4.2, matching the real `networkpolicy.PolicyEvaluation.Limitations string`).
- A `ScopeUnresolved` security group attached to a subnet forces that subnet's evaluation to `Unknown`, never silent exclusion (spec §4.2).
- A non-`active` `PeeringConnection` is never a usable route edge, but is never read as proof of isolation either (spec §4.3).
- `FindCandidateCloudRoutes` surfaces a distinct `exhausted` bool; a zero-route result with `exhausted=true` ("truncated, absence not proven") must never be conflated with `exhausted=false` ("fully explored, no route exists") (spec §4.3).
- `ComposeCloudHop`'s 3-tier priority is fixed: a real `networkgraph.NetworkObservation` wins outright; otherwise `routeFound` gates whether the security-group verdict passes through or is forced to `Unknown` (spec §5.1).
- No live cloud-provider API calls anywhere in this plan — topology arrives only via the normalized import endpoint (spec §8).
- Host machine has ~7.84-8.2GB RAM: never run unscoped `go test ./internal/api/...` or `./internal/db/...`. Always `go build ./...` plus a scoped package test plus a `-run` regex covering every test added/changed in that task together. Check `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize` before any `internal/api` or `internal/db` test run.
- `git push` immediately after every commit. Work happens inline on `main`, no worktree, no feature branch (standing session convention).

## Review Focus

1. **A `ScopeUnresolved` security group attached to the subnet in question** (Task 1) — evaluation must degrade to `Unknown`, never silently exclude that group's potentially-denying rules.
2. **Multiple matching security-group rules at different `Order` values for the same flow** (Task 1) — first-match-wins ordering must actually decide the outcome, not slice/map iteration order.
3. **A peering connection in a non-`active` state (`pending`/`rejected`)** (Task 2) — must never be a usable route edge, and must never be read as proof the two networks are isolated.
4. **A dense/cyclic peering mesh exhausting the step budget** (Task 2) — must surface `exhausted=true`, never silently truncate into a false "no route found".
5. **A real `networkgraph.NetworkObservation` for a hop that routing/policy evidence alone would classify differently** (Task 3) — the observation must win outright.

---

## Task 1: `internal/cloudtopology` — Data Model and Security-Group Evaluation

**Files:**
- Create: `orchestrator/internal/cloudtopology/types.go`
- Create: `orchestrator/internal/cloudtopology/sgeval.go`
- Test: `orchestrator/internal/cloudtopology/sgeval_test.go`

**Interfaces:**
- Consumes: `cloudgraph.PathState`, `cloudgraph.Provenance` (`github.com/audspect/bas/internal/cloudgraph`); `networkpolicy.ParsePortRange(s string) (matchAny bool, low, high int, err error)` (`github.com/audspect/bas/internal/networkpolicy`).
- Produces: `GroupScope` (`ScopeNetwork`, `ScopeSubnet`, `ScopeUnresolved`), `RuleAction` (`ActionAllow`, `ActionDeny`, `ActionUnresolved`), string consts `TargetLocal`/`TargetPeering`/`TargetInternetGateway`/`TargetNATGateway`/`TargetTransitGateway`/`TargetUnknown`, `PeeringActive`/`PeeringPending`/`PeeringRejected`/`PeeringUnknown`, `DirectionInbound`/`DirectionOutbound`; types `CloudNetwork`, `CloudSubnet`, `SecurityGroup`, `SecurityGroupRule`, `RouteTableEntry`, `PeeringConnection`, `CloudTopologyImport`; `CloudFlow{SourceCIDR, DestCIDR, Protocol string; Port int}`, `SecurityGroupEvaluation{Flow CloudFlow; State cloudgraph.PathState; MatchedRule *SecurityGroupRule; Provenance cloudgraph.Provenance; Limitations string}`, `func EvaluateSecurityGroupRules(imp *CloudTopologyImport, subnetID string, flow CloudFlow) (SecurityGroupEvaluation, error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/cloudtopology/sgeval_test.go
package cloudtopology

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func testImport() *CloudTopologyImport {
	return &CloudTopologyImport{
		Networks: []CloudNetwork{{CanonicalID: "vpc-1", CIDRBlocks: []string{"10.0.0.0/16"}}},
		Subnets: []CloudSubnet{
			{CanonicalID: "subnet-1", NetworkID: "vpc-1", CIDRBlock: "10.0.1.0/24"},
		},
		Groups: []SecurityGroup{
			{CanonicalID: "sg-1", NetworkID: "vpc-1", Scope: ScopeSubnet, SubnetID: "subnet-1"},
		},
		Rules: []SecurityGroupRule{
			{ID: "r1", GroupID: "sg-1", Order: 10, Direction: DirectionOutbound, Action: ActionAllow, Protocol: "tcp", PortRange: "443", CIDR: "10.0.2.0/24"},
		},
	}
}

func TestEvaluateSecurityGroupRules_AllowMatch_PolicySupported(t *testing.T) {
	imp := testImport()
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q", eval.State, cloudgraph.PolicySupported)
	}
	if eval.MatchedRule == nil || eval.MatchedRule.ID != "r1" {
		t.Fatalf("MatchedRule = %v, want rule r1", eval.MatchedRule)
	}
}

func TestEvaluateSecurityGroupRules_NoMatch_ImplicitDeny(t *testing.T) {
	imp := testImport()
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", CloudFlow{DestCIDR: "10.0.9.0/24", Protocol: "tcp", Port: 22})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q (implicit deny)", eval.State, cloudgraph.Blocked)
	}
}

// TestEvaluateSecurityGroupRules_OrderDecides pins Review Focus #2: two
// rules both match the flow, at different Order values -- the lower
// Order (evaluated first) must decide the outcome regardless of slice
// position.
func TestEvaluateSecurityGroupRules_OrderDecides(t *testing.T) {
	imp := testImport()
	imp.Rules = []SecurityGroupRule{
		{ID: "deny-later", GroupID: "sg-1", Order: 20, Direction: DirectionOutbound, Action: ActionDeny, Protocol: "tcp", PortRange: "443", CIDR: "10.0.2.0/24"},
		{ID: "allow-first", GroupID: "sg-1", Order: 10, Direction: DirectionOutbound, Action: ActionAllow, Protocol: "tcp", PortRange: "443", CIDR: "10.0.2.0/24"},
	}
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q -- the lower-Order allow rule must win, not slice position", eval.State, cloudgraph.PolicySupported)
	}
	if eval.MatchedRule == nil || eval.MatchedRule.ID != "allow-first" {
		t.Fatalf("MatchedRule = %v, want allow-first", eval.MatchedRule)
	}
}

// TestEvaluateSecurityGroupRules_UnresolvedGroupAttached_ForcesUnknown
// pins Review Focus #1: a ScopeUnresolved group attached to the subnet
// must force Unknown even though the resolved group's own rule would
// otherwise allow the flow -- its rules might apply and might deny
// traffic the resolved rules appear to allow.
func TestEvaluateSecurityGroupRules_UnresolvedGroupAttached_ForcesUnknown(t *testing.T) {
	imp := testImport()
	imp.Groups = append(imp.Groups, SecurityGroup{CanonicalID: "sg-unresolved", NetworkID: "vpc-1", Scope: ScopeUnresolved, SubnetID: "subnet-1"})
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- an unresolved-attachment group must force Unknown", eval.State, cloudgraph.Unknown)
	}
	if eval.Limitations == "" {
		t.Fatal("want a non-empty Limitations explaining the unresolved group")
	}
}

func TestEvaluateSecurityGroupRules_NoGroupsAtAll_Unknown(t *testing.T) {
	imp := testImport()
	imp.Groups = nil
	imp.Rules = nil
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- zero declared groups is missing evidence, never a confirmed deny", eval.State, cloudgraph.Unknown)
	}
}

// TestEvaluateSecurityGroupRules_ReferencedGroupRule_MatchesOnPortOnly
// pins the SG-to-SG reference handling: a rule with ReferencedGroupID
// (no CIDR) matches on protocol/port alone, since this schema cannot
// resolve group membership -- callers must mark such rules
// ActionUnresolved at import time (enforced in Task 7's validation),
// so a match here always yields Unknown.
func TestEvaluateSecurityGroupRules_ReferencedGroupRule_MatchesOnPortOnly(t *testing.T) {
	imp := testImport()
	imp.Rules = []SecurityGroupRule{
		{ID: "sg-ref", GroupID: "sg-1", Order: 10, Direction: DirectionOutbound, Action: ActionUnresolved, Protocol: "tcp", PortRange: "443", ReferencedGroupID: "sg-other", Note: "SG-to-SG reference, group membership not resolvable by this schema"},
	}
	eval, err := EvaluateSecurityGroupRules(imp, "subnet-1", CloudFlow{DestCIDR: "10.0.2.0/24", Protocol: "tcp", Port: 443})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q", eval.State, cloudgraph.Unknown)
	}
	if eval.Limitations == "" {
		t.Fatal("want the rule's Note carried into Limitations")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cloudtopology/... -run TestEvaluateSecurityGroupRules -v`
Expected: FAIL — `package cloudtopology` has no `CloudTopologyImport`/`CloudFlow`/`EvaluateSecurityGroupRules` etc. (build failure, not a test failure — the package doesn't exist yet).

- [ ] **Step 3: Write `types.go`**

```go
// orchestrator/internal/cloudtopology/types.go

// Package cloudtopology models a vendor-agnostic, normalized cloud
// network topology (VPCs, subnets, security groups, route tables,
// peering) and evaluates/searches it to produce cloudgraph.PathState
// evidence. It never imports internal/cloudgraph's IAM-evaluation
// types beyond PathState/Provenance/AccountScope -- see
// docs/superpowers/specs/2026-10-14-network-bas-phase6a-cloud-topology-design.md
// §2-3 for why this schema is shared (unlike internal/networkpolicy
// and internal/networktopology, which stay deliberately independent).
package cloudtopology

import (
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

const (
	MaxSubnetsPerImport        = 500
	MaxRulesPerImport          = 5000
	MaxRoutesPerImport         = 5000
	MaxHopsPerPathQuery        = 10
	MaxCandidateRoutesPerQuery = 20

	// maxRouteSearchSteps is a defensive bound on total route-search
	// work, independent of the subnet/route caps above -- a dense
	// peering mesh within those caps could still cost more exploration
	// than the candidate-count cap alone would bound. Not a
	// caller-tunable safety knob.
	maxRouteSearchSteps = 20000
)

// GroupScope says how far a SecurityGroup's rules reach. A provider
// whose real attachment model this schema cannot represent faithfully
// (e.g. per-instance/per-ENI attachment) gets ScopeUnresolved, never a
// guessed Network or Subnet scope.
type GroupScope string

const (
	ScopeNetwork    GroupScope = "network"
	ScopeSubnet     GroupScope = "subnet"
	ScopeUnresolved GroupScope = "unresolved"
)

// RuleAction mirrors networkpolicy.RuleAction's three-value shape,
// including ActionUnresolved for a vendor construct (NAT, stateful
// return traffic, SG-to-SG group-reference rules) this schema cannot
// losslessly represent.
type RuleAction string

const (
	ActionAllow      RuleAction = "allow"
	ActionDeny       RuleAction = "deny"
	ActionUnresolved RuleAction = "unresolved"
)

const (
	DirectionInbound  = "inbound"
	DirectionOutbound = "outbound"

	TargetLocal           = "local"
	TargetPeering         = "peering"
	TargetInternetGateway = "internet-gateway"
	TargetNATGateway      = "nat-gateway"
	TargetTransitGateway  = "transit-gateway"
	TargetUnknown         = "unknown"

	PeeringActive   = "active"
	PeeringPending  = "pending"
	PeeringRejected = "rejected"
	PeeringUnknown  = "unknown"
)

// CloudNetwork is a VPC/VNet-equivalent construct.
type CloudNetwork struct {
	CanonicalID  string                   `json:"canonicalId"`
	AccountScope *cloudgraph.AccountScope `json:"accountScope,omitempty"`
	CIDRBlocks   []string                 `json:"cidrBlocks"`
	DisplayName  string                   `json:"displayName,omitempty"`
}

// CloudSubnet belongs to exactly one CloudNetwork.
type CloudSubnet struct {
	CanonicalID string `json:"canonicalId"`
	NetworkID   string `json:"networkId"`
	CIDRBlock   string `json:"cidrBlock"`
	DisplayName string `json:"displayName,omitempty"`
}

// SecurityGroup is a named collection of rules, attached at the scope
// Scope declares.
type SecurityGroup struct {
	CanonicalID string     `json:"canonicalId"`
	NetworkID   string     `json:"networkId"`
	Scope       GroupScope `json:"scope"`
	SubnetID    string     `json:"subnetId,omitempty"` // set only when Scope == ScopeSubnet
}

// SecurityGroupRule is one normalized rule. Exactly one of CIDR or
// ReferencedGroupID is set -- a direct CIDR, or a reference to another
// security group (common in AWS/Azure SG-to-SG rules, which this
// schema cannot resolve group membership for -- see
// EvaluateSecurityGroupRules). Order is the rule's evaluation
// priority, lower evaluated first -- AWS's allow-only, no-priority
// shape gets a synthetic ascending Order at import time, making it a
// degenerate case of the same model Azure NSGs use natively.
type SecurityGroupRule struct {
	ID                string     `json:"id"`
	GroupID           string     `json:"groupId"`
	Order             int        `json:"order"`
	Direction         string     `json:"direction"` // DirectionInbound | DirectionOutbound
	Action            RuleAction `json:"action"`
	Protocol          string     `json:"protocol,omitempty"`
	PortRange         string     `json:"portRange,omitempty"`
	CIDR              string     `json:"cidr,omitempty"`
	ReferencedGroupID string     `json:"referencedGroupId,omitempty"`
	// Note is required whenever Action == ActionUnresolved -- same
	// discipline as networkpolicy.Rule.Note.
	Note string `json:"note,omitempty"`
}

// RouteTableEntry is one route, associated to a subnet.
type RouteTableEntry struct {
	ID              string `json:"id"`
	SubnetID        string `json:"subnetId"`
	DestinationCIDR string `json:"destinationCidr"`
	Target          string `json:"target"` // TargetLocal | TargetPeering | TargetInternetGateway | TargetNATGateway | TargetTransitGateway | TargetUnknown
	TargetRef       string `json:"targetRef,omitempty"` // e.g. PeeringConnection.CanonicalID when Target == TargetPeering
}

// PeeringConnection links two CloudNetworks, possibly cross-account.
// Only State == PeeringActive is ever treated as a usable route edge.
type PeeringConnection struct {
	CanonicalID string `json:"canonicalId"`
	NetworkAID  string `json:"networkAId"`
	NetworkBID  string `json:"networkBId"`
	State       string `json:"state"` // PeeringActive | PeeringPending | PeeringRejected | PeeringUnknown
}

// CloudTopologyImport is one auditable, versioned topology snapshot --
// the same shape discipline as networkpolicy.PolicyImport and
// networktopology.TopologyImport. Limitations is required to be
// non-empty whenever any SecurityGroup.Scope == ScopeUnresolved or any
// SecurityGroupRule.Action == ActionUnresolved, enforced at the API
// validation layer (Task 7), not here.
type CloudTopologyImport struct {
	ID            string              `json:"id,omitempty"`
	SourceType    string              `json:"sourceType"`
	ImportedBy    string              `json:"importedBy,omitempty"`
	ImportedAt    time.Time           `json:"importedAt,omitempty"`
	ConfigVersion string              `json:"configVersion,omitempty"`
	Networks      []CloudNetwork      `json:"networks"`
	Subnets       []CloudSubnet       `json:"subnets"`
	Groups        []SecurityGroup     `json:"groups"`
	Rules         []SecurityGroupRule `json:"rules"`
	Routes        []RouteTableEntry   `json:"routes"`
	Peerings      []PeeringConnection `json:"peerings"`
	Limitations   []string            `json:"limitations,omitempty"`
}
```

- [ ] **Step 4: Write `sgeval.go`**

```go
// orchestrator/internal/cloudtopology/sgeval.go
package cloudtopology

import (
	"fmt"
	"net"
	"sort"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// CloudFlow is a candidate flow to evaluate -- mirrors
// networkpolicy.PolicyQuery, but keyed to a resolved subnet rather
// than a zone (subnet resolution from a caller-supplied host happens
// one level up, at the API handler -- Task 8).
type CloudFlow struct {
	SourceCIDR string
	DestCIDR   string
	Protocol   string
	Port       int
}

// SecurityGroupEvaluation is EvaluateSecurityGroupRules's result.
type SecurityGroupEvaluation struct {
	Flow        CloudFlow
	State       cloudgraph.PathState
	MatchedRule *SecurityGroupRule // nil when implicit-deny applied, or when no groups/rules were evaluable
	Provenance  cloudgraph.Provenance
	Limitations string
}

// MatchesPort reports whether port falls within r.PortRange, reusing
// networkpolicy.ParsePortRange's parsing rather than duplicating it.
func (r SecurityGroupRule) MatchesPort(port int) (bool, error) {
	matchAny, low, high, err := networkpolicy.ParsePortRange(r.PortRange)
	if err != nil {
		return false, err
	}
	if matchAny {
		return true, nil
	}
	return port >= low && port <= high, nil
}

// EvaluateSecurityGroupRules evaluates every rule from every security
// group applicable to subnetID against flow, in Order, first match
// wins. Applicable groups are every ScopeNetwork group on the
// subnet's network, plus every ScopeSubnet group attached to
// subnetID. If any ScopeUnresolved group is also attached, the result
// is forced to Unknown regardless of what the resolved groups' rules
// would otherwise decide. Zero applicable groups at all is likewise
// Unknown (missing evidence, never a confirmed deny). No rule matching
// any applicable group falls through to implicit deny, which is safe
// to assume uniformly across providers.
func EvaluateSecurityGroupRules(imp *CloudTopologyImport, subnetID string, flow CloudFlow) (SecurityGroupEvaluation, error) {
	result := SecurityGroupEvaluation{Flow: flow}

	var subnet *CloudSubnet
	for i := range imp.Subnets {
		if imp.Subnets[i].CanonicalID == subnetID {
			subnet = &imp.Subnets[i]
			break
		}
	}
	if subnet == nil {
		return result, fmt.Errorf("cloudtopology: subnet %q not found in this import", subnetID)
	}

	var applicable []SecurityGroup
	unresolvedAttached := false
	for _, g := range imp.Groups {
		switch g.Scope {
		case ScopeNetwork:
			if g.NetworkID == subnet.NetworkID {
				applicable = append(applicable, g)
			}
		case ScopeSubnet:
			if g.SubnetID == subnetID {
				applicable = append(applicable, g)
			}
		case ScopeUnresolved:
			if g.NetworkID == subnet.NetworkID || g.SubnetID == subnetID {
				unresolvedAttached = true
			}
		}
	}

	if unresolvedAttached {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "an unresolved-attachment security group applies to this subnet; its rules might apply and might deny traffic the resolved groups' rules appear to allow"
		return result, nil
	}

	if len(applicable) == 0 {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no security groups declared for this subnet in the import; cannot determine policy"
		return result, nil
	}

	groupIDs := make(map[string]bool, len(applicable))
	for _, g := range applicable {
		groupIDs[g.CanonicalID] = true
	}
	var rules []SecurityGroupRule
	for _, r := range imp.Rules {
		if groupIDs[r.GroupID] {
			rules = append(rules, r)
		}
	}
	sort.SliceStable(rules, func(i, j int) bool { return rules[i].Order < rules[j].Order })

	for i := range rules {
		matched, err := matchesFlow(rules[i], flow)
		if err != nil {
			return result, err
		}
		if !matched {
			continue
		}
		switch rules[i].Action {
		case ActionAllow:
			result.State = cloudgraph.PolicySupported
			result.Provenance = cloudgraph.Provenance{Confidence: "medium"}
		case ActionDeny:
			result.State = cloudgraph.Blocked
			result.Provenance = cloudgraph.Provenance{Confidence: "medium"}
		case ActionUnresolved:
			result.State = cloudgraph.Unknown
			result.Provenance = cloudgraph.Provenance{Confidence: "none"}
			result.Limitations = rules[i].Note
		default:
			return result, fmt.Errorf("cloudtopology: rule %q has unknown action %q", rules[i].ID, rules[i].Action)
		}
		matchedRule := rules[i]
		result.MatchedRule = &matchedRule
		return result, nil
	}

	result.State = cloudgraph.Blocked
	result.Provenance = cloudgraph.Provenance{Confidence: "low"}
	return result, nil
}

// matchesFlow reports whether rule applies to flow. A rule with no
// CIDR (a ReferencedGroupID-only, SG-to-SG rule) matches on
// protocol/port alone, since this schema cannot resolve group
// membership -- import validation (Task 7) requires such rules to
// carry Action == ActionUnresolved, so a match here is never read as
// a real allow/deny.
func matchesFlow(rule SecurityGroupRule, flow CloudFlow) (bool, error) {
	if rule.Protocol != "" && flow.Protocol != "" && rule.Protocol != flow.Protocol {
		return false, nil
	}
	portOK, err := rule.MatchesPort(flow.Port)
	if err != nil {
		return false, err
	}
	if !portOK {
		return false, nil
	}
	if rule.CIDR == "" {
		return true, nil
	}
	var targetCIDR string
	if rule.Direction == DirectionInbound {
		targetCIDR = flow.SourceCIDR
	} else {
		targetCIDR = flow.DestCIDR
	}
	if targetCIDR == "" {
		return false, nil
	}
	return cidrsOverlap(rule.CIDR, targetCIDR)
}

// cidrsOverlap treats two CIDRs as overlapping when either contains
// the other's network address -- the same deliberate simplification
// networkpolicy.cidrsOverlap uses, re-implemented locally rather than
// imported (cloudtopology and networkpolicy stay independent packages).
func cidrsOverlap(a, b string) (bool, error) {
	_, aNet, err := net.ParseCIDR(a)
	if err != nil {
		return false, fmt.Errorf("cloudtopology: invalid CIDR %q: %w", a, err)
	}
	_, bNet, err := net.ParseCIDR(b)
	if err != nil {
		return false, fmt.Errorf("cloudtopology: invalid CIDR %q: %w", b, err)
	}
	return aNet.Contains(bNet.IP) || bNet.Contains(aNet.IP), nil
}
```

Note: fix the stray `#` comment typo (`# Unknown` → `// Unknown`) left in the doc comment above when transcribing — it must read as a normal Go comment line, not a directive.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/cloudtopology/... -run TestEvaluateSecurityGroupRules -v`
Expected: PASS, all 6 tests.

- [ ] **Step 6: Run full package build and test**

Run: `go build ./... && go test ./internal/cloudtopology/... -v`
Expected: build clean, all tests PASS.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/cloudtopology/types.go orchestrator/internal/cloudtopology/sgeval.go orchestrator/internal/cloudtopology/sgeval_test.go
git commit -m "feat(cloudtopology): add normalized schema and security-group rule evaluation" -m "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Task 2: `internal/cloudtopology` — Host Resolution and Route/Peering Search

**Files:**
- Create: `orchestrator/internal/cloudtopology/resolve.go`
- Create: `orchestrator/internal/cloudtopology/routes.go`
- Test: `orchestrator/internal/cloudtopology/routes_test.go`

**Interfaces:**
- Consumes: `CloudTopologyImport`, `CloudSubnet`, `RouteTableEntry`, `PeeringConnection`, `TargetLocal`/`TargetPeering`, `PeeringActive` (Task 1).
- Produces: `func SubnetForHost(host string, subnets []CloudSubnet) (string, error)`; `type CloudRoutePath []string`; `func FindCandidateCloudRoutes(imp *CloudTopologyImport, sourceSubnetID, destSubnetID string, maxHops int) (routes []CloudRoutePath, exhausted bool, err error)`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/cloudtopology/routes_test.go
package cloudtopology

import "testing"

func TestSubnetForHost_FindsContainingSubnet(t *testing.T) {
	subnets := []CloudSubnet{{CanonicalID: "subnet-1", CIDRBlock: "10.0.1.0/24"}, {CanonicalID: "subnet-2", CIDRBlock: "10.0.2.0/24"}}
	got, err := SubnetForHost("10.0.1.5", subnets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "subnet-1" {
		t.Fatalf("got %q, want subnet-1", got)
	}
}

func TestSubnetForHost_NoMatch_Error(t *testing.T) {
	subnets := []CloudSubnet{{CanonicalID: "subnet-1", CIDRBlock: "10.0.1.0/24"}}
	if _, err := SubnetForHost("192.168.1.1", subnets); err == nil {
		t.Fatal("want error for a host no subnet contains")
	}
}

// threeHopImport builds: subnet-a (vpc-1) --local--> subnet-b (vpc-1)
// --peering(active)--> subnet-c (vpc-2) -- a genuinely multi-hop
// fixture (3 subnets, 2 peered networks), not a 2-node degenerate
// case, per the plan's own grounding note about Phase 5's bugs that
// flat fixtures masked.
func threeHopImport() *CloudTopologyImport {
	return &CloudTopologyImport{
		Networks: []CloudNetwork{
			{CanonicalID: "vpc-1", CIDRBlocks: []string{"10.0.0.0/16"}},
			{CanonicalID: "vpc-2", CIDRBlocks: []string{"10.1.0.0/16"}},
		},
		Subnets: []CloudSubnet{
			{CanonicalID: "subnet-a", NetworkID: "vpc-1", CIDRBlock: "10.0.1.0/24"},
			{CanonicalID: "subnet-b", NetworkID: "vpc-1", CIDRBlock: "10.0.2.0/24"},
			{CanonicalID: "subnet-c", NetworkID: "vpc-2", CIDRBlock: "10.1.1.0/24"},
		},
		Peerings: []PeeringConnection{
			{CanonicalID: "peer-1", NetworkAID: "vpc-1", NetworkBID: "vpc-2", State: PeeringActive},
		},
		Routes: []RouteTableEntry{
			{ID: "rt-a-local", SubnetID: "subnet-a", DestinationCIDR: "10.0.2.0/24", Target: TargetLocal},
			{ID: "rt-b-peer", SubnetID: "subnet-b", DestinationCIDR: "10.1.1.0/24", Target: TargetPeering, TargetRef: "peer-1"},
		},
	}
}

func TestFindCandidateCloudRoutes_MultiHopThroughPeering(t *testing.T) {
	imp := threeHopImport()
	routes, exhausted, err := FindCandidateCloudRoutes(imp, "subnet-a", "subnet-c", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exhausted {
		t.Fatal("did not expect the search to be exhausted for a tiny topology")
	}
	if len(routes) != 1 {
		t.Fatalf("got %d routes, want 1", len(routes))
	}
	want := CloudRoutePath{"subnet-a", "subnet-b", "subnet-c"}
	got := routes[0]
	if len(got) != len(want) {
		t.Fatalf("route = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("route = %v, want %v", got, want)
		}
	}
}

// TestFindCandidateCloudRoutes_PendingPeering_NoRouteButNotIsolated
// pins Review Focus #3: a pending (non-active) peering is real
// evidence of no route via THAT connection, distinct from "no peering
// declared at all" -- both currently surface as zero candidate
// routes with exhausted=false, which callers must read as "no known
// route", never "proven blocked".
func TestFindCandidateCloudRoutes_PendingPeering_NoRouteButNotIsolated(t *testing.T) {
	imp := threeHopImport()
	imp.Peerings[0].State = PeeringPending
	routes, exhausted, err := FindCandidateCloudRoutes(imp, "subnet-a", "subnet-c", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 0 {
		t.Fatalf("got %d routes, want 0 -- a pending peering must not be a usable route edge", len(routes))
	}
	if exhausted {
		t.Fatal("a small topology with no usable edge must report exhausted=false (fully explored), not true (truncated)")
	}
}

func TestFindCandidateCloudRoutes_SameSubnet_TrivialRoute(t *testing.T) {
	imp := threeHopImport()
	routes, _, err := FindCandidateCloudRoutes(imp, "subnet-a", "subnet-a", 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 || len(routes[0]) != 1 {
		t.Fatalf("routes = %v, want one trivial single-element route", routes)
	}
}

// TestFindCandidateCloudRoutes_DenseMesh_ExhaustsBudget pins Review
// Focus #4 with a genuinely dense, highly interconnected mesh (every
// subnet locally routed to every other subnet in the same network,
// across many networks chained by active peerings) sized to reliably
// blow maxRouteSearchSteps=20000 before the search can prove no route
// exists to an unreachable target -- mirroring Phase 3's own final-
// review requirement for a deliberately dense fixture, not a trivial
// one.
func TestFindCandidateCloudRoutes_DenseMesh_ExhaustsBudget(t *testing.T) {
	const networks = 8
	const subnetsPerNetwork = 6
	imp := &CloudTopologyImport{}
	for n := 0; n < networks; n++ {
		netID := vpcID(n)
		imp.Networks = append(imp.Networks, CloudNetwork{CanonicalID: netID})
		for s := 0; s < subnetsPerNetwork; s++ {
			imp.Subnets = append(imp.Subnets, CloudSubnet{CanonicalID: subnetID(n, s), NetworkID: netID, CIDRBlock: subnetCIDR(n, s)})
		}
		for s := 0; s < subnetsPerNetwork; s++ {
			for t := 0; t < subnetsPerNetwork; t++ {
				if s == t {
					continue
				}
				imp.Routes = append(imp.Routes, RouteTableEntry{SubnetID: subnetID(n, s), DestinationCIDR: subnetCIDR(n, t), Target: TargetLocal})
			}
		}
		if n > 0 {
			peerID := peeringID(n - 1)
			imp.Peerings = append(imp.Peerings, PeeringConnection{CanonicalID: peerID, NetworkAID: vpcID(n - 1), NetworkBID: netID, State: PeeringActive})
			for s := 0; s < subnetsPerNetwork; s++ {
				imp.Routes = append(imp.Routes, RouteTableEntry{SubnetID: subnetID(n-1, s), DestinationCIDR: subnetCIDR(n, 0), Target: TargetPeering, TargetRef: peerID})
				imp.Routes = append(imp.Routes, RouteTableEntry{SubnetID: subnetID(n, s), DestinationCIDR: subnetCIDR(n-1, 0), Target: TargetPeering, TargetRef: peerID})
			}
		}
	}
	// An isolated subnet in its own, otherwise-unconnected network --
	// no route can ever reach it, but the search must exhaust its step
	// budget exploring the dense mesh above before it could prove that.
	imp.Networks = append(imp.Networks, CloudNetwork{CanonicalID: "vpc-isolated"})
	imp.Subnets = append(imp.Subnets, CloudSubnet{CanonicalID: "subnet-isolated", NetworkID: "vpc-isolated", CIDRBlock: "192.168.99.0/24"})

	_, exhausted, err := FindCandidateCloudRoutes(imp, subnetID(0, 0), "subnet-isolated", MaxHopsPerPathQuery)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !exhausted {
		t.Fatal("want exhausted=true -- a dense mesh this large must blow the step budget before exhaustively ruling out the isolated subnet")
	}
}

func vpcID(n int) string       { return "vpc-" + itoa(n) }
func subnetID(n, s int) string { return "subnet-" + itoa(n) + "-" + itoa(s) }
func peeringID(n int) string   { return "peer-" + itoa(n) }
func subnetCIDR(n, s int) string {
	return "10." + itoa(n) + "." + itoa(s) + ".0/24"
}
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cloudtopology/... -run "TestSubnetForHost|TestFindCandidateCloudRoutes" -v`
Expected: FAIL — `SubnetForHost`/`FindCandidateCloudRoutes`/`CloudRoutePath` undefined.

- [ ] **Step 3: Write `resolve.go`**

```go
// orchestrator/internal/cloudtopology/resolve.go
package cloudtopology

import (
	"fmt"
	"net"
)

// SubnetForHost returns the CanonicalID of the subnet whose CIDRBlock
// contains host (a literal IP address). More than one match is
// ambiguous and returns an error rather than picking one arbitrarily
// -- the same discipline as networktopology.ZoneForHost.
func SubnetForHost(host string, subnets []CloudSubnet) (string, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		return "", fmt.Errorf("cloudtopology: %q is not a literal IP address", host)
	}
	var matches []string
	for _, s := range subnets {
		_, ipNet, err := net.ParseCIDR(s.CIDRBlock)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			matches = append(matches, s.CanonicalID)
		}
	}
	if len(matches) == 0 {
		return "", fmt.Errorf("cloudtopology: no declared subnet contains host %q", host)
	}
	if len(matches) > 1 {
		return "", fmt.Errorf("cloudtopology: host %q matches multiple subnets (%v) -- ambiguous", host, matches)
	}
	return matches[0], nil
}
```

- [ ] **Step 4: Write `routes.go`**

```go
// orchestrator/internal/cloudtopology/routes.go
package cloudtopology

import (
	"fmt"
	"net"
)

// CloudRoutePath is an ordered sequence of subnet CanonicalIDs from
// source to destination, inclusive of both endpoints -- same shape as
// networktopology.RoutePath.
type CloudRoutePath []string

// FindCandidateCloudRoutes returns up to MaxCandidateRoutesPerQuery
// simple paths (no repeated subnet) from sourceSubnetID to
// destSubnetID, each at most maxHops edges long (clamped to
// MaxHopsPerPathQuery, or defaulted to it when zero/negative). A
// same-network local route (a TargetLocal RouteTableEntry on the
// current subnet covering the destination's CIDR) connects two
// subnets in one network; a cross-network hop requires a TargetPeering
// RouteTableEntry referencing a PeeringConnection whose State ==
// PeeringActive -- a pending/rejected peering is real evidence of no
// route via that specific connection, never proof no other path
// exists. sourceSubnetID == destSubnetID always returns one trivial
// single-element route. Zero routes is a valid result, not an error.
//
// exhausted is true when the defensive maxRouteSearchSteps budget was
// hit before the search could either find MaxCandidateRoutesPerQuery
// routes or exhaustively rule out more. A zero-route result with
// exhausted=true means "search was truncated, absence is not
// proven"; exhausted=false means "search space was fully explored, no
// route exists" -- callers must not conflate the two.
func FindCandidateCloudRoutes(imp *CloudTopologyImport, sourceSubnetID, destSubnetID string, maxHops int) ([]CloudRoutePath, bool, error) {
	if len(imp.Subnets) > MaxSubnetsPerImport {
		return nil, false, fmt.Errorf("cloudtopology: topology has too many subnets -- got %d, max %d", len(imp.Subnets), MaxSubnetsPerImport)
	}
	if len(imp.Routes) > MaxRoutesPerImport {
		return nil, false, fmt.Errorf("cloudtopology: topology has too many routes -- got %d, max %d", len(imp.Routes), MaxRoutesPerImport)
	}
	if maxHops <= 0 || maxHops > MaxHopsPerPathQuery {
		maxHops = MaxHopsPerPathQuery
	}

	subnetByID := make(map[string]*CloudSubnet, len(imp.Subnets))
	for i := range imp.Subnets {
		subnetByID[imp.Subnets[i].CanonicalID] = &imp.Subnets[i]
	}
	if _, ok := subnetByID[sourceSubnetID]; !ok {
		return nil, false, fmt.Errorf("cloudtopology: subnet %q not found in this import", sourceSubnetID)
	}
	if _, ok := subnetByID[destSubnetID]; !ok {
		return nil, false, fmt.Errorf("cloudtopology: subnet %q not found in this import", destSubnetID)
	}
	if sourceSubnetID == destSubnetID {
		return []CloudRoutePath{{sourceSubnetID}}, false, nil
	}

	peeringByID := make(map[string]*PeeringConnection, len(imp.Peerings))
	for i := range imp.Peerings {
		peeringByID[imp.Peerings[i].CanonicalID] = &imp.Peerings[i]
	}
	adjacency := buildCloudAdjacency(imp, subnetByID, peeringByID)

	var routes []CloudRoutePath
	exhausted := false
	steps := 0
	visited := map[string]bool{sourceSubnetID: true}

	var dfs func(path []string) bool // returns true to stop the whole search
	dfs = func(path []string) bool {
		steps++
		if steps > maxRouteSearchSteps {
			exhausted = true
			return true
		}
		if len(routes) >= MaxCandidateRoutesPerQuery {
			return true
		}
		current := path[len(path)-1]
		if current == destSubnetID {
			routes = append(routes, append(CloudRoutePath{}, path...))
			return false
		}
		if len(path)-1 >= maxHops {
			return false
		}
		for _, next := range adjacency[current] {
			if visited[next] {
				continue
			}
			visited[next] = true
			stop := dfs(append(append([]string{}, path...), next))
			visited[next] = false
			if stop {
				return true
			}
		}
		return false
	}
	dfs([]string{sourceSubnetID})

	return routes, exhausted, nil
}

// buildCloudAdjacency returns, for each subnet, the subnets it has a
// usable route to.
func buildCloudAdjacency(imp *CloudTopologyImport, subnetByID map[string]*CloudSubnet, peeringByID map[string]*PeeringConnection) map[string][]string {
	adjacency := make(map[string][]string)
	for _, route := range imp.Routes {
		from, ok := subnetByID[route.SubnetID]
		if !ok {
			continue
		}
		switch route.Target {
		case TargetLocal:
			for _, s := range imp.Subnets {
				if s.NetworkID == from.NetworkID && s.CanonicalID != from.CanonicalID && cidrCovers(route.DestinationCIDR, s.CIDRBlock) {
					adjacency[from.CanonicalID] = append(adjacency[from.CanonicalID], s.CanonicalID)
				}
			}
		case TargetPeering:
			peer, ok := peeringByID[route.TargetRef]
			if !ok || peer.State != PeeringActive {
				continue
			}
			var peerNetworkID string
			switch {
			case peer.NetworkAID == from.NetworkID:
				peerNetworkID = peer.NetworkBID
			case peer.NetworkBID == from.NetworkID:
				peerNetworkID = peer.NetworkAID
			default:
				continue
			}
			for _, s := range imp.Subnets {
				if s.NetworkID == peerNetworkID && cidrCovers(route.DestinationCIDR, s.CIDRBlock) {
					adjacency[from.CanonicalID] = append(adjacency[from.CanonicalID], s.CanonicalID)
				}
			}
		}
	}
	return adjacency
}

func cidrCovers(destinationCIDR, subnetCIDR string) bool {
	_, destNet, err := net.ParseCIDR(destinationCIDR)
	if err != nil {
		return false
	}
	ip, _, err := net.ParseCIDR(subnetCIDR)
	if err != nil {
		return false
	}
	return destNet.Contains(ip)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/cloudtopology/... -run "TestSubnetForHost|TestFindCandidateCloudRoutes" -v`
Expected: PASS, all 6 tests. The dense-mesh test may take a moment (tens of thousands of recursive steps) but must complete well under the default test timeout.

- [ ] **Step 6: Run full package build and test**

Run: `go build ./... && go test ./internal/cloudtopology/... -v`
Expected: build clean, all tests PASS (Task 1's 6 + Task 2's 6 = 12).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/cloudtopology/resolve.go orchestrator/internal/cloudtopology/routes.go orchestrator/internal/cloudtopology/routes_test.go
git commit -m "feat(cloudtopology): add subnet host resolution and route/peering search

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Task 3: `internal/cloudpath` — Hop Composition

**Files:**
- Create: `orchestrator/internal/cloudpath/compose.go`
- Test: `orchestrator/internal/cloudpath/compose_test.go`

**Interfaces:**
- Consumes: `cloudtopology.CloudFlow`, `cloudtopology.SecurityGroupEvaluation` (Task 1); `cloudgraph.PathState`, `cloudgraph.Provenance`; `networkgraph.Target`, `networkgraph.NetworkObservation`.
- Produces: `type CloudHopResult struct { FromSubnet, ToSubnet string; State cloudgraph.PathState; Limitations string; Provenance cloudgraph.Provenance; Observation *networkgraph.NetworkObservation; SecurityGroupEvaluation *cloudtopology.SecurityGroupEvaluation; RouteFound bool }`; `func ComposeCloudHop(fromSubnet, toSubnet string, routeFound bool, sgEval *cloudtopology.SecurityGroupEvaluation, observations []networkgraph.NetworkObservation) CloudHopResult`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/cloudpath/compose_test.go
package cloudpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/networkgraph"
)

func TestComposeCloudHop_NoObservation_RouteFound_PolicyPassesThrough(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, nil)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q", hop.State, cloudgraph.PolicySupported)
	}
}

// TestComposeCloudHop_RouteFoundButPolicyDenies and
// TestComposeCloudHop_RouteAbsentButPolicyWouldPermit together pin the
// spec's core "two independent evidence questions" principle: route
// and policy must each be able to independently decide or override the
// other's naive expectation.
func TestComposeCloudHop_RouteFoundButPolicyDenies(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, nil)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- a found route never overrides a security-group deny", hop.State, cloudgraph.Blocked)
	}
}

func TestComposeCloudHop_RouteAbsentButPolicyWouldPermit(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}
	hop := ComposeCloudHop("subnet-a", "subnet-b", false, sgEval, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q -- an absent route forces Unknown even though policy would otherwise permit", hop.State, cloudgraph.Unknown)
	}
}

func TestComposeCloudHop_NoSecurityGroupEvaluation_Unknown(t *testing.T) {
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, nil, nil)
	if hop.State != cloudgraph.Unknown {
		t.Fatalf("State = %q, want %q", hop.State, cloudgraph.Unknown)
	}
}

// TestComposeCloudHop_RealObservation_WinsOutright pins Review Focus
// #5: a real NetworkObservation for this hop's flow must win outright
// over security-group evidence that would otherwise classify it
// differently (here: the observation shows Blocked while the
// security-group evaluation says PolicySupported).
func TestComposeCloudHop_RealObservation_WinsOutright(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{
		Flow:  cloudtopology.CloudFlow{DestCIDR: "10.0.2.5/32", Protocol: "tcp", Port: 443},
		State: cloudgraph.PolicySupported,
	}
	observations := []networkgraph.NetworkObservation{
		{Target: networkgraph.Target{Host: "10.0.2.5", Port: 443, Protocol: "tcp"}, State: cloudgraph.Blocked, Provenance: cloudgraph.Provenance{Confidence: "high"}},
	}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, observations)
	if hop.State != cloudgraph.Blocked {
		t.Fatalf("State = %q, want %q -- a real observation must win outright over security-group evidence", hop.State, cloudgraph.Blocked)
	}
	if hop.Observation == nil {
		t.Fatal("want Observation populated when a real match was found")
	}
}

func TestComposeCloudHop_ObservationForDifferentPort_DoesNotMatch(t *testing.T) {
	sgEval := &cloudtopology.SecurityGroupEvaluation{
		Flow:  cloudtopology.CloudFlow{DestCIDR: "10.0.2.5/32", Protocol: "tcp", Port: 443},
		State: cloudgraph.PolicySupported,
	}
	observations := []networkgraph.NetworkObservation{
		{Target: networkgraph.Target{Host: "10.0.2.5", Port: 22, Protocol: "tcp"}, State: cloudgraph.Blocked},
	}
	hop := ComposeCloudHop("subnet-a", "subnet-b", true, sgEval, observations)
	if hop.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q -- an observation for a different port must not match", hop.State, cloudgraph.PolicySupported)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cloudpath/... -run TestComposeCloudHop -v`
Expected: FAIL — package `cloudpath` does not exist yet.

- [ ] **Step 3: Write `compose.go`**

```go
// orchestrator/internal/cloudpath/compose.go

// Package cloudpath is the one place routing evidence and
// security-group evidence (internal/cloudtopology) and direct
// observation evidence (internal/networkgraph) are combined into
// classified, multi-hop cloud network paths -- and the one place
// cloud-topology evidence and Cloud BAS IAM evidence (internal/
// cloudgraph) are allowed to meet, additively (see correlate.go). It
// plays exactly the role internal/networkpath plays for on-premises
// evidence.
package cloudpath

import (
	"net"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/networkgraph"
)

// CloudHopResult is one hop's evidence-composed classification.
type CloudHopResult struct {
	FromSubnet              string                                 `json:"fromSubnet"`
	ToSubnet                string                                 `json:"toSubnet"`
	State                   cloudgraph.PathState                   `json:"state"`
	Limitations             string                                 `json:"limitations,omitempty"`
	Provenance              cloudgraph.Provenance                  `json:"provenance"`
	Observation             *networkgraph.NetworkObservation       `json:"observation,omitempty"`
	SecurityGroupEvaluation *cloudtopology.SecurityGroupEvaluation `json:"securityGroupEvaluation,omitempty"`
	RouteFound              bool                                   `json:"routeFound"`
}

// ComposeCloudHop classifies one hop, in priority order -- identical
// discipline to networkpath.ComposeHop:
//  1. A real NetworkObservation exists for this hop's flow: it wins
//     outright, regardless of routing/security-group evidence.
//  2. No observation, route found: the security-group verdict passes
//     through as-is.
//  3. No observation, route not found (or no security-group
//     evaluation at all): forced to Unknown, regardless of what the
//     security-group verdict would otherwise have been.
func ComposeCloudHop(fromSubnet, toSubnet string, routeFound bool, sgEval *cloudtopology.SecurityGroupEvaluation, observations []networkgraph.NetworkObservation) CloudHopResult {
	result := CloudHopResult{FromSubnet: fromSubnet, ToSubnet: toSubnet, RouteFound: routeFound, SecurityGroupEvaluation: sgEval}

	if sgEval != nil {
		if obs := matchingObservation(sgEval.Flow, observations); obs != nil {
			result.Observation = obs
			result.State = obs.State
			result.Provenance = obs.Provenance
			if !routeFound {
				result.Limitations = "no declared route for this hop, but a live observation demonstrates connectivity directly -- topology data may be incomplete"
			}
			return result
		}
	}

	if sgEval == nil {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no security-group evaluation available for this hop"
		return result
	}

	if !routeFound {
		result.State = cloudgraph.Unknown
		result.Provenance = cloudgraph.Provenance{Confidence: "none"}
		result.Limitations = "no route found between these subnets; security-group evidence alone does not establish that a path exists"
		return result
	}

	result.State = sgEval.State
	result.Provenance = sgEval.Provenance
	result.Limitations = sgEval.Limitations
	return result
}

// matchingObservation finds a real NetworkObservation whose Target
// falls within flow's destination CIDR and port -- the local
// equivalent of networkcorrelation.CorrelateReachability, re-grounded
// here since that function is typed to networkpolicy.PolicyEvaluation,
// not cloudtopology.SecurityGroupEvaluation.
func matchingObservation(flow cloudtopology.CloudFlow, observations []networkgraph.NetworkObservation) *networkgraph.NetworkObservation {
	if flow.DestCIDR == "" {
		return nil
	}
	_, destNet, err := net.ParseCIDR(flow.DestCIDR)
	if err != nil {
		return nil
	}
	for i := range observations {
		obs := &observations[i]
		if obs.Target.Port != flow.Port {
			continue
		}
		if flow.Protocol != "" && obs.Target.Protocol != "" && obs.Target.Protocol != flow.Protocol {
			continue
		}
		ip := net.ParseIP(obs.Target.Host)
		if ip == nil || !destNet.Contains(ip) {
			continue
		}
		return obs
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cloudpath/... -run TestComposeCloudHop -v`
Expected: PASS, all 6 tests.

- [ ] **Step 5: Run full build and package test**

Run: `go build ./... && go test ./internal/cloudpath/... -v`
Expected: build clean, all 6 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/cloudpath/compose.go orchestrator/internal/cloudpath/compose_test.go
git commit -m "feat(cloudpath): add hop composition combining routing, security-group, and observation evidence

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Task 4: `internal/cloudpath` — Path Aggregation

**Files:**
- Create: `orchestrator/internal/cloudpath/aggregate.go`
- Test: `orchestrator/internal/cloudpath/aggregate_test.go`

**Interfaces:**
- Consumes: `CloudHopResult` (Task 3).
- Produces: `type CloudPathResult struct { State cloudgraph.PathState; Confidence string; Hops []CloudHopResult }`; `func AggregateCloudPathState(hops []CloudHopResult) cloudgraph.PathState`; `func AggregateCloudConfidence(hopCount int, weakestHopConfidence string) string`; `func AggregateCloudPath(hops []CloudHopResult) CloudPathResult`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/cloudpath/aggregate_test.go
package cloudpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func TestAggregateCloudPathState_AnyBlockedWins(t *testing.T) {
	hops := []CloudHopResult{
		{State: cloudgraph.PolicySupported},
		{State: cloudgraph.Blocked},
		{State: cloudgraph.Observed},
	}
	if got := AggregateCloudPathState(hops); got != cloudgraph.Blocked {
		t.Fatalf("got %q, want %q", got, cloudgraph.Blocked)
	}
}

func TestAggregateCloudPathState_UnknownBeatsPolicySupported(t *testing.T) {
	hops := []CloudHopResult{{State: cloudgraph.PolicySupported}, {State: cloudgraph.Unknown}}
	if got := AggregateCloudPathState(hops); got != cloudgraph.Unknown {
		t.Fatalf("got %q, want %q", got, cloudgraph.Unknown)
	}
}

func TestAggregateCloudPathState_AllObserved(t *testing.T) {
	hops := []CloudHopResult{{State: cloudgraph.Observed}, {State: cloudgraph.Observed}}
	if got := AggregateCloudPathState(hops); got != cloudgraph.Observed {
		t.Fatalf("got %q, want %q", got, cloudgraph.Observed)
	}
}

func TestAggregateCloudPath_SingleHop_ConfidencePassesThroughConfidenceLabel(t *testing.T) {
	hops := []CloudHopResult{{State: cloudgraph.PolicySupported, Provenance: cloudgraph.Provenance{Confidence: "medium"}}}
	result := AggregateCloudPath(hops)
	if result.State != cloudgraph.PolicySupported {
		t.Fatalf("State = %q, want %q", result.State, cloudgraph.PolicySupported)
	}
	if result.Confidence == "" {
		t.Fatal("want a non-empty Confidence label")
	}
}

func TestAggregateCloudConfidence_NoneWhenWeakestHopHasNoEvidence(t *testing.T) {
	got := AggregateCloudConfidence(2, "none")
	if got != "none (2-hop chain; weakest link: none)" {
		t.Fatalf("got %q", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cloudpath/... -run "TestAggregateCloudPathState|TestAggregateCloudPath|TestAggregateCloudConfidence" -v`
Expected: FAIL — `AggregateCloudPathState`/`AggregateCloudPath`/`AggregateCloudConfidence`/`CloudPathResult` undefined.

- [ ] **Step 3: Write `aggregate.go`**

```go
// orchestrator/internal/cloudpath/aggregate.go
package cloudpath

import (
	"fmt"

	"github.com/audspect/bas/internal/cloudgraph"
)

// CloudPathResult is the full path-level result: an aggregated
// PathState and confidence, plus the per-hop detail it was derived
// from.
type CloudPathResult struct {
	State      cloudgraph.PathState `json:"state"`
	Confidence string               `json:"confidence"`
	Hops       []CloudHopResult     `json:"hops"`
}

// AggregateCloudPathState computes the path-level PathState from an
// ordered slice of per-hop results, following the exact ranking
// precedent networkpath.AggregatePathState already established on
// this same PathState enum: Blocked short-circuits immediately;
// otherwise weakest-wins in order Unknown > PolicySupported >
// Observed. Re-implemented locally rather than imported, matching
// networkpath's own precedent for keeping each evidence domain
// self-contained.
func AggregateCloudPathState(hops []CloudHopResult) cloudgraph.PathState {
	sawUnknown := false
	sawPolicySupported := false
	sawObserved := false
	for _, h := range hops {
		switch h.State {
		case cloudgraph.Blocked:
			return cloudgraph.Blocked
		case cloudgraph.Unknown:
			sawUnknown = true
		case cloudgraph.PolicySupported:
			sawPolicySupported = true
		case cloudgraph.Observed:
			sawObserved = true
		}
	}
	if sawUnknown {
		return cloudgraph.Unknown
	}
	if sawPolicySupported {
		return cloudgraph.PolicySupported
	}
	if sawObserved {
		return cloudgraph.Observed
	}
	return cloudgraph.Unknown
}

// AggregateCloudConfidence mirrors networkpath.AggregateConfidence
// exactly: "none" only when the weakest hop had no evidence at all,
// otherwise always "low" regardless of the weakest hop's own
// confidence -- chaining hops compounds uncertainty beyond any single
// hop's quality. Always annotated with hop-count and the weakest
// hop's own value.
func AggregateCloudConfidence(hopCount int, weakestHopConfidence string) string {
	label := "low"
	if weakestHopConfidence == "none" {
		label = "none"
	}
	return fmt.Sprintf("%s (%d-hop chain; weakest link: %s)", label, hopCount, weakestHopConfidence)
}

// AggregateCloudPath computes the full path-level result from an
// ordered slice of per-hop results.
func AggregateCloudPath(hops []CloudHopResult) CloudPathResult {
	state := AggregateCloudPathState(hops)
	return CloudPathResult{State: state, Confidence: AggregateCloudConfidence(len(hops), weakestCloudHopConfidence(hops, state)), Hops: hops}
}

// weakestCloudHopConfidence returns the Provenance.Confidence of the
// first hop whose State equals the path's own aggregated state -- the
// hop that actually determined it, per AggregateCloudPathState's
// ranking.
func weakestCloudHopConfidence(hops []CloudHopResult, pathState cloudgraph.PathState) string {
	for _, h := range hops {
		if h.State == pathState {
			return h.Provenance.Confidence
		}
	}
	if len(hops) > 0 {
		return hops[0].Provenance.Confidence
	}
	return "none"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cloudpath/... -v`
Expected: PASS, all 11 tests (Task 3's 6 + Task 4's 5).

- [ ] **Step 5: Run full build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/cloudpath/aggregate.go orchestrator/internal/cloudpath/aggregate_test.go
git commit -m "feat(cloudpath): add path-level aggregation

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Task 5: `internal/cloudpath` — Cloud BAS Correlation (Reporting-Layer Only)

**Files:**
- Create: `orchestrator/internal/cloudpath/correlate.go`
- Test: `orchestrator/internal/cloudpath/correlate_test.go`

**Interfaces:**
- Consumes: `CloudPathResult` (Task 4); `cloudgraph.EvaluationResult`, `cloudgraph.AccountScope`.
- Produces: `type CloudFindingCorrelation struct { Source, Account, Note string }`; `func CorrelateCloudFinding(path CloudPathResult, iamFinding cloudgraph.EvaluationResult, account cloudgraph.AccountScope) *CloudFindingCorrelation`.

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/cloudpath/correlate_test.go
package cloudpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

// TestCorrelateCloudFinding_DemonstratesReportLayerCorrelation
// satisfies the spec's §2/§5.3 Definition-of-Done requirement: a
// report-layer example correlating a cloud-topology path result with
// a Cloud BAS IAM finding for the same account, without merging their
// verdicts -- built from a synthetic/fixture EvaluationResult, since
// the Cloud BAS Initiative itself is currently held with no live
// evaluation pipeline.
func TestCorrelateCloudFinding_DemonstratesReportLayerCorrelation(t *testing.T) {
	path := CloudPathResult{State: cloudgraph.PolicySupported}
	iamFinding := cloudgraph.EvaluationResult{State: cloudgraph.ConditionallyReachable, AllowedBy: "identity-policy"}
	account := cloudgraph.AccountScope{Provider: "aws", AccountID: "111122223333"}

	correlation := CorrelateCloudFinding(path, iamFinding, account)
	if correlation == nil {
		t.Fatal("want a non-nil correlation when an account is given")
	}
	if correlation.Source != "cloudgraph" {
		t.Fatalf("Source = %q, want %q", correlation.Source, "cloudgraph")
	}
	if correlation.Account != "111122223333" {
		t.Fatalf("Account = %q, want %q", correlation.Account, "111122223333")
	}
	// The correlation must never alter the path's own verdict -- it is
	// purely additive context.
	if path.State != cloudgraph.PolicySupported {
		t.Fatalf("path.State changed to %q -- correlation must never mutate the path's own State", path.State)
	}
}

func TestCorrelateCloudFinding_ZeroAccountScope_NilCorrelation(t *testing.T) {
	path := CloudPathResult{State: cloudgraph.Blocked}
	iamFinding := cloudgraph.EvaluationResult{State: cloudgraph.Blocked}
	if got := CorrelateCloudFinding(path, iamFinding, cloudgraph.AccountScope{}); got != nil {
		t.Fatalf("got %v, want nil for a zero-value account scope -- nothing to cite", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cloudpath/... -run TestCorrelateCloudFinding -v`
Expected: FAIL — `CorrelateCloudFinding`/`CloudFindingCorrelation` undefined.

- [ ] **Step 3: Write `correlate.go`**

```go
// orchestrator/internal/cloudpath/correlate.go
package cloudpath

import (
	"fmt"

	"github.com/audspect/bas/internal/cloudgraph"
)

// CloudFindingCorrelation is purely additive context cited from a
// Cloud BAS IAM evaluation. It never changes a CloudPathResult's own
// State -- a report may say "this network path and this IAM finding
// both involve account X", never "therefore this IAM finding is more
// or less exploitable". Mirrors networkpath.CorroboratingEvidence's
// own additive-only discipline.
type CloudFindingCorrelation struct {
	Source  string `json:"source"` // "cloudgraph"
	Account string `json:"account"`
	Note    string `json:"note,omitempty"`
}

// CorrelateCloudFinding cites a Cloud BAS IAM evaluation result
// alongside a cloud path result when both reference the same
// account -- matching only on AccountScope, nothing deeper (no
// inference that the IAM path and the network path involve the same
// specific resource). Returns nil only when there is nothing to cite
// (a zero-value account), never when the finding is "uninteresting" --
// interest judgments belong to the report layer, not this function.
func CorrelateCloudFinding(path CloudPathResult, iamFinding cloudgraph.EvaluationResult, account cloudgraph.AccountScope) *CloudFindingCorrelation {
	if account == (cloudgraph.AccountScope{}) {
		return nil
	}
	return &CloudFindingCorrelation{
		Source:  "cloudgraph",
		Account: account.AccountID,
		Note:    fmt.Sprintf("cloud network path (%s) and IAM finding (%s) both reference account %s -- cited together, not merged", path.State, iamFinding.State, account.AccountID),
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cloudpath/... -v`
Expected: PASS, all 13 tests.

- [ ] **Step 5: Run full build**

Run: `go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/cloudpath/correlate.go orchestrator/internal/cloudpath/correlate_test.go
git commit -m "feat(cloudpath): add additive Cloud BAS IAM-finding correlation

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Task 6: Persistence — `cloud_topology_imports`

**Files:**
- Create: `orchestrator/internal/db/cloudtopology_store.go`
- Test: `orchestrator/internal/db/cloudtopology_store_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go:161-164` (immediately after the existing `EnsureTransportSecurityCheckSchema` call)
- Modify: `orchestrator/cmd/server/main.go:308` area (immediately after the existing `EnsureTransportSecurityCheckSchema` call)

**Interfaces:**
- Consumes: `cloudtopology.CloudTopologyImport` and its nested types (Task 1); the existing `nullableString(s string) *string` helper already defined in `orchestrator/internal/db/networkdiscovery_store.go:78` (same `db` package — do not redefine).
- Produces: `func EnsureCloudTopologySchema(ctx context.Context, pool *pgxpool.Pool) error`; `func InsertCloudTopologyImport(ctx context.Context, pool *pgxpool.Pool, imp *cloudtopology.CloudTopologyImport) error`; `func GetCloudTopologyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*cloudtopology.CloudTopologyImport, error)` (404 via `errors.Is(err, pgx.ErrNoRows)`); `func ListCloudTopologyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*cloudtopology.CloudTopologyImport, error)`.

- [ ] **Step 1: Check free memory before any `internal/db` test run**

Run: `Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize`
If free memory is below ~1GB, check `docker ps`/`tasklist` for stray orphaned testcontainers or `*.test.exe` processes before proceeding (per Global Constraints — this is normal/expected on this host, not something to fix).

- [ ] **Step 2: Write the failing test**

```go
// orchestrator/internal/db/cloudtopology_store_test.go
package db

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudtopology"
)

func testCloudTopologyImport(id string) *cloudtopology.CloudTopologyImport {
	return &cloudtopology.CloudTopologyImport{
		ID:         id,
		SourceType: "manual",
		Networks:   []cloudtopology.CloudNetwork{{CanonicalID: "vpc-1", CIDRBlocks: []string{"10.0.0.0/16"}}},
		Subnets:    []cloudtopology.CloudSubnet{{CanonicalID: "subnet-1", NetworkID: "vpc-1", CIDRBlock: "10.0.1.0/24"}},
		Groups:     []cloudtopology.SecurityGroup{{CanonicalID: "sg-1", NetworkID: "vpc-1", Scope: cloudtopology.ScopeNetwork}},
		Rules: []cloudtopology.SecurityGroupRule{
			{ID: "r1", GroupID: "sg-1", Order: 10, Direction: cloudtopology.DirectionOutbound, Action: cloudtopology.ActionAllow, Protocol: "tcp", PortRange: "443", CIDR: "0.0.0.0/0"},
		},
		Routes:   []cloudtopology.RouteTableEntry{{ID: "rt-1", SubnetID: "subnet-1", DestinationCIDR: "0.0.0.0/0", Target: cloudtopology.TargetInternetGateway}},
		Peerings: nil,
	}
}

func TestCloudTopologyImport_InsertGetList_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		imp := testCloudTopologyImport(newID())
		if err := InsertCloudTopologyImport(ctx, pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := GetCloudTopologyImport(ctx, pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if len(got.Subnets) != 1 || got.Subnets[0].CanonicalID != "subnet-1" {
			t.Fatalf("Subnets round-tripped as %v", got.Subnets)
		}
		if len(got.Rules) != 1 || got.Rules[0].ID != "r1" {
			t.Fatalf("Rules round-tripped as %v", got.Rules)
		}

		list, err := ListCloudTopologyImports(ctx, pool, 10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, l := range list {
			if l.ID == imp.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted import not present in list")
		}
	})
}

func TestGetCloudTopologyImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := GetCloudTopologyImport(context.Background(), pool, "does-not-exist")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/db/... -run TestCloudTopologyImport -v`
Expected: FAIL — `EnsureCloudTopologySchema`/`InsertCloudTopologyImport` etc. undefined, and the table doesn't exist yet in `testdb.go`'s setup.

- [ ] **Step 4: Write `cloudtopology_store.go`**

```go
// orchestrator/internal/db/cloudtopology_store.go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudtopology"
)

// EnsureCloudTopologySchema creates the cloud_topology_imports table.
func EnsureCloudTopologySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS cloud_topology_imports (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type    text        NOT NULL,
			imported_by    text,
			imported_at    timestamptz NOT NULL DEFAULT NOW(),
			config_version text,
			limitations    text[],
			topology_data  jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("cloud_topology_imports: ensure schema: %w", err)
	}
	return nil
}

// cloudTopologyData is the shape persisted in the topology_data jsonb
// column -- just the six slices that make an import's content, not
// its metadata (which live in their own columns).
type cloudTopologyData struct {
	Networks []cloudtopology.CloudNetwork      `json:"networks"`
	Subnets  []cloudtopology.CloudSubnet       `json:"subnets"`
	Groups   []cloudtopology.SecurityGroup     `json:"groups"`
	Rules    []cloudtopology.SecurityGroupRule `json:"rules"`
	Routes   []cloudtopology.RouteTableEntry   `json:"routes"`
	Peerings []cloudtopology.PeeringConnection `json:"peerings"`
}

// InsertCloudTopologyImport writes a new cloud_topology_imports row.
// The caller supplies imp.ID already generated.
func InsertCloudTopologyImport(ctx context.Context, pool *pgxpool.Pool, imp *cloudtopology.CloudTopologyImport) error {
	data, err := json.Marshal(cloudTopologyData{
		Networks: imp.Networks, Subnets: imp.Subnets, Groups: imp.Groups,
		Rules: imp.Rules, Routes: imp.Routes, Peerings: imp.Peerings,
	})
	if err != nil {
		return fmt.Errorf("cloud_topology_imports: marshal topology data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO cloud_topology_imports (id, source_type, imported_by, config_version, limitations, topology_data)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("cloud_topology_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanCloudTopologyImport(row pgx.Row) (*cloudtopology.CloudTopologyImport, error) {
	imp := &cloudtopology.CloudTopologyImport{}
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
	var td cloudTopologyData
	if err := json.Unmarshal(data, &td); err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: unmarshal topology data for %s: %w", imp.ID, err)
	}
	imp.Networks, imp.Subnets, imp.Groups = td.Networks, td.Subnets, td.Groups
	imp.Rules, imp.Routes, imp.Peerings = td.Rules, td.Routes, td.Peerings
	return imp, nil
}

// GetCloudTopologyImport returns one import by id. A missing id
// returns an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetCloudTopologyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*cloudtopology.CloudTopologyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM cloud_topology_imports WHERE id = $1`, id)
	imp, err := scanCloudTopologyImport(row)
	if err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListCloudTopologyImports returns up to limit rows, newest first.
func ListCloudTopologyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*cloudtopology.CloudTopologyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, limitations, topology_data
		 FROM cloud_topology_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*cloudtopology.CloudTopologyImport
	for rows.Next() {
		imp, err := scanCloudTopologyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("cloud_topology_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cloud_topology_imports: list rows: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 5: Wire the schema into `testdb.go`**

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block ending at line 164 (`return nil, fmt.Errorf("testutil: EnsureTransportSecurityCheckSchema: %w", err)` / `}`), add:

```go
	if err := db.EnsureCloudTopologySchema(ctx, pool); err != nil {
		pool.Close()
		return nil, fmt.Errorf("testutil: EnsureCloudTopologySchema: %w", err)
	}
```

(Match the exact if/pool.Close()/return three-line shape the two calls immediately above it already use — re-read those lines in the file before editing, since this plan's line numbers may have shifted.)

- [ ] **Step 6: Wire the schema into `main.go`**

In `orchestrator/cmd/server/main.go`, immediately after the existing `EnsureTransportSecurityCheckSchema` call (around line 308), add the matching call:

```go
	if err := db.EnsureCloudTopologySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("EnsureCloudTopologySchema: %v", err)
	}
```

(Match whatever exact error-handling form — `log.Fatalf` vs. another pattern — the `EnsureTransportSecurityCheckSchema` call immediately above it actually uses; re-read that line before editing.)

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/db/... -run TestCloudTopologyImport -v`
Expected: PASS, both tests.

- [ ] **Step 8: Run full build and the scoped db test**

Run: `go build ./... && go test ./internal/db/... -run "TestCloudTopologyImport|TestGetCloudTopologyImport" -v`
Expected: build clean, both tests PASS. Do not run the unscoped `./internal/db/...` suite (Global Constraints — host RAM).

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/db/cloudtopology_store.go orchestrator/internal/db/cloudtopology_store_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(db): add cloud_topology_imports persistence

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Task 7: API — Cloud Topology Import Endpoint

**Files:**
- Create: `orchestrator/internal/api/cloudtopology_handlers.go`
- Test: `orchestrator/internal/api/cloudtopology_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go:237` area (new permission const, after `CanImportNetworkControlExpectation`) and its two `rolePermissions` map entries (`RoleAdmin` around line 298, `RoleAnalyst` around line 314)
- Modify: `orchestrator/internal/api/routes.go` (new GET routes near line 257, new POST route near line 433)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (new rows near line 70 and line 219)

**Interfaces:**
- Consumes: `cloudtopology.CloudTopologyImport` and nested types (Task 1); `db.InsertCloudTopologyImport`/`GetCloudTopologyImport`/`ListCloudTopologyImports` (Task 6); `networkpolicy.ParsePortRange` (already used by Task 1, reused again here for the same validation purpose).
- Produces: `auth.CanImportCloudTopology` permission; `(h *Handler) CreateCloudTopologyImport`, `(h *Handler) ListCloudTopologyImports`, `(h *Handler) GetCloudTopologyImport` HTTP handlers.

- [ ] **Step 1: Add the permission**

In `orchestrator/internal/auth/permissions.go`, immediately after the `CanImportNetworkControlExpectation` const declaration (re-read the file around line 233-238 first — line numbers shift), add:

```go
	// cloud-topology:import gates importing a normalized cloud
	// network topology (VPCs, subnets, security groups, route tables,
	// peering -- Network BAS Phase 6A) -- same placement as
	// CanImportNetworkTopology, for the same reason.
	CanImportCloudTopology Permission = "cloud-topology:import"
```

Then add `CanImportCloudTopology: true,` to both the `RoleAdmin` map (next to the existing `CanImportNetworkControlExpectation: true,` line) and the `RoleAnalyst` map (next to its own `CanImportNetworkControlExpectation: true,` on the same line as `CanImportNetworkPolicy`/`CanImportNetworkTopology`).

- [ ] **Step 2: Write the failing tests**

```go
// orchestrator/internal/api/cloudtopology_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validCloudTopologyImportBody() map[string]any {
	return map[string]any{
		"sourceType": "manual",
		"networks":   []map[string]any{{"canonicalId": "vpc-1", "cidrBlocks": []string{"10.0.0.0/16"}}},
		"subnets":    []map[string]any{{"canonicalId": "subnet-1", "networkId": "vpc-1", "cidrBlock": "10.0.1.0/24"}},
		"groups":     []map[string]any{{"canonicalId": "sg-1", "networkId": "vpc-1", "scope": "network"}},
		"rules": []map[string]any{
			{"id": "r1", "groupId": "sg-1", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "0.0.0.0/0"},
		},
		"routes": []map[string]any{
			{"id": "rt-1", "subnetId": "subnet-1", "destinationCidr": "0.0.0.0/0", "target": "internet-gateway"},
		},
	}
}

func TestCreateCloudTopologyImport_Valid_Created(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validCloudTopologyImportBody())
		userID := seedUser(t, pool, "cloudtopo-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateCloudTopologyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var created cloudtopology.CloudTopologyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if created.ID == "" {
			t.Fatal("want non-empty ID")
		}
	})
}

// TestCreateCloudTopologyImport_UnresolvedGroupWithoutLimitations_Rejected
// pins Review Focus #1 at the import-validation boundary: a
// ScopeUnresolved group declared without a non-empty top-level
// Limitations entry must be rejected, not silently accepted.
func TestCreateCloudTopologyImport_UnresolvedGroupWithoutLimitations_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudTopologyImportBody()
		body["groups"] = []map[string]any{{"canonicalId": "sg-1", "networkId": "vpc-1", "scope": "unresolved"}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "cloudtopo-op-unresolved", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateCloudTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateCloudTopologyImport_SGReferenceRuleWithoutUnresolvedAction_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validCloudTopologyImportBody()
		body["rules"] = []map[string]any{
			{"id": "r1", "groupId": "sg-1", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "referencedGroupId": "sg-2"},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "cloudtopo-op-sgref", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateCloudTopologyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400 -- an SG-to-SG reference rule cannot be resolved by this schema and must be marked unresolved, never allow/deny", rec.Code, rec.Body.String())
		}
	})
}

func TestListAndGetCloudTopologyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		b, _ := json.Marshal(validCloudTopologyImportBody())
		userID := seedUser(t, pool, "cloudtopo-op-rt", "pw12345678", string(auth.RoleAnalyst), true)
		createReq := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		createRec := callAuthed(h.CreateCloudTopologyImport, createReq)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created cloudtopology.CloudTopologyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/cloud-topology-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListCloudTopologyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/cloud-topology-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetCloudTopologyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/api/... -run "TestCreateCloudTopologyImport|TestListAndGetCloudTopologyImport" -v`
Expected: FAIL — `h.CreateCloudTopologyImport` etc. undefined, and `auth.CanImportCloudTopology` undefined.

- [ ] **Step 4: Write `cloudtopology_handlers.go`**

```go
// orchestrator/internal/api/cloudtopology_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkpolicy"
)

const maxCloudTopologyImportRequestBytes = 5 << 20

// CreateCloudTopologyImport -- POST /api/cloud-topology-imports.
func (h *Handler) CreateCloudTopologyImport(w http.ResponseWriter, r *http.Request) {
	var req cloudtopology.CloudTopologyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCloudTopologyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateCloudTopologyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertCloudTopologyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "cloudtopology.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "cloudtopology.import", req.ID, map[string]any{"subnetCount": len(req.Subnets), "ruleCount": len(req.Rules)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateCloudTopologyImport(imp *cloudtopology.CloudTopologyImport) error {
	if len(imp.Subnets) == 0 {
		return fmt.Errorf("at least one subnet is required")
	}
	if len(imp.Subnets) > cloudtopology.MaxSubnetsPerImport {
		return fmt.Errorf("too many subnets — got %d, max %d", len(imp.Subnets), cloudtopology.MaxSubnetsPerImport)
	}
	if len(imp.Rules) > cloudtopology.MaxRulesPerImport {
		return fmt.Errorf("too many rules — got %d, max %d", len(imp.Rules), cloudtopology.MaxRulesPerImport)
	}
	if len(imp.Routes) > cloudtopology.MaxRoutesPerImport {
		return fmt.Errorf("too many routes — got %d, max %d", len(imp.Routes), cloudtopology.MaxRoutesPerImport)
	}

	networkIDs := make(map[string]bool, len(imp.Networks))
	for i, n := range imp.Networks {
		if n.CanonicalID == "" {
			return fmt.Errorf("networks[%d]: canonicalId required", i)
		}
		networkIDs[n.CanonicalID] = true
		for _, c := range n.CIDRBlocks {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("networks[%d]: invalid cidrBlock %q", i, c)
			}
		}
	}
	subnetIDs := make(map[string]bool, len(imp.Subnets))
	for i, s := range imp.Subnets {
		if s.CanonicalID == "" {
			return fmt.Errorf("subnets[%d]: canonicalId required", i)
		}
		if !networkIDs[s.NetworkID] {
			return fmt.Errorf("subnets[%d]: networkId %q not found in networks", i, s.NetworkID)
		}
		if _, _, err := net.ParseCIDR(s.CIDRBlock); err != nil {
			return fmt.Errorf("subnets[%d]: invalid cidrBlock %q", i, s.CIDRBlock)
		}
		subnetIDs[s.CanonicalID] = true
	}

	hasLimitations := len(imp.Limitations) > 0
	groupIDs := make(map[string]bool, len(imp.Groups))
	for i, g := range imp.Groups {
		if g.CanonicalID == "" {
			return fmt.Errorf("groups[%d]: canonicalId required", i)
		}
		switch g.Scope {
		case cloudtopology.ScopeNetwork:
			if !networkIDs[g.NetworkID] {
				return fmt.Errorf("groups[%d]: networkId %q not found in networks", i, g.NetworkID)
			}
		case cloudtopology.ScopeSubnet:
			if !subnetIDs[g.SubnetID] {
				return fmt.Errorf("groups[%d]: subnetId %q not found in subnets", i, g.SubnetID)
			}
		case cloudtopology.ScopeUnresolved:
			if !hasLimitations {
				return fmt.Errorf("limitations must be non-empty when any group has unresolved scope")
			}
		default:
			return fmt.Errorf("groups[%d]: unknown scope %q", i, g.Scope)
		}
		groupIDs[g.CanonicalID] = true
	}

	for i, rule := range imp.Rules {
		if !groupIDs[rule.GroupID] {
			return fmt.Errorf("rules[%d]: groupId %q not found in groups", i, rule.GroupID)
		}
		if rule.Direction != cloudtopology.DirectionInbound && rule.Direction != cloudtopology.DirectionOutbound {
			return fmt.Errorf("rules[%d]: direction must be %q or %q", i, cloudtopology.DirectionInbound, cloudtopology.DirectionOutbound)
		}
		if rule.CIDR == "" && rule.ReferencedGroupID == "" {
			return fmt.Errorf("rules[%d]: exactly one of cidr or referencedGroupId is required", i)
		}
		if rule.CIDR != "" && rule.ReferencedGroupID != "" {
			return fmt.Errorf("rules[%d]: exactly one of cidr or referencedGroupId is required, not both", i)
		}
		switch rule.Action {
		case cloudtopology.ActionAllow, cloudtopology.ActionDeny:
			if rule.ReferencedGroupID != "" {
				return fmt.Errorf("rules[%d]: a security-group-reference rule cannot be resolved by this schema -- action must be %q, not %q", i, cloudtopology.ActionUnresolved, rule.Action)
			}
		case cloudtopology.ActionUnresolved:
			if rule.Note == "" {
				return fmt.Errorf("rules[%d]: note required when action is unresolved", i)
			}
			if !hasLimitations {
				return fmt.Errorf("limitations must be non-empty when any rule is unresolved")
			}
		default:
			return fmt.Errorf("rules[%d]: unknown action %q", i, rule.Action)
		}
		if rule.CIDR != "" {
			if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
				return fmt.Errorf("rules[%d]: invalid cidr %q", i, rule.CIDR)
			}
		}
		if _, _, _, err := networkpolicy.ParsePortRange(rule.PortRange); err != nil {
			return fmt.Errorf("rules[%d]: %v", i, err)
		}
	}

	for i, route := range imp.Routes {
		if !subnetIDs[route.SubnetID] {
			return fmt.Errorf("routes[%d]: subnetId %q not found in subnets", i, route.SubnetID)
		}
		if _, _, err := net.ParseCIDR(route.DestinationCIDR); err != nil {
			return fmt.Errorf("routes[%d]: invalid destinationCidr %q", i, route.DestinationCIDR)
		}
	}
	for i, p := range imp.Peerings {
		if !networkIDs[p.NetworkAID] {
			return fmt.Errorf("peerings[%d]: networkAId %q not found in networks", i, p.NetworkAID)
		}
		if !networkIDs[p.NetworkBID] {
			return fmt.Errorf("peerings[%d]: networkBId %q not found in networks", i, p.NetworkBID)
		}
	}
	return nil
}

// ListCloudTopologyImports -- GET /api/cloud-topology-imports.
func (h *Handler) ListCloudTopologyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListCloudTopologyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*cloudtopology.CloudTopologyImport{}
	}
	respond(w, imports)
}

// GetCloudTopologyImport -- GET /api/cloud-topology-imports/{id}.
func (h *Handler) GetCloudTopologyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetCloudTopologyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "cloud topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
```

- [ ] **Step 5: Wire the routes**

In `orchestrator/internal/api/routes.go`, add two GET routes immediately after the existing `network-topology-imports` GET routes (re-read around line 256-257 first):

```go
		r.Get("/api/cloud-topology-imports", h.ListCloudTopologyImports)
		r.Get("/api/cloud-topology-imports/{id}", h.GetCloudTopologyImport)
```

And add the POST route immediately after the existing `network-topology-imports` POST route (re-read around line 433 first):

```go
		r.With(auth.RequirePermission(auth.CanImportCloudTopology)).Post("/api/cloud-topology-imports", h.CreateCloudTopologyImport)
```

- [ ] **Step 6: Add the RBAC matrix rows**

In `orchestrator/internal/api/rbac_matrix_test.go`, add immediately after the existing `network-topology-imports` GET rows (re-read around line 69-70 first):

```go
	{http.MethodGet, "/api/cloud-topology-imports", tierAny, ""},
	{http.MethodGet, "/api/cloud-topology-imports/{id}", tierAny, ""},
```

And immediately after the existing `network-topology-imports` POST row (re-read around line 219 first):

```go
	{http.MethodPost, "/api/cloud-topology-imports", tierPermission, auth.CanImportCloudTopology},
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/api/... -run "TestCreateCloudTopologyImport|TestListAndGetCloudTopologyImport" -v`
Expected: PASS, all 4 tests.

- [ ] **Step 8: Run the RBAC matrix test and full build**

Run: `go build ./... && go test ./internal/api/... -run "TestRBACMatrix|TestCreateCloudTopologyImport|TestListAndGetCloudTopologyImport" -v`
Expected: build clean, all tests PASS including the full RBAC matrix (confirms the new routes/permission are wired correctly end-to-end). Check free memory first per Global Constraints; do not run the unscoped `internal/api` suite.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/api/cloudtopology_handlers.go orchestrator/internal/api/cloudtopology_handlers_test.go orchestrator/internal/auth/permissions.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add cloud topology import endpoints

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Task 8: API — Cloud Path Query Endpoint

**Files:**
- Create: `orchestrator/internal/api/cloudpath_handlers.go`
- Test: `orchestrator/internal/api/cloudpath_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (new GET-less single POST route, immediately after the Task 7 import POST route and after the existing `network-paths` POST route near line 435)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (new row immediately after the existing `network-paths` POST row near line 221)

**Interfaces:**
- Consumes: `cloudtopology.SubnetForHost`, `cloudtopology.FindCandidateCloudRoutes`, `cloudtopology.EvaluateSecurityGroupRules`, `cloudtopology.CloudFlow` (Tasks 1-2); `cloudpath.ComposeCloudHop`, `cloudpath.AggregateCloudPath`, `cloudpath.CloudPathResult` (Tasks 3-4); `db.GetCloudTopologyImport` (Task 6); existing `db.GetNetworkDiscoveryRun`/`db.ListNetworkObservationsByRun` (Phase 1, unchanged).
- Produces: `(h *Handler) FindCloudPaths` HTTP handler, mounted at `POST /api/cloud-paths`, gated by the same `auth.CanImportCloudTopology` permission Task 7 added (same placement rationale as `network-paths` reusing `CanImportNetworkTopology`).

- [ ] **Step 1: Write the failing tests**

```go
// orchestrator/internal/api/cloudpath_handlers_test.go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/cloudpath"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createCloudTopologyImportForPathTest(t *testing.T, h *Handler, userID string) string {
	t.Helper()
	body := map[string]any{
		"sourceType": "manual",
		"networks":   []map[string]any{{"canonicalId": "vpc-1", "cidrBlocks": []string{"10.0.0.0/16"}}},
		"subnets": []map[string]any{
			{"canonicalId": "subnet-a", "networkId": "vpc-1", "cidrBlock": "10.0.1.0/24"},
			{"canonicalId": "subnet-b", "networkId": "vpc-1", "cidrBlock": "10.0.2.0/24"},
		},
		"groups": []map[string]any{{"canonicalId": "sg-1", "networkId": "vpc-1", "scope": "network"}},
		"rules": []map[string]any{
			{"id": "r1", "groupId": "sg-1", "order": 10, "direction": "outbound", "action": "allow", "protocol": "tcp", "portRange": "443", "cidr": "10.0.2.0/24"},
		},
		"routes": []map[string]any{
			{"id": "rt-1", "subnetId": "subnet-a", "destinationCidr": "10.0.2.0/24", "target": "local"},
		},
	}
	b, _ := json.Marshal(body)
	req := authedRequest(t, http.MethodPost, "/api/cloud-topology-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
	rec := callAuthed(h.CreateCloudTopologyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create topology import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return created.ID
}

func TestFindCloudPaths_RouteFoundAndPolicyPermits_PolicySupported(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op", "pw12345678", string(auth.RoleAnalyst), true)
		topoID := createCloudTopologyImportForPathTest(t, h, userID)

		body := map[string]any{
			"topologyImportId": topoID,
			"sourceHost":       "10.0.1.5",
			"destHost":         "10.0.2.5",
			"port":             443,
			"protocol":         "tcp",
		}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindCloudPaths, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Results []cloudpath.CloudPathResult `json:"results"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(resp.Results) != 1 {
			t.Fatalf("got %d results, want 1", len(resp.Results))
		}
		if resp.Results[0].State != "policy_supported" {
			t.Fatalf("State = %q, want %q", resp.Results[0].State, "policy_supported")
		}
	})
}

func TestFindCloudPaths_MissingRequiredFields_Rejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op-bad", "pw12345678", string(auth.RoleAnalyst), true)
		b, _ := json.Marshal(map[string]any{"sourceHost": "10.0.1.5"})
		req := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindCloudPaths, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
		}
	})
}

func TestFindCloudPaths_UnknownTopologyImport_NotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "cloudpath-op-404", "pw12345678", string(auth.RoleAnalyst), true)
		body := map[string]any{"topologyImportId": "does-not-exist", "sourceHost": "10.0.1.5", "destHost": "10.0.2.5", "port": 443}
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/cloud-paths", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.FindCloudPaths, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s, want 404", rec.Code, rec.Body.String())
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/... -run TestFindCloudPaths -v`
Expected: FAIL — `h.FindCloudPaths` undefined.

- [ ] **Step 3: Write `cloudpath_handlers.go`**

```go
// orchestrator/internal/api/cloudpath_handlers.go
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/cloudpath"
	"github.com/audspect/bas/internal/cloudtopology"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkgraph"
)

const maxCloudPathRequestBytes = 1 << 16

type cloudPathRequest struct {
	TopologyImportID string `json:"topologyImportId"`
	DiscoveryRunID   string `json:"discoveryRunId,omitempty"`
	SourceHost       string `json:"sourceHost"`
	DestHost         string `json:"destHost"`
	Port             int    `json:"port"`
	Protocol         string `json:"protocol,omitempty"`
	MaxHops          int    `json:"maxHops,omitempty"`
}

// cloudPathResponse mirrors networkPathResponse's shape exactly,
// including the omitempty on SearchExhausted (see
// internal/api/networkpath_handlers.go).
type cloudPathResponse struct {
	Results         []cloudpath.CloudPathResult `json:"results"`
	SearchExhausted bool                        `json:"searchExhausted,omitempty"`
}

// FindCloudPaths -- POST /api/cloud-paths. Resolves sourceHost/
// destHost to subnets in the named topology import, finds candidate
// routes, evaluates security groups per hop, and composes+aggregates
// each one's evidence. Not persisted -- computed fresh on every call
// from already-persisted evidence sources, exactly as
// FindNetworkPaths does for the on-premises domain.
func (h *Handler) FindCloudPaths(w http.ResponseWriter, r *http.Request) {
	var req cloudPathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCloudPathRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.TopologyImportID == "" || req.SourceHost == "" || req.DestHost == "" || req.Port == 0 {
		jsonError(w, "topologyImportId, sourceHost, destHost, and port are all required", http.StatusBadRequest)
		return
	}

	topo, err := db.GetCloudTopologyImport(r.Context(), h.db, req.TopologyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "cloud topology import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sourceSubnet, err := cloudtopology.SubnetForHost(req.SourceHost, topo.Subnets)
	if err != nil {
		jsonError(w, "sourceHost: "+err.Error(), http.StatusBadRequest)
		return
	}
	destSubnet, err := cloudtopology.SubnetForHost(req.DestHost, topo.Subnets)
	if err != nil {
		jsonError(w, "destHost: "+err.Error(), http.StatusBadRequest)
		return
	}

	var observations []networkgraph.NetworkObservation
	if req.DiscoveryRunID != "" {
		if _, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, req.DiscoveryRunID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, "network discovery run not found", http.StatusNotFound)
				return
			}
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		observations, err = db.ListNetworkObservationsByRun(r.Context(), h.db, req.DiscoveryRunID)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	routes, exhausted, err := cloudtopology.FindCandidateCloudRoutes(topo, sourceSubnet, destSubnet, req.MaxHops)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var results []cloudpath.CloudPathResult
	if len(routes) == 0 {
		hop := h.composeCloudPathHop(topo, sourceSubnet, destSubnet, false, req, observations, true)
		results = append(results, cloudpath.AggregateCloudPath([]cloudpath.CloudHopResult{hop}))
	} else {
		for _, route := range routes {
			singleHop := len(route) == 2
			hops := make([]cloudpath.CloudHopResult, 0, len(route)-1)
			for i := 0; i < len(route)-1; i++ {
				hop := h.composeCloudPathHop(topo, route[i], route[i+1], true, req, observations, singleHop)
				hops = append(hops, hop)
			}
			if len(hops) == 0 {
				// route has a single element (source == dest, the
				// trivial case) -- there is no hop to compose.
				continue
			}
			results = append(results, cloudpath.AggregateCloudPath(hops))
		}
	}

	respond(w, cloudPathResponse{Results: results, SearchExhausted: exhausted})
}

// composeCloudPathHop evaluates security-group policy for one
// fromSubnet->toSubnet hop and composes its evidence. attachObservation
// gates both observation correlation: Phase 1 only ever observes
// "vantage point -> destination host" directly, never an arbitrary
// intermediate hop, so it is only ever eligible when the entire
// candidate route is exactly one hop (the literal sourceHost/destHost
// the caller supplied) -- mirroring
// internal/api/networkpath_handlers.go's composeNetworkPathHop
// exactly. When attachObservation is false, the flow's destination
// CIDR is the intermediate toSubnet's own CIDR block (we're asking
// "can traffic reach the next subnet", not "can it reach the literal
// final host").
func (h *Handler) composeCloudPathHop(topo *cloudtopology.CloudTopologyImport, fromSubnet, toSubnet string, routeFound bool, req cloudPathRequest, observations []networkgraph.NetworkObservation, attachObservation bool) cloudpath.CloudHopResult {
	flow := cloudtopology.CloudFlow{Port: req.Port, Protocol: req.Protocol}
	if attachObservation {
		flow.DestCIDR = req.DestHost + "/32"
	} else if cidr, ok := subnetCIDRByID(topo, toSubnet); ok {
		flow.DestCIDR = cidr
	} else {
		flow.DestCIDR = req.DestHost + "/32"
	}

	sgEval, err := cloudtopology.EvaluateSecurityGroupRules(topo, fromSubnet, flow)
	var sgEvalPtr *cloudtopology.SecurityGroupEvaluation
	if err == nil {
		sgEvalPtr = &sgEval
	}

	var hopObservations []networkgraph.NetworkObservation
	if attachObservation {
		hopObservations = observations
	}
	hop := cloudpath.ComposeCloudHop(fromSubnet, toSubnet, routeFound, sgEvalPtr, hopObservations)
	if !attachObservation && len(observations) > 0 {
		note := "a discovery run was supplied, but Phase 1 only observes the vantage point's direct probe to the final destination host -- this intermediate hop has no real observation evidence available"
		if hop.Limitations == "" {
			hop.Limitations = note
		} else {
			hop.Limitations = hop.Limitations + "; " + note
		}
	}
	return hop
}

func subnetCIDRByID(topo *cloudtopology.CloudTopologyImport, subnetID string) (string, bool) {
	for _, s := range topo.Subnets {
		if s.CanonicalID == subnetID {
			return s.CIDRBlock, true
		}
	}
	return "", false
}
```

- [ ] **Step 4: Wire the route**

In `orchestrator/internal/api/routes.go`, add immediately after the Task 7 `cloud-topology-imports` POST route and the existing `network-paths` POST route (re-read around line 435 first):

```go
		r.With(auth.RequirePermission(auth.CanImportCloudTopology)).Post("/api/cloud-paths", h.FindCloudPaths)
```

- [ ] **Step 5: Add the RBAC matrix row**

In `orchestrator/internal/api/rbac_matrix_test.go`, add immediately after the existing `network-paths` POST row (re-read around line 221 first):

```go
	{http.MethodPost, "/api/cloud-paths", tierPermission, auth.CanImportCloudTopology},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/api/... -run TestFindCloudPaths -v`
Expected: PASS, all 3 tests.

- [ ] **Step 7: Run the full combined gate**

Run: `go build ./... && go vet ./...`
Expected: clean.

Run: `go test ./internal/cloudtopology/... ./internal/cloudpath/... -v`
Expected: all 24 tests (Tasks 1-5) PASS.

Check free memory per Global Constraints, then run: `go test ./internal/db/... -run "TestCloudTopologyImport|TestGetCloudTopologyImport" -v` and `go test ./internal/api/... -run "TestRBACMatrix|TestCreateCloudTopologyImport|TestListAndGetCloudTopologyImport|TestFindCloudPaths" -v`
Expected: both PASS — this is the plan's one combined gate at the very end, covering every test this plan added plus the full RBAC matrix.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/cloudpath_handlers.go orchestrator/internal/api/cloudpath_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(api): add cloud path query endpoint

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git push origin main
```

---

## Self-Review

**1. Spec coverage:**
- §4.1 (data model) → Task 1 (`types.go`).
- §4.2 (security-group evaluation, including `ScopeUnresolved` degrade) → Task 1 (`sgeval.go`).
- §4.2.1 (safety caps) → Task 1 (`types.go` consts), enforced at Task 2 (`FindCandidateCloudRoutes`) and Task 7 (`validateCloudTopologyImport`).
- §4.3 (route/peering search, `exhausted` semantics) → Task 2 (`routes.go`).
- §5.1 (hop composition, 3-tier priority) → Task 3 (`compose.go`).
- §5.2 (aggregation) → Task 4 (`aggregate.go`).
- §5.3 (Cloud BAS correlation, reporting-layer only) → Task 5 (`correlate.go`).
- §6 (persistence & API: table, permission, import endpoint, path endpoint, `searchExhausted` omitempty) → Tasks 6-8.
- §7 (Review Focus, 5 items) → each item has its dedicated test, named in the Review Focus section above and cross-referenced in its owning task.
- §8 (safety constraints: no live cloud API calls, cloud-visibility limitations recorded) → import-only ingestion (Task 7), `Limitations` field threaded through every task.
- §9 (explicitly deferred: native vendor parsers, public-exposure/management-plane derived queries, per-instance SG attachment, VPN/Phase 6B, transit-gateway-specific logic) → nothing in this plan attempts any of these; `TargetTransitGateway` is modeled only as one more opaque route target, never given its own propagation logic.
- §10 (acceptance criteria 1-5) → criterion 1 = Task 1; criterion 2 = Task 2; criterion 3 = Tasks 3-4; criterion 4 = Task 5; criterion 5 = Tasks 1 & 7's `Limitations`/`Note` validation.

**2. Placeholder scan:** No `TBD`/`TODO`; every step has real, complete code. The one typo caught during drafting (`# Unknown` in a doc comment) has been fixed in Task 1.

**3. Type consistency:** `CloudFlow`, `SecurityGroupEvaluation`, `CloudTopologyImport` (Task 1) are consumed identically in Tasks 2, 3, 7, 8 with the same field names throughout. `CloudHopResult` (Task 3) is consumed identically in Task 4 (`AggregateCloudPath`) and Task 8 (`composeCloudPathHop`). `CloudPathResult` (Task 4) is consumed identically in Task 5 (`CorrelateCloudFinding`) and Task 8 (handler response). `CloudRoutePath` (Task 2) is consumed identically in Task 8's route-iteration loop.

**4. Review Focus:** All five items (listed above) each have a dedicated, named test in their owning task (Task 1 for #1-#2, Task 2 for #3-#4, Task 3 for #5) — none deferred, none generic-only.

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-10-14-network-bas-phase6a-cloud-topology.md`. Please review the plan. Does it capture what you want?

Execution method: **Native/inline** — the standing convention for this entire initiative (every prior phase: 1, 2A, 3, 4, 5A, 5B). I implement every task myself in this session, then one fresh reviewer on the most capable available model checks the whole branch at the end, per `superpowers:executing-plans`.

