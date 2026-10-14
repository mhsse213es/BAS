# Network BAS Phase 2A: Firewall & Segmentation Policy Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a vendor-agnostic normalized firewall/segmentation policy schema, an ordered first-match policy evaluator producing `cloudgraph.PathState` evidence, and a correlation layer that joins policy evidence against Phase 1's `networkgraph` reachability evidence — exposed via a Postgres-backed HTTP API following the established `cloud_run`/`network_discovery` precedent.

**Architecture:** Three new packages, each with one boundary: `internal/networkpolicy` (pure types + evaluation, imports `cloudgraph` only), `internal/networkcorrelation` (the only package that imports both `networkpolicy` and `networkgraph` — correlation is structurally confined here, not just by convention), plus `internal/db`/`internal/api` additions mirroring Phase 1's dedicated-API-and-Postgres pattern exactly.

**Tech Stack:** Go, `net.ParseCIDR`/`net.IPNet.Contains` for CIDR work, Postgres via `pgxpool` (one `jsonb` column per policy import, not exploded into relational rule rows — an import is an atomic, versioned snapshot), `go-chi/chi/v5` routing.

**Spec:** `docs/superpowers/specs/2026-10-13-network-bas-phase2a-policy-evidence-design.md`. Parent: `docs/superpowers/specs/2026-10-13-network-bas-architecture-design.md`.

## Global Constraints

- `MaxRulesPerImport = 5000`, `MaxZonesPerImport = 500` (sized for a real enterprise firewall config, not a live-probe blast-radius concern — this is pure computation).
- `MaxPolicyQueriesPerEvaluation = 500`.
- Import request body cap: 5 MiB via `http.MaxBytesReader` from the start (lesson already applied in Phase 1, not bolted on later). Evaluation request body cap: 1 MiB.
- A `Rule.PortRange` of `""` matches any port; a bare number matches only that port; a `"low-high"` range matches inclusively; anything else is rejected at import validation time, never silently treated as "any".
- `ActionUnresolved` (and ambiguous/unresolvable zone references) must always surface as `cloudgraph.Unknown` with a non-empty limitation note — at every layer (evaluation, correlation, API) — never coerced into a stronger claim closer to the API boundary.
- An explicit `ActionDeny` match (or default-deny with no match) maps to `cloudgraph.Blocked` — held to the same evidentiary standard as Phase 1's actively-refused-connection classification, not a weaker inference.
- No persisted "comparisons" table — `GetNetworkReachabilityComparison` computes `CorrelateReachability` fresh from the two already-persisted evidence sources on every call.
- `internal/networkpolicy` never imports `internal/networkgraph`, and vice versa. Only `internal/networkcorrelation` imports both — this is how the master spec's "correlation is reporting-layer only" rule is enforced structurally.
- No comparison label (`consistent-allow`, `discrepancy-unexpected-block`, `discrepancy-unenforced-deny`, `consistent-deny`, `untested`, `policy-inconclusive`) may be documented or rendered as a security verdict stronger than "these two independently-collected pieces of evidence agree/disagree" — `discrepancy-unenforced-deny` in particular is "the parsed policy and the live test disagree," never "confirmed vulnerability."
- `ImportedBy` on every policy import is always the authenticated caller from `auth.ClaimsFrom(r.Context())`, never trusted from the request body — same discipline as Phase 1's `RequestedBy`.
- New permission `CanImportNetworkPolicy = "network-policy:import"` is granted to `RoleAdmin` and `RoleAnalyst` (mirroring `CanRunScenario`'s placement — this is an analyst-usable, evidence-producing action, not an admin-only platform-configuration action like `CanImportOpenAEVBundle`).
- Host machine has only 7.84GB RAM: never run the full unscoped `go test ./internal/api/...`. Substitute `go build ./...` + `go test ./internal/networkpolicy/... ./internal/networkcorrelation/... ./internal/db/...` + every relevant `internal/api` test together via one `-run` regex. Check `Get-CimInstance Win32_OperatingSystem` free/total memory before any `internal/api` test run.
- Work happens inline on `main`, no worktree, no feature branch (standing session convention). `git fetch` + `git log --oneline main..origin/main` before every push.
- Sonnet only for the final-review subagent dispatch, never Opus.

## Review Focus

- **Two zones in one import share the same `Name`.** A query or rule referencing that name by zone is now genuinely ambiguous — a reasonable person would expect this to surface as inconclusive evidence, not for the evaluator to silently pick one of the two. Task 2's tests must cover this directly.
- **An `ActionUnresolved` rule is the first match for a query.** The evaluation must carry that rule's own `Note` into the result's `Limitations`, and the import itself must be rejected at validation time if the rule has no `Note`, or if the import's own top-level `Limitations` list is empty despite having at least one `Unresolved` rule. Both the evaluation-time and import-time halves of this need their own tests (Task 2 and Task 5 respectively) — a plan that only tests one half would let the other regress silently.
- **A Phase 1 `NetworkObservation.Target.Host` is a hostname, not a literal IP** (Phase 1's `Target.Host` field never required a literal IP). Phase 2A does no DNS resolution, so correlating it against a CIDR-based policy destination must degrade honestly to "no match" rather than crashing on a malformed CIDR string or silently mismatching. Task 3 needs a test with a non-IP host to prove this.
- **Port-range boundary correctness.** A rule's `"1024-65535"` range must match exactly at `1024` and `65535` (inclusive) and reject `1023`/`65536`. Off-by-one errors here are easy to introduce and easy to miss with only mid-range test values. Task 1's tests must include both boundary values explicitly, not just a value safely inside the range.
- **The oversized-body-rejected-before-full-decode discipline**, which Phase 1 only reached after a post-hoc review fix, must ship correct from Task 5/6's first version here — both the import and evaluation endpoints need their own `http.MaxBytesReader`-rejection test from the start, not deferred to a later fix pass.

---

### Task 1: Core Types & Port-Range Matching

**Files:**
- Create: `orchestrator/internal/networkpolicy/types.go`
- Create: `orchestrator/internal/networkpolicy/portmatch.go`
- Test: `orchestrator/internal/networkpolicy/portmatch_test.go`

**Interfaces:**
- Consumes: nothing (first task in this plan).
- Produces: `networkpolicy.RuleAction` (`ActionAllow`/`ActionDeny`/`ActionUnresolved`), `networkpolicy.Zone{Name, CIDRs}`, `networkpolicy.Rule{ID, Order, SourceZone, SourceCIDR, DestZone, DestCIDR, Protocol, PortRange, Action, Note}`, `networkpolicy.DefaultPolicy` (`DefaultAllow`/`DefaultDeny`), `networkpolicy.PolicyImport{ID, SourceType, ImportedBy, ImportedAt, ConfigVersion, DefaultPolicy, Zones, Rules, Limitations}`, `networkpolicy.ParsePortRange(s string) (matchAny bool, low, high int, err error)`, `networkpolicy.Rule.MatchesPort(port int) (bool, error)`. Task 2 consumes every type here plus `ParsePortRange`/`MatchesPort` exactly as defined. Task 5 consumes `PolicyImport`/`Zone`/`Rule`/`RuleAction`/`DefaultPolicy` for request decoding and validation, and `ParsePortRange` for import-time `PortRange` validation.

- [ ] **Step 1: Create the core types file**

Create `orchestrator/internal/networkpolicy/types.go`:

```go
// Package networkpolicy models a vendor-agnostic, normalized firewall and
// segmentation policy, and evaluates it against candidate traffic queries
// to produce cloudgraph.PathState evidence. It never imports
// internal/networkgraph -- see internal/networkcorrelation for the one
// place policy evidence and reachability evidence are allowed to meet.
package networkpolicy

import "time"

// RuleAction is a rule's effect when it matches. ActionUnresolved exists
// specifically so a vendor construct this schema can't losslessly
// represent (NAT, stateful return traffic, address/service groups) can be
// represented honestly instead of forced into Allow or Deny.
type RuleAction string

const (
	ActionAllow      RuleAction = "allow"
	ActionDeny       RuleAction = "deny"
	ActionUnresolved RuleAction = "unresolved"
)

// Zone is a named network segment, resolved to one or more CIDRs.
type Zone struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// Rule is one normalized policy rule. Each side (source/dest) is either a
// zone reference (SourceZone/DestZone, resolved against the owning
// PolicyImport's Zones) or a direct CIDR (SourceCIDR/DestCIDR) -- never
// both for the same side.
type Rule struct {
	ID         string     `json:"id"`
	Order      int        `json:"order"`
	SourceZone string     `json:"sourceZone,omitempty"`
	SourceCIDR string     `json:"sourceCidr,omitempty"`
	DestZone   string     `json:"destZone,omitempty"`
	DestCIDR   string     `json:"destCidr,omitempty"`
	Protocol   string     `json:"protocol,omitempty"`
	PortRange  string     `json:"portRange,omitempty"`
	Action     RuleAction `json:"action"`
	// Note is required whenever Action == ActionUnresolved -- it is the
	// honest explanation for why this rule couldn't be losslessly
	// translated, carried into any PolicyEvaluation this rule decides.
	Note string `json:"note,omitempty"`
}

// DefaultPolicy is what applies when no rule matches a query.
type DefaultPolicy string

const (
	DefaultAllow DefaultPolicy = "allow"
	DefaultDeny  DefaultPolicy = "deny"
)

// PolicyImport is one auditable, versioned policy snapshot.
type PolicyImport struct {
	ID            string        `json:"id,omitempty"`
	SourceType    string        `json:"sourceType"`
	ImportedBy    string        `json:"importedBy,omitempty"`
	ImportedAt    time.Time     `json:"importedAt,omitempty"`
	ConfigVersion string        `json:"configVersion,omitempty"`
	DefaultPolicy DefaultPolicy `json:"defaultPolicy"`
	Zones         []Zone        `json:"zones"`
	Rules         []Rule        `json:"rules"`
	// Limitations is required to be non-empty whenever any Rule.Action ==
	// ActionUnresolved -- enforced at the API validation layer (Task 5),
	// not here (this package has no validation of its own).
	Limitations []string `json:"limitations,omitempty"`
}
```

- [ ] **Step 2: Write the failing tests for port-range parsing and matching**

Create `orchestrator/internal/networkpolicy/portmatch_test.go`:

```go
package networkpolicy

import "testing"

func TestParsePortRange_EmptyMatchesAny(t *testing.T) {
	matchAny, _, _, err := ParsePortRange("")
	if err != nil {
		t.Fatalf("ParsePortRange: %v", err)
	}
	if !matchAny {
		t.Fatal("want matchAny true for an empty PortRange")
	}
}

func TestParsePortRange_BareNumberMatchesExactOnly(t *testing.T) {
	matchAny, low, high, err := ParsePortRange("443")
	if err != nil {
		t.Fatalf("ParsePortRange: %v", err)
	}
	if matchAny || low != 443 || high != 443 {
		t.Fatalf("got matchAny=%v low=%d high=%d, want matchAny=false low=443 high=443", matchAny, low, high)
	}
}

func TestParsePortRange_RangeParsesInclusiveBounds(t *testing.T) {
	matchAny, low, high, err := ParsePortRange("1024-65535")
	if err != nil {
		t.Fatalf("ParsePortRange: %v", err)
	}
	if matchAny || low != 1024 || high != 65535 {
		t.Fatalf("got matchAny=%v low=%d high=%d, want matchAny=false low=1024 high=65535", matchAny, low, high)
	}
}

func TestParsePortRange_RejectsMalformed(t *testing.T) {
	cases := []string{"abc", "100-abc", "100-50", "0", "70000", "-5", "100-"}
	for _, c := range cases {
		if _, _, _, err := ParsePortRange(c); err == nil {
			t.Errorf("ParsePortRange(%q): want error, got none", c)
		}
	}
}

func TestRule_MatchesPort_EmptyRangeMatchesAnyPort(t *testing.T) {
	r := Rule{PortRange: ""}
	ok, err := r.MatchesPort(1)
	if err != nil || !ok {
		t.Fatalf("MatchesPort(1) = %v, %v; want true, nil", ok, err)
	}
	ok, err = r.MatchesPort(65535)
	if err != nil || !ok {
		t.Fatalf("MatchesPort(65535) = %v, %v; want true, nil", ok, err)
	}
}

func TestRule_MatchesPort_ExactPort(t *testing.T) {
	r := Rule{PortRange: "443"}
	if ok, err := r.MatchesPort(443); err != nil || !ok {
		t.Fatalf("MatchesPort(443) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := r.MatchesPort(444); err != nil || ok {
		t.Fatalf("MatchesPort(444) = %v, %v; want false, nil", ok, err)
	}
}

func TestRule_MatchesPort_RangeInclusiveBoundaries(t *testing.T) {
	r := Rule{PortRange: "1024-65535"}
	if ok, err := r.MatchesPort(1024); err != nil || !ok {
		t.Fatalf("MatchesPort(1024) = %v, %v; want true, nil (lower boundary)", ok, err)
	}
	if ok, err := r.MatchesPort(65535); err != nil || !ok {
		t.Fatalf("MatchesPort(65535) = %v, %v; want true, nil (upper boundary)", ok, err)
	}
	if ok, err := r.MatchesPort(1023); err != nil || ok {
		t.Fatalf("MatchesPort(1023) = %v, %v; want false, nil (just below lower boundary)", ok, err)
	}
	if ok, err := r.MatchesPort(65536); err != nil || ok {
		t.Fatalf("MatchesPort(65536) = %v, %v; want false, nil (just above upper boundary)", ok, err)
	}
}

func TestRule_MatchesPort_MalformedReturnsError(t *testing.T) {
	r := Rule{PortRange: "not-a-port"}
	if _, err := r.MatchesPort(443); err == nil {
		t.Fatal("want error for a malformed PortRange")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/networkpolicy/... -v`
Expected: FAIL — `ParsePortRange` undefined (package doesn't compile without it).

- [ ] **Step 4: Implement port-range parsing and matching**

Create `orchestrator/internal/networkpolicy/portmatch.go`:

```go
package networkpolicy

import (
	"fmt"
	"strconv"
	"strings"
)

// ParsePortRange parses a Rule.PortRange string. "" matches any port. A
// bare number matches only that port. A "low-high" range matches any port
// in [low, high] inclusive. Any other form is rejected -- this is the one
// place that decides whether a PortRange string is well-formed; it is
// never silently treated as "any".
func ParsePortRange(s string) (matchAny bool, low, high int, err error) {
	if s == "" {
		return true, 0, 0, nil
	}
	if !strings.Contains(s, "-") {
		p, convErr := strconv.Atoi(s)
		if convErr != nil || p < 1 || p > 65535 {
			return false, 0, 0, fmt.Errorf("networkpolicy: invalid port %q", s)
		}
		return false, p, p, nil
	}
	parts := strings.SplitN(s, "-", 2)
	lo, loErr := strconv.Atoi(parts[0])
	hi, hiErr := strconv.Atoi(parts[1])
	if loErr != nil || hiErr != nil || lo < 1 || hi > 65535 || lo > hi {
		return false, 0, 0, fmt.Errorf("networkpolicy: invalid port range %q", s)
	}
	return false, lo, hi, nil
}

// MatchesPort reports whether port falls within r.PortRange.
func (r Rule) MatchesPort(port int) (bool, error) {
	matchAny, low, high, err := ParsePortRange(r.PortRange)
	if err != nil {
		return false, err
	}
	if matchAny {
		return true, nil
	}
	return port >= low && port <= high, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/networkpolicy/... -v`
Expected: PASS (8/8 test functions).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networkpolicy/types.go orchestrator/internal/networkpolicy/portmatch.go orchestrator/internal/networkpolicy/portmatch_test.go
git commit -m "feat(networkpolicy): add core policy types and port-range matching"
```

---

### Task 2: Policy Evaluation (Zone/CIDR Resolution + Ordered Rule Matching)

**Files:**
- Create: `orchestrator/internal/networkpolicy/evaluate.go`
- Test: `orchestrator/internal/networkpolicy/evaluate_test.go`

**Interfaces:**
- Consumes: `Zone`, `Rule`, `RuleAction`, `DefaultPolicy`, `PolicyImport`, `Rule.MatchesPort` (Task 1).
- Produces: `networkpolicy.MaxRulesPerImport`, `networkpolicy.MaxZonesPerImport`, `networkpolicy.MaxPolicyQueriesPerEvaluation`, `networkpolicy.PolicyQuery{SourceZone, SourceCIDR, DestZone, DestCIDR, Protocol, Port}`, `networkpolicy.PolicyEvaluation{Query, State, MatchedRule, Provenance, Limitations}`, `networkpolicy.EvaluatePolicyMatrix(imp *PolicyImport, queries []PolicyQuery) ([]PolicyEvaluation, error)`. Task 3 consumes `PolicyEvaluation`/`PolicyQuery` exactly as defined here. Task 5/6 consume `EvaluatePolicyMatrix` and the three `Max*` constants for their own request validation, mirroring Phase 1's handler-level defense-in-depth.

**Scope refinement (resolving a gap the spec left at prose level, per this plan's own job of pinning down implementation mechanics):** matching normalizes *both* the query side and the rule side to resolved CIDR sets via the same zone-or-direct-CIDR resolution, then checks CIDR-set overlap — there is no separate "zone identity" concept needed once both sides resolve to CIDRs, which simplifies the spec's "ambiguous CIDR-to-multiple-zones" language down to the one case that actually needs it: a *zone-name* reference (`SourceZone`/`DestZone`, on either a query or a rule) that matches zero or more than one entry in `imp.Zones` by name. That is the only place "ambiguous" is possible under this algorithm, and it surfaces as `Unknown` exactly as the spec requires. CIDR overlap itself is computed as mutual containment (`aNet.Contains(bNet.IP) || bNet.Contains(aNet.IP)`) — correct for the overwhelmingly common nested-subnet case (a zone's CIDR containing a query's CIDR or vice versa), not a full arbitrary-range-intersection algorithm; this is a deliberate, documented simplification appropriate to Phase 2A's "prove the pipeline" scope, not silently narrower than what was asked.

- [ ] **Step 1: Write the failing tests for policy evaluation**

Create `orchestrator/internal/networkpolicy/evaluate_test.go`:

```go
package networkpolicy

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

func testImport(defaultPolicy DefaultPolicy, zones []Zone, rules []Rule) *PolicyImport {
	return &PolicyImport{ID: "imp-1", SourceType: "manual-normalized", DefaultPolicy: defaultPolicy, Zones: zones, Rules: rules}
}

func TestEvaluatePolicyMatrix_ZoneToZoneAllowMatch(t *testing.T) {
	imp := testImport(DefaultDeny,
		[]Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}, {Name: "internal", CIDRs: []string{"10.0.2.0/24"}}},
		[]Rule{{ID: "r1", Order: 1, SourceZone: "dmz", DestZone: "internal", Protocol: "tcp", PortRange: "443", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceZone: "dmz", DestZone: "internal", Protocol: "tcp", Port: 443}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported", results[0].State)
	}
	if results[0].MatchedRule == nil || results[0].MatchedRule.ID != "r1" {
		t.Fatalf("MatchedRule = %+v, want rule r1", results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_CIDRToCIDRDenyMatch(t *testing.T) {
	imp := testImport(DefaultAllow, nil,
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "192.168.1.0/24", Protocol: "tcp", PortRange: "22", Action: ActionDeny}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.5.5/32", DestCIDR: "192.168.1.10/32", Protocol: "tcp", Port: 22}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_MixedZoneAndCIDRMatch(t *testing.T) {
	imp := testImport(DefaultDeny,
		[]Zone{{Name: "web-tier", CIDRs: []string{"10.0.1.0/24"}}},
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "0.0.0.0/0", DestZone: "web-tier", Protocol: "tcp", PortRange: "443", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "203.0.113.5/32", DestCIDR: "10.0.1.50/32", Protocol: "tcp", Port: 443}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported {
		t.Fatalf("state = %q, want policy_supported", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_FirstMatchWinsOverLaterConflictingRule(t *testing.T) {
	imp := testImport(DefaultDeny, nil,
		[]Rule{
			{ID: "allow-first", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", PortRange: "443", Action: ActionAllow},
			{ID: "deny-second", Order: 2, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", PortRange: "443", Action: ActionDeny},
		},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 443}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported || results[0].MatchedRule.ID != "allow-first" {
		t.Fatalf("got state=%q matchedRule=%+v, want policy_supported via allow-first (order matters)", results[0].State, results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_UnresolvedActionIsUnknownWithNote(t *testing.T) {
	imp := testImport(DefaultDeny, nil,
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", PortRange: "", Action: ActionUnresolved, Note: "NAT rule, cannot translate losslessly"}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown", results[0].State)
	}
	if results[0].Limitations != "NAT rule, cannot translate losslessly" {
		t.Fatalf("Limitations = %q, want the rule's own Note carried through", results[0].Limitations)
	}
}

func TestEvaluatePolicyMatrix_AmbiguousZoneNameIsUnknown(t *testing.T) {
	imp := testImport(DefaultDeny,
		[]Zone{{Name: "dup", CIDRs: []string{"10.0.1.0/24"}}, {Name: "dup", CIDRs: []string{"10.0.9.0/24"}}},
		[]Rule{{ID: "r1", Order: 1, SourceZone: "dup", DestCIDR: "10.0.0.0/8", PortRange: "", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceZone: "dup", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown -- two zones sharing a name must never be silently resolved to one of them", results[0].State)
	}
	if results[0].Limitations == "" {
		t.Fatal("want a non-empty limitation note explaining the ambiguity")
	}
}

func TestEvaluatePolicyMatrix_UnknownZoneNameIsUnknown(t *testing.T) {
	imp := testImport(DefaultAllow, []Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}}, nil)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceZone: "does-not-exist", DestCIDR: "10.0.1.5/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Unknown {
		t.Fatalf("state = %q, want unknown for a zone name absent from this import", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_NoRuleMatchesDefaultAllow(t *testing.T) {
	imp := testImport(DefaultAllow, nil, nil)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.PolicySupported || results[0].MatchedRule != nil {
		t.Fatalf("got state=%q matchedRule=%+v, want policy_supported via default policy, no matched rule", results[0].State, results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_NoRuleMatchesDefaultDeny(t *testing.T) {
	imp := testImport(DefaultDeny, nil, nil)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Port: 80}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Blocked || results[0].MatchedRule != nil {
		t.Fatalf("got state=%q matchedRule=%+v, want blocked via default policy, no matched rule", results[0].State, results[0].MatchedRule)
	}
}

func TestEvaluatePolicyMatrix_ProtocolMismatchDoesNotMatch(t *testing.T) {
	imp := testImport(DefaultDeny, nil,
		[]Rule{{ID: "r1", Order: 1, SourceCIDR: "10.0.0.0/8", DestCIDR: "10.0.0.0/8", Protocol: "udp", PortRange: "53", Action: ActionAllow}},
	)
	results, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{SourceCIDR: "10.0.1.1/32", DestCIDR: "10.0.2.2/32", Protocol: "tcp", Port: 53}})
	if err != nil {
		t.Fatalf("EvaluatePolicyMatrix: %v", err)
	}
	if results[0].State != cloudgraph.Blocked {
		t.Fatalf("state = %q, want blocked via default policy -- the udp-only rule must not match a tcp query", results[0].State)
	}
}

func TestEvaluatePolicyMatrix_RejectsEmptyQueries(t *testing.T) {
	imp := testImport(DefaultAllow, nil, nil)
	if _, err := EvaluatePolicyMatrix(imp, nil); err == nil {
		t.Fatal("want error for zero queries")
	}
}

func TestEvaluatePolicyMatrix_RejectsTooManyQueries(t *testing.T) {
	imp := testImport(DefaultAllow, nil, nil)
	queries := make([]PolicyQuery, MaxPolicyQueriesPerEvaluation+1)
	if _, err := EvaluatePolicyMatrix(imp, queries); err == nil {
		t.Fatal("want error for too many queries")
	}
}

func TestEvaluatePolicyMatrix_RejectsImportOverRuleCap(t *testing.T) {
	rules := make([]Rule, MaxRulesPerImport+1)
	imp := testImport(DefaultAllow, nil, rules)
	if _, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{Port: 80}}); err == nil {
		t.Fatal("want error for an import with too many rules")
	}
}

func TestEvaluatePolicyMatrix_RejectsImportOverZoneCap(t *testing.T) {
	zones := make([]Zone, MaxZonesPerImport+1)
	imp := testImport(DefaultAllow, zones, nil)
	if _, err := EvaluatePolicyMatrix(imp, []PolicyQuery{{Port: 80}}); err == nil {
		t.Fatal("want error for an import with too many zones")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/networkpolicy/... -run TestEvaluatePolicyMatrix -v`
Expected: FAIL — `EvaluatePolicyMatrix`, `PolicyQuery`, `MaxRulesPerImport`, etc. undefined.

- [ ] **Step 3: Implement policy evaluation**

Create `orchestrator/internal/networkpolicy/evaluate.go`:

```go
package networkpolicy

import (
	"fmt"
	"net"
	"time"

	"github.com/audspect/bas/internal/cloudgraph"
)

const (
	MaxRulesPerImport             = 5000
	MaxZonesPerImport             = 500
	MaxPolicyQueriesPerEvaluation = 500
)

// PolicyQuery is one row of a policy test matrix. Exactly one of
// SourceZone/SourceCIDR, and exactly one of DestZone/DestCIDR, should be
// set per side.
type PolicyQuery struct {
	SourceZone, SourceCIDR string
	DestZone, DestCIDR     string
	Protocol               string
	Port                   int
}

// PolicyEvaluation is EvaluatePolicyMatrix's per-query result.
type PolicyEvaluation struct {
	Query       PolicyQuery
	State       cloudgraph.PathState
	MatchedRule *Rule // nil when the default policy applied, or when resolution failed before any rule was checked
	Provenance  cloudgraph.Provenance
	Limitations string
}

// resolvedRule caches one rule's source/dest CIDR resolution so it is
// computed once per EvaluatePolicyMatrix call, not once per query --
// otherwise worst-case cost is O(queries x rules x zones) instead of
// O(rules x zones + queries x rules).
type resolvedRule struct {
	rule       *Rule
	srcCIDRs   []string
	dstCIDRs   []string
	resolveErr error
}

// EvaluatePolicyMatrix evaluates every query against imp's rules (walked
// in Order, first match wins) and default policy, producing one
// PolicyEvaluation per query in the same order as queries.
func EvaluatePolicyMatrix(imp *PolicyImport, queries []PolicyQuery) ([]PolicyEvaluation, error) {
	if len(queries) == 0 {
		return nil, fmt.Errorf("networkpolicy: EvaluatePolicyMatrix requires at least one query")
	}
	if len(queries) > MaxPolicyQueriesPerEvaluation {
		return nil, fmt.Errorf("networkpolicy: too many queries -- got %d, max %d", len(queries), MaxPolicyQueriesPerEvaluation)
	}
	if len(imp.Rules) > MaxRulesPerImport {
		return nil, fmt.Errorf("networkpolicy: import has too many rules -- got %d, max %d", len(imp.Rules), MaxRulesPerImport)
	}
	if len(imp.Zones) > MaxZonesPerImport {
		return nil, fmt.Errorf("networkpolicy: import has too many zones -- got %d, max %d", len(imp.Zones), MaxZonesPerImport)
	}

	resolved := make([]resolvedRule, len(imp.Rules))
	for i := range imp.Rules {
		r := &imp.Rules[i]
		src, srcErr := resolveSide(r.SourceZone, r.SourceCIDR, imp.Zones)
		dst, dstErr := resolveSide(r.DestZone, r.DestCIDR, imp.Zones)
		rr := resolvedRule{rule: r, srcCIDRs: src, dstCIDRs: dst}
		if srcErr != nil {
			rr.resolveErr = srcErr
		} else if dstErr != nil {
			rr.resolveErr = dstErr
		}
		resolved[i] = rr
	}

	results := make([]PolicyEvaluation, len(queries))
	for i, q := range queries {
		results[i] = evaluateOne(imp, q, resolved)
	}
	return results, nil
}

func evaluateOne(imp *PolicyImport, q PolicyQuery, resolved []resolvedRule) PolicyEvaluation {
	querySrc, srcErr := resolveSide(q.SourceZone, q.SourceCIDR, imp.Zones)
	queryDst, dstErr := resolveSide(q.DestZone, q.DestCIDR, imp.Zones)
	if srcErr != nil || dstErr != nil {
		note := srcErr
		if note == nil {
			note = dstErr
		}
		return PolicyEvaluation{Query: q, State: cloudgraph.Unknown, Limitations: note.Error(), Provenance: provenanceFor(imp, "none")}
	}

	for _, rr := range resolved {
		if rr.resolveErr != nil {
			continue // this rule's own zone reference couldn't be resolved -- skip it defensively, never abort the whole evaluation
		}
		matched, err := matchResolved(rr.rule, q, querySrc, queryDst, rr.srcCIDRs, rr.dstCIDRs)
		if err != nil || !matched {
			continue
		}
		switch rr.rule.Action {
		case ActionAllow:
			return PolicyEvaluation{Query: q, State: cloudgraph.PolicySupported, MatchedRule: rr.rule, Provenance: provenanceFor(imp, "medium")}
		case ActionDeny:
			return PolicyEvaluation{Query: q, State: cloudgraph.Blocked, MatchedRule: rr.rule, Provenance: provenanceFor(imp, "medium")}
		default: // ActionUnresolved
			return PolicyEvaluation{Query: q, State: cloudgraph.Unknown, MatchedRule: rr.rule, Limitations: rr.rule.Note, Provenance: provenanceFor(imp, "none")}
		}
	}

	if imp.DefaultPolicy == DefaultAllow {
		return PolicyEvaluation{Query: q, State: cloudgraph.PolicySupported, Provenance: provenanceFor(imp, "low")}
	}
	return PolicyEvaluation{Query: q, State: cloudgraph.Blocked, Provenance: provenanceFor(imp, "low")}
}

func matchResolved(rule *Rule, q PolicyQuery, querySrc, queryDst, ruleSrc, ruleDst []string) (bool, error) {
	if rule.Protocol != "" && q.Protocol != "" && rule.Protocol != q.Protocol {
		return false, nil
	}
	portOK, err := rule.MatchesPort(q.Port)
	if err != nil {
		return false, err
	}
	if !portOK {
		return false, nil
	}
	if !cidrSetsOverlap(ruleSrc, querySrc) {
		return false, nil
	}
	if !cidrSetsOverlap(ruleDst, queryDst) {
		return false, nil
	}
	return true, nil
}

// resolveSide resolves one side (source or dest) of a query or rule to
// the CIDR(s) it represents. A direct CIDR is used as-is. A zone-name
// reference must match exactly one entry in zones by Name -- zero or
// more than one match is unresolvable and returned as an error so the
// caller classifies Unknown rather than guessing which zone was meant.
func resolveSide(zoneName, cidr string, zones []Zone) ([]string, error) {
	if cidr != "" {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("networkpolicy: invalid CIDR %q: %w", cidr, err)
		}
		return []string{cidr}, nil
	}
	if zoneName == "" {
		return nil, fmt.Errorf("networkpolicy: neither a zone nor a CIDR was given for this side")
	}
	var found []Zone
	for _, z := range zones {
		if z.Name == zoneName {
			found = append(found, z)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("networkpolicy: zone %q not found in this import", zoneName)
	}
	if len(found) > 1 {
		return nil, fmt.Errorf("networkpolicy: zone name %q is ambiguous -- %d zones share this name", zoneName, len(found))
	}
	return found[0].CIDRs, nil
}

func cidrSetsOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if overlap, err := cidrsOverlap(x, y); err == nil && overlap {
				return true
			}
		}
	}
	return false
}

// cidrsOverlap treats two CIDRs as overlapping when either contains the
// other's network address -- correct for the common nested-subnet case
// (a zone's CIDR containing a query's CIDR, or vice versa), not a full
// arbitrary-range-intersection algorithm. A deliberate, documented
// simplification for Phase 2A's scope.
func cidrsOverlap(a, b string) (bool, error) {
	_, aNet, err := net.ParseCIDR(a)
	if err != nil {
		return false, fmt.Errorf("networkpolicy: invalid CIDR %q: %w", a, err)
	}
	_, bNet, err := net.ParseCIDR(b)
	if err != nil {
		return false, fmt.Errorf("networkpolicy: invalid CIDR %q: %w", b, err)
	}
	return aNet.Contains(bNet.IP) || bNet.Contains(aNet.IP), nil
}

func provenanceFor(imp *PolicyImport, confidence string) cloudgraph.Provenance {
	return cloudgraph.Provenance{Source: "policy-import:" + imp.ID, ObservedAt: time.Now(), Confidence: confidence}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/networkpolicy/... -run TestEvaluatePolicyMatrix -v`
Expected: PASS (14/14).

- [ ] **Step 5: Run the full package suite**

Run: `cd orchestrator && go build ./... && go test ./internal/networkpolicy/... -v`
Expected: build clean; all tests from Tasks 1-2 pass (22 test functions, 0 failures).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networkpolicy/evaluate.go orchestrator/internal/networkpolicy/evaluate_test.go
git commit -m "feat(networkpolicy): add ordered policy evaluation against cloudgraph.PathState"
```

---

### Task 3: Evidence Correlation (`internal/networkcorrelation`)

**Files:**
- Create: `orchestrator/internal/networkcorrelation/correlate.go`
- Test: `orchestrator/internal/networkcorrelation/correlate_test.go`

**Interfaces:**
- Consumes: `networkpolicy.PolicyEvaluation`/`PolicyQuery` (Task 2), `networkgraph.NetworkObservation`/`Target` (Phase 1, unchanged), `cloudgraph.PathState` (existing).
- Produces: `networkcorrelation.ComparisonLabel` (`ConsistentAllow`/`DiscrepancyUnexpectedBlock`/`DiscrepancyUnenforcedDeny`/`ConsistentDeny`/`Untested`/`PolicyInconclusive`), `networkcorrelation.ReachabilityComparison{Evaluation, Observation, Label}`, `networkcorrelation.CorrelateReachability(evaluations []networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) []ReachabilityComparison`. Task 6 consumes `CorrelateReachability` and every exported type here exactly as defined.

- [ ] **Step 1: Write the failing tests for correlation**

Create `orchestrator/internal/networkcorrelation/correlate_test.go`:

```go
package networkcorrelation

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

func eval(destCIDR string, port int, state cloudgraph.PathState) networkpolicy.PolicyEvaluation {
	return networkpolicy.PolicyEvaluation{Query: networkpolicy.PolicyQuery{DestCIDR: destCIDR, Port: port}, State: state}
}

func obs(host string, port int, state cloudgraph.PathState) networkgraph.NetworkObservation {
	return networkgraph.NetworkObservation{Target: networkgraph.Target{Host: host, Port: port}, State: state}
}

func TestCorrelateReachability_ConsistentAllow(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Observed)})
	if out[0].Label != ConsistentAllow {
		t.Fatalf("label = %q, want consistent-allow", out[0].Label)
	}
	if out[0].Observation == nil {
		t.Fatal("want a matched observation")
	}
}

func TestCorrelateReachability_DiscrepancyUnexpectedBlock(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Blocked)})
	if out[0].Label != DiscrepancyUnexpectedBlock {
		t.Fatalf("label = %q, want discrepancy-unexpected-block", out[0].Label)
	}
}

func TestCorrelateReachability_DiscrepancyUnenforcedDeny(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 22, cloudgraph.Blocked)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 22, cloudgraph.Observed)})
	if out[0].Label != DiscrepancyUnenforcedDeny {
		t.Fatalf("label = %q, want discrepancy-unenforced-deny", out[0].Label)
	}
}

func TestCorrelateReachability_ConsistentDeny(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 22, cloudgraph.Blocked)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 22, cloudgraph.Blocked)})
	if out[0].Label != ConsistentDeny {
		t.Fatalf("label = %q, want consistent-deny", out[0].Label)
	}
}

func TestCorrelateReachability_UntestedWhenNoObservationMatches(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)}, nil)
	if out[0].Label != Untested {
		t.Fatalf("label = %q, want untested", out[0].Label)
	}
	if out[0].Observation != nil {
		t.Fatal("want no observation attached")
	}
}

func TestCorrelateReachability_UntestedWhenObservationIsUnknown(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Unknown)})
	if out[0].Label != Untested {
		t.Fatalf("label = %q, want untested", out[0].Label)
	}
}

func TestCorrelateReachability_PolicyInconclusiveWhenPolicyStateIsUnknown(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.Unknown)},
		[]networkgraph.NetworkObservation{obs("10.0.0.5", 443, cloudgraph.Observed)})
	if out[0].Label != PolicyInconclusive {
		t.Fatalf("label = %q, want policy-inconclusive", out[0].Label)
	}
}

func TestCorrelateReachability_NoMatchWhenHostOutsideCIDR(t *testing.T) {
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("10.0.9.9", 443, cloudgraph.Observed)})
	if out[0].Label != Untested || out[0].Observation != nil {
		t.Fatalf("got label=%q observation=%+v, want untested with no match -- the observation's host is outside the evaluated /32", out[0].Label, out[0].Observation)
	}
}

func TestCorrelateReachability_NonIPObservationHostDoesNotCrash(t *testing.T) {
	// Phase 1's Target.Host is never required to be a literal IP. Phase 2A
	// does no DNS resolution, so this must degrade to "no match" honestly,
	// not panic or silently mismatch.
	out := CorrelateReachability([]networkpolicy.PolicyEvaluation{eval("10.0.0.5/32", 443, cloudgraph.PolicySupported)},
		[]networkgraph.NetworkObservation{obs("some-hostname.internal", 443, cloudgraph.Observed)})
	if out[0].Label != Untested || out[0].Observation != nil {
		t.Fatalf("got label=%q observation=%+v, want untested with no match for a non-IP host", out[0].Label, out[0].Observation)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/networkcorrelation/... -v`
Expected: FAIL — package `internal/networkcorrelation` doesn't exist yet / `CorrelateReachability` undefined.

- [ ] **Step 3: Implement correlation**

Create `orchestrator/internal/networkcorrelation/correlate.go`:

```go
// Package networkcorrelation is the one place Network BAS policy evidence
// (internal/networkpolicy) and reachability evidence (internal/networkgraph)
// are allowed to meet. Both evidence packages import only cloudgraph;
// neither imports the other or this package -- correlation is a
// reporting-layer join, never an inference baked into either evidence
// domain.
package networkcorrelation

import (
	"net"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

// ComparisonLabel never implies a security verdict stronger than "these
// two independently-collected pieces of evidence agree" or "disagree" --
// DiscrepancyUnenforcedDeny in particular means "the parsed policy and
// the live test disagree," never "confirmed vulnerability": the policy
// input may itself be a stale or imperfect translation.
type ComparisonLabel string

const (
	ConsistentAllow            ComparisonLabel = "consistent-allow"
	DiscrepancyUnexpectedBlock ComparisonLabel = "discrepancy-unexpected-block"
	DiscrepancyUnenforcedDeny  ComparisonLabel = "discrepancy-unenforced-deny"
	ConsistentDeny             ComparisonLabel = "consistent-deny"
	Untested                   ComparisonLabel = "untested"
	PolicyInconclusive         ComparisonLabel = "policy-inconclusive"
)

// ReachabilityComparison pairs one PolicyEvaluation with the
// NetworkObservation (if any) that corroborates or contradicts it.
type ReachabilityComparison struct {
	Evaluation  networkpolicy.PolicyEvaluation    `json:"evaluation"`
	Observation *networkgraph.NetworkObservation `json:"observation,omitempty"`
	Label       ComparisonLabel                   `json:"label"`
}

// CorrelateReachability joins each evaluation to the observation (if any)
// whose Target falls inside the evaluation's destination CIDR on the same
// port, and labels the pair. Neither evaluations' nor observations' own
// States are re-derived here -- only compared.
func CorrelateReachability(evaluations []networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) []ReachabilityComparison {
	out := make([]ReachabilityComparison, len(evaluations))
	for i, ev := range evaluations {
		o := findMatchingObservation(ev, observations)
		out[i] = ReachabilityComparison{Evaluation: ev, Observation: o, Label: labelFor(ev.State, o)}
	}
	return out
}

// findMatchingObservation only correlates against a query's direct
// DestCIDR -- a zone-named destination has no single host to match
// against an observation's Target.Host. A non-IP Target.Host (Phase 1
// never requires a literal IP) fails net.ParseIP and is treated as no
// match, honestly: Phase 2A performs no DNS resolution.
func findMatchingObservation(ev networkpolicy.PolicyEvaluation, observations []networkgraph.NetworkObservation) *networkgraph.NetworkObservation {
	if ev.Query.DestCIDR == "" {
		return nil
	}
	_, destNet, err := net.ParseCIDR(ev.Query.DestCIDR)
	if err != nil {
		return nil
	}
	for i := range observations {
		o := &observations[i]
		if o.Target.Port != ev.Query.Port {
			continue
		}
		ip := net.ParseIP(o.Target.Host)
		if ip == nil || !destNet.Contains(ip) {
			continue
		}
		return o
	}
	return nil
}

func labelFor(policyState cloudgraph.PathState, obs *networkgraph.NetworkObservation) ComparisonLabel {
	if policyState == cloudgraph.Unknown {
		return PolicyInconclusive
	}
	if obs == nil || obs.State == cloudgraph.Unknown {
		return Untested
	}
	switch {
	case policyState == cloudgraph.PolicySupported && obs.State == cloudgraph.Observed:
		return ConsistentAllow
	case policyState == cloudgraph.PolicySupported && obs.State == cloudgraph.Blocked:
		return DiscrepancyUnexpectedBlock
	case policyState == cloudgraph.Blocked && obs.State == cloudgraph.Observed:
		return DiscrepancyUnenforcedDeny
	case policyState == cloudgraph.Blocked && obs.State == cloudgraph.Blocked:
		return ConsistentDeny
	default:
		return Untested
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/networkcorrelation/... -v`
Expected: PASS (9/9).

- [ ] **Step 5: Run the full build**

Run: `cd orchestrator && go build ./...`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/networkcorrelation/correlate.go orchestrator/internal/networkcorrelation/correlate_test.go
git commit -m "feat(networkcorrelation): add policy/reachability evidence correlation"
```

---

### Task 4: Database Schema & Store

**Files:**
- Create: `orchestrator/internal/db/networkpolicy_store.go`
- Test: `orchestrator/internal/db/networkpolicy_store_test.go`
- Modify: `orchestrator/cmd/server/main.go` (wire `EnsureNetworkPolicySchema`)
- Modify: `orchestrator/internal/testutil/testdb.go` (wire `EnsureNetworkPolicySchema`)

**Interfaces:**
- Consumes: `networkpolicy.PolicyImport`/`Zone`/`Rule`/`DefaultPolicy` (Tasks 1-2). Reuses `db.nullableString` (already defined in `networkdiscovery_store.go`, same package).
- Produces: `db.EnsureNetworkPolicySchema(ctx, pool) error`, `db.InsertNetworkPolicyImport(ctx, pool, imp *networkpolicy.PolicyImport) error`, `db.GetNetworkPolicyImport(ctx, pool, id string) (*networkpolicy.PolicyImport, error)` (404 via `errors.Is(err, pgx.ErrNoRows)`), `db.ListNetworkPolicyImports(ctx, pool, limit int) ([]*networkpolicy.PolicyImport, error)`. Task 5/6 consume every one of these exactly as defined here.

- [ ] **Step 1: Write the failing tests for the store layer**

Create `orchestrator/internal/db/networkpolicy_store_test.go`:

```go
package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkpolicy"
)

func TestInsertNetworkPolicyImport_RoundTripsThroughGetAndList(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		imp := &networkpolicy.PolicyImport{
			ID: "npimp-roundtrip-1", SourceType: "manual-normalized", ImportedBy: "alice",
			ConfigVersion: "v1", DefaultPolicy: networkpolicy.DefaultDeny,
			Zones:       []networkpolicy.Zone{{Name: "dmz", CIDRs: []string{"10.0.1.0/24"}}},
			Rules:       []networkpolicy.Rule{{ID: "r1", Order: 1, SourceZone: "dmz", DestCIDR: "0.0.0.0/0", PortRange: "443", Action: networkpolicy.ActionAllow}},
			Limitations: []string{"hand-translated from a vendor export"},
		}
		if err := db.InsertNetworkPolicyImport(context.Background(), pool, imp); err != nil {
			t.Fatalf("insert: %v", err)
		}

		got, err := db.GetNetworkPolicyImport(context.Background(), pool, imp.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.SourceType != "manual-normalized" || got.ImportedBy != "alice" || got.ConfigVersion != "v1" || got.DefaultPolicy != networkpolicy.DefaultDeny {
			t.Fatalf("got %+v, want SourceType=manual-normalized ImportedBy=alice ConfigVersion=v1 DefaultPolicy=deny", got)
		}
		if len(got.Zones) != 1 || got.Zones[0].Name != "dmz" || len(got.Zones[0].CIDRs) != 1 || got.Zones[0].CIDRs[0] != "10.0.1.0/24" {
			t.Fatalf("Zones round-trip mismatch: %+v", got.Zones)
		}
		if len(got.Rules) != 1 || got.Rules[0].ID != "r1" || got.Rules[0].Action != networkpolicy.ActionAllow {
			t.Fatalf("Rules round-trip mismatch: %+v", got.Rules)
		}
		if len(got.Limitations) != 1 || got.Limitations[0] != "hand-translated from a vendor export" {
			t.Fatalf("Limitations round-trip mismatch: %+v", got.Limitations)
		}
		if got.ImportedAt.IsZero() {
			t.Fatal("ImportedAt should be populated by the database default")
		}

		list, err := db.ListNetworkPolicyImports(context.Background(), pool, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		found := false
		for _, r := range list {
			if r.ID == imp.ID {
				found = true
			}
		}
		if !found {
			t.Fatal("inserted import should appear in the list")
		}
	})
}

func TestGetNetworkPolicyImport_NonexistentIDReturnsErrNoRows(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		_, err := db.GetNetworkPolicyImport(context.Background(), pool, "nonexistent-import-id")
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("got %v, want an error satisfying errors.Is(err, pgx.ErrNoRows)", err)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/db/...`
Expected: FAIL — `db.PolicyImport`-related functions undefined.

- [ ] **Step 3: Implement the schema and store functions**

Create `orchestrator/internal/db/networkpolicy_store.go`:

```go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/networkpolicy"
)

// EnsureNetworkPolicySchema creates the network_policy_imports table.
func EnsureNetworkPolicySchema(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS network_policy_imports (
			id             text        PRIMARY KEY DEFAULT gen_random_uuid()::text,
			source_type    text        NOT NULL,
			imported_by    text,
			imported_at    timestamptz NOT NULL DEFAULT NOW(),
			config_version text,
			default_policy text        NOT NULL,
			limitations    text[],
			policy_data    jsonb       NOT NULL
		)`)
	if err != nil {
		return fmt.Errorf("network_policy_imports: ensure schema: %w", err)
	}
	return nil
}

// policyData is the shape persisted in the policy_data jsonb column --
// just the two slices that make an import's content, not its metadata
// (which live in their own columns).
type policyData struct {
	Zones []networkpolicy.Zone `json:"zones"`
	Rules []networkpolicy.Rule `json:"rules"`
}

// InsertNetworkPolicyImport writes a new network_policy_imports row. The
// caller supplies imp.ID already generated.
func InsertNetworkPolicyImport(ctx context.Context, pool *pgxpool.Pool, imp *networkpolicy.PolicyImport) error {
	data, err := json.Marshal(policyData{Zones: imp.Zones, Rules: imp.Rules})
	if err != nil {
		return fmt.Errorf("network_policy_imports: marshal policy data for %s: %w", imp.ID, err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO network_policy_imports (id, source_type, imported_by, config_version, default_policy, limitations, policy_data)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		imp.ID, imp.SourceType, nullableString(imp.ImportedBy), nullableString(imp.ConfigVersion), string(imp.DefaultPolicy), imp.Limitations, data)
	if err != nil {
		return fmt.Errorf("network_policy_imports: insert %s: %w", imp.ID, err)
	}
	return nil
}

func scanNetworkPolicyImport(row pgx.Row) (*networkpolicy.PolicyImport, error) {
	imp := &networkpolicy.PolicyImport{}
	var importedBy, configVersion *string
	var defaultPolicy string
	var data []byte
	if err := row.Scan(&imp.ID, &imp.SourceType, &importedBy, &imp.ImportedAt, &configVersion, &defaultPolicy, &imp.Limitations, &data); err != nil {
		return nil, err
	}
	if importedBy != nil {
		imp.ImportedBy = *importedBy
	}
	if configVersion != nil {
		imp.ConfigVersion = *configVersion
	}
	imp.DefaultPolicy = networkpolicy.DefaultPolicy(defaultPolicy)
	var pd policyData
	if err := json.Unmarshal(data, &pd); err != nil {
		return nil, fmt.Errorf("network_policy_imports: unmarshal policy data for %s: %w", imp.ID, err)
	}
	imp.Zones = pd.Zones
	imp.Rules = pd.Rules
	return imp, nil
}

// GetNetworkPolicyImport returns one import by id. A missing id returns
// an error satisfying errors.Is(err, pgx.ErrNoRows).
func GetNetworkPolicyImport(ctx context.Context, pool *pgxpool.Pool, id string) (*networkpolicy.PolicyImport, error) {
	row := pool.QueryRow(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, default_policy, limitations, policy_data
		 FROM network_policy_imports WHERE id = $1`, id)
	imp, err := scanNetworkPolicyImport(row)
	if err != nil {
		return nil, fmt.Errorf("network_policy_imports: get %s: %w", id, err)
	}
	return imp, nil
}

// ListNetworkPolicyImports returns up to limit rows, newest first.
func ListNetworkPolicyImports(ctx context.Context, pool *pgxpool.Pool, limit int) ([]*networkpolicy.PolicyImport, error) {
	rows, err := pool.Query(ctx,
		`SELECT id, source_type, imported_by, imported_at, config_version, default_policy, limitations, policy_data
		 FROM network_policy_imports ORDER BY imported_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("network_policy_imports: list: %w", err)
	}
	defer rows.Close()
	var out []*networkpolicy.PolicyImport
	for rows.Next() {
		imp, err := scanNetworkPolicyImport(rows)
		if err != nil {
			return nil, fmt.Errorf("network_policy_imports: list scan: %w", err)
		}
		out = append(out, imp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("network_policy_imports: list rows: %w", err)
	}
	return out, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd orchestrator && go test ./internal/db/... -run 'TestInsertNetworkPolicyImport|TestGetNetworkPolicyImport' -v`
Expected: PASS (2/2).

- [ ] **Step 5: Wire the schema into server startup and the test pool**

In `orchestrator/cmd/server/main.go`, immediately after the existing block:

```go
	if err := db.EnsureNetworkDiscoverySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] network discovery schema: %v", err)
	}
```

add:

```go
	if err := db.EnsureNetworkPolicySchema(context.Background(), adminPool); err != nil {
		log.Fatalf("[FATAL] network policy schema: %v", err)
	}
```

In `orchestrator/internal/testutil/testdb.go`, immediately after the existing block:

```go
	if err := db.EnsureNetworkDiscoverySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureNetworkDiscoverySchema: %w", err)
	}
```

add:

```go
	if err := db.EnsureNetworkPolicySchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(context.Background())
		return nil, fmt.Errorf("testutil: EnsureNetworkPolicySchema: %w", err)
	}
```

- [ ] **Step 6: Run the full db package suite**

Run: `cd orchestrator && go build ./... && go test ./internal/db/... -v`
Expected: build clean; full suite passes (every existing `internal/db` test plus the 2 new ones from this task).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/db/networkpolicy_store.go orchestrator/internal/db/networkpolicy_store_test.go orchestrator/cmd/server/main.go orchestrator/internal/testutil/testdb.go
git commit -m "feat(networkpolicy): add schema and store layer for policy imports"
```

---

### Task 5: Import/List/Get HTTP API + New Permission

**Files:**
- Create: `orchestrator/internal/api/networkpolicy_handlers.go`
- Test: `orchestrator/internal/api/networkpolicy_handlers_test.go`
- Modify: `orchestrator/internal/auth/permissions.go` (add `CanImportNetworkPolicy`, grant to `RoleAdmin`+`RoleAnalyst`)
- Modify: `orchestrator/internal/api/routes.go` (register 3 routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (3 matching rows)

**Interfaces:**
- Consumes: `networkpolicy.PolicyImport`/`Zone`/`Rule`/`RuleAction`/`DefaultPolicy`/`ParsePortRange`/`MaxZonesPerImport`/`MaxRulesPerImport` (Tasks 1-2), `db.InsertNetworkPolicyImport`/`GetNetworkPolicyImport`/`ListNetworkPolicyImports` (Task 4), plus existing `auth.ClaimsFrom`, `newID()`, `jsonError`, `respond`, `respondStatus`, `h.auditLog` (all reused identically from Phase 1's handlers).
- Produces: `h.CreateNetworkPolicyImport`, `h.ListNetworkPolicyImports`, `h.GetNetworkPolicyImport` (handler methods), `auth.CanImportNetworkPolicy`. Task 6 reuses `auth.CanImportNetworkPolicy` for its own route gating.

- [ ] **Step 1: Add the new permission**

In `orchestrator/internal/auth/permissions.go`, immediately before the closing `)` of the `Permission` const block (right after `CanResolveActorIdentity`):

```go
	// network-policy:import gates importing a normalized firewall/
	// segmentation policy document (Network BAS Phase 2A) -- granted
	// alongside CanRunScenario, not admin-only, since this is an
	// analyst-usable, evidence-producing action.
	CanImportNetworkPolicy Permission = "network-policy:import"
)
```

(replacing the line that currently reads `CanResolveActorIdentity Permission = "intel:resolve-actor"` followed by `)` with both lines followed by `)`).

In the same file's `rolePermissions` map, add `CanImportNetworkPolicy: true,` immediately after `CanRunScenario: true,` in **both** the `RoleAdmin` block (near `CanRunScenario: true, CanRunCalderaAdversary: true, CanRunAdversaryTemplate: true,`) and the `RoleAnalyst` block (same line shape).

- [ ] **Step 2: Write the failing tests for the import/list/get endpoints**

Create `orchestrator/internal/api/networkpolicy_handlers_test.go`:

```go
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkpolicy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func validPolicyImportBody() map[string]any {
	return map[string]any{
		"sourceType":    "manual-normalized",
		"defaultPolicy": "deny",
		"zones":         []map[string]any{{"name": "dmz", "cidrs": []string{"10.0.1.0/24"}}},
		"rules": []map[string]any{
			{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "portRange": "443", "action": "allow"},
		},
	}
}

func networkPolicyImportReq(t *testing.T, pool *pgxpool.Pool, body map[string]any) *http.Request {
	t.Helper()
	userID := seedUser(t, pool, "netpolicy-op", "pw12345678", string(auth.RoleAnalyst), true)
	b, _ := json.Marshal(body)
	return authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
}

func TestCreateNetworkPolicyImport_ValidImportPersists(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkPolicyImportReq(t, pool, validPolicyImportBody())
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkpolicy.PolicyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.ID == "" {
			t.Fatal("want non-empty id")
		}
	})
}

func TestCreateNetworkPolicyImport_EmptyZonesRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["zones"] = []map[string]any{}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_EmptyRulesRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_InvalidCIDRRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["zones"] = []map[string]any{{"name": "dmz", "cidrs": []string{"not-a-cidr"}}}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_UnknownActionRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "action": "maybe"}}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_UnresolvedWithoutNoteRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "action": "unresolved"}}
		body["limitations"] = []string{"something"}
		req := networkPolicyImportReq(t, pool, body)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_UnresolvedWithoutLimitationsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := validPolicyImportBody()
		body["rules"] = []map[string]any{{"id": "r1", "order": 1, "sourceZone": "dmz", "destCidr": "0.0.0.0/0", "action": "unresolved", "note": "NAT, cannot translate"}}
		req := networkPolicyImportReq(t, pool, body) // no top-level "limitations" key
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpolicy-op-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"sourceType":"` + strings.Repeat("x", maxNetworkPolicyImportRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestCreateNetworkPolicyImport_ImportedByIsServerControlled(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpolicy-op-spoof", "pw12345678", string(auth.RoleAnalyst), true)
		body := validPolicyImportBody()
		body["importedBy"] = "spoofed-user"
		b, _ := json.Marshal(body)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-imports", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.CreateNetworkPolicyImport, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var resp networkpolicy.PolicyImport
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}

		got, err := db.GetNetworkPolicyImport(context.Background(), pool, resp.ID)
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		if got.ImportedBy != userID {
			t.Fatalf("ImportedBy = %q, want %q (the authenticated caller, not the spoofed body value)", got.ImportedBy, userID)
		}
	})
}

func TestListAndGetNetworkPolicyImport_RoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := networkPolicyImportReq(t, pool, validPolicyImportBody())
		createRec := callAuthed(h.CreateNetworkPolicyImport, req)
		if createRec.Code != http.StatusCreated {
			t.Fatalf("create status = %d, body = %s", createRec.Code, createRec.Body.String())
		}
		var created networkpolicy.PolicyImport
		if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
			t.Fatalf("decode create: %v", err)
		}

		listReq := authedRequest(t, http.MethodGet, "/api/network-policy-imports", nil, auth.RoleViewer, "")
		listRec := callAuthed(h.ListNetworkPolicyImports, listReq)
		if listRec.Code != http.StatusOK {
			t.Fatalf("list status = %d, body = %s", listRec.Code, listRec.Body.String())
		}

		getReq := authedRequest(t, http.MethodGet, "/api/network-policy-imports/"+created.ID, nil, auth.RoleViewer, "")
		getReq = withURLParam(getReq, "id", created.ID)
		getRec := callAuthed(h.GetNetworkPolicyImport, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("get status = %d, body = %s", getRec.Code, getRec.Body.String())
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.CreateNetworkPolicyImport`, `maxNetworkPolicyImportRequestBytes` undefined.

- [ ] **Step 4: Implement the handlers**

Create `orchestrator/internal/api/networkpolicy_handlers.go`:

```go
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
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkpolicy"
)

// maxNetworkPolicyImportRequestBytes is larger than Phase 1's equivalent
// caps -- a real policy document (up to MaxRulesPerImport rules) is
// bigger than a target list, but still ships from the start, not as a
// follow-up fix.
const maxNetworkPolicyImportRequestBytes = 5 << 20

// CreateNetworkPolicyImport -- POST /api/network-policy-imports.
func (h *Handler) CreateNetworkPolicyImport(w http.ResponseWriter, r *http.Request) {
	var req networkpolicy.PolicyImport
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkPolicyImportRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateNetworkPolicyImport(&req); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var importedBy string
	if c, ok := auth.ClaimsFrom(r.Context()); ok && c != nil {
		importedBy = c.UserID
	}
	req.ID = newID()
	req.ImportedBy = importedBy

	if err := db.InsertNetworkPolicyImport(r.Context(), h.db, &req); err != nil {
		h.auditLog(r, "networkpolicy.import", "", map[string]any{"error": err.Error()}, "error")
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditLog(r, "networkpolicy.import", req.ID, map[string]any{"ruleCount": len(req.Rules), "zoneCount": len(req.Zones)}, "ok")
	respondStatus(w, req, http.StatusCreated)
}

func validateNetworkPolicyImport(imp *networkpolicy.PolicyImport) error {
	if len(imp.Zones) == 0 {
		return fmt.Errorf("at least one zone is required")
	}
	if len(imp.Zones) > networkpolicy.MaxZonesPerImport {
		return fmt.Errorf("too many zones — got %d, max %d", len(imp.Zones), networkpolicy.MaxZonesPerImport)
	}
	if len(imp.Rules) == 0 {
		return fmt.Errorf("at least one rule is required")
	}
	if len(imp.Rules) > networkpolicy.MaxRulesPerImport {
		return fmt.Errorf("too many rules — got %d, max %d", len(imp.Rules), networkpolicy.MaxRulesPerImport)
	}
	if imp.DefaultPolicy != networkpolicy.DefaultAllow && imp.DefaultPolicy != networkpolicy.DefaultDeny {
		return fmt.Errorf("defaultPolicy must be %q or %q", networkpolicy.DefaultAllow, networkpolicy.DefaultDeny)
	}
	for i, z := range imp.Zones {
		if z.Name == "" {
			return fmt.Errorf("zones[%d]: name required", i)
		}
		for _, c := range z.CIDRs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return fmt.Errorf("zones[%d]: invalid CIDR %q", i, c)
			}
		}
	}
	hasLimitations := len(imp.Limitations) > 0
	for i, rule := range imp.Rules {
		switch rule.Action {
		case networkpolicy.ActionAllow, networkpolicy.ActionDeny:
		case networkpolicy.ActionUnresolved:
			if rule.Note == "" {
				return fmt.Errorf("rules[%d]: note required when action is unresolved", i)
			}
			if !hasLimitations {
				return fmt.Errorf("limitations must be non-empty when any rule is unresolved")
			}
		default:
			return fmt.Errorf("rules[%d]: unknown action %q", i, rule.Action)
		}
		if rule.SourceCIDR != "" {
			if _, _, err := net.ParseCIDR(rule.SourceCIDR); err != nil {
				return fmt.Errorf("rules[%d]: invalid sourceCidr %q", i, rule.SourceCIDR)
			}
		}
		if rule.DestCIDR != "" {
			if _, _, err := net.ParseCIDR(rule.DestCIDR); err != nil {
				return fmt.Errorf("rules[%d]: invalid destCidr %q", i, rule.DestCIDR)
			}
		}
		if _, _, _, err := networkpolicy.ParsePortRange(rule.PortRange); err != nil {
			return fmt.Errorf("rules[%d]: %v", i, err)
		}
	}
	return nil
}

// ListNetworkPolicyImports -- GET /api/network-policy-imports.
func (h *Handler) ListNetworkPolicyImports(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 && l <= 100 {
		limit = l
	}
	imports, err := db.ListNetworkPolicyImports(r.Context(), h.db, limit)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if imports == nil {
		imports = []*networkpolicy.PolicyImport{}
	}
	respond(w, imports)
}

// GetNetworkPolicyImport -- GET /api/network-policy-imports/{id}.
func (h *Handler) GetNetworkPolicyImport(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	imp, err := db.GetNetworkPolicyImport(r.Context(), h.db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network policy import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, imp)
}
```

- [ ] **Step 5: Register the routes and RBAC matrix rows**

In `orchestrator/internal/api/routes.go`, right after:

```go
		r.Get("/api/network-discovery-runs", h.ListNetworkDiscoveryRuns)
```

add:

```go
		r.Get("/api/network-policy-imports", h.ListNetworkPolicyImports)
```

Right after:

```go
		r.Get("/api/network-discovery-runs/{id}", h.GetNetworkDiscoveryRun)
```

add:

```go
		r.Get("/api/network-policy-imports/{id}", h.GetNetworkPolicyImport)
```

Right after:

```go
		r.With(auth.RequirePermission(auth.CanRunScenario)).Post("/api/network-discovery-runs", h.TriggerNetworkDiscoveryRun)
```

add:

```go
		r.With(auth.RequirePermission(auth.CanImportNetworkPolicy)).Post("/api/network-policy-imports", h.CreateNetworkPolicyImport)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, right after:

```go
	{http.MethodGet, "/api/network-discovery-runs", tierAny, ""},
	{http.MethodGet, "/api/network-discovery-runs/{id}", tierAny, ""},
```

add:

```go
	{http.MethodGet, "/api/network-policy-imports", tierAny, ""},
	{http.MethodGet, "/api/network-policy-imports/{id}", tierAny, ""},
```

and right after:

```go
	{http.MethodPost, "/api/network-discovery-runs", tierPermission, auth.CanRunScenario},
```

add:

```go
	{http.MethodPost, "/api/network-policy-imports", tierPermission, auth.CanImportNetworkPolicy},
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/api/... -run 'TestCreateNetworkPolicyImport|TestListAndGetNetworkPolicyImport|TestRBACMatrix_NoDrift' -v`
Expected: PASS (all 11 tests).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/networkpolicy_handlers.go orchestrator/internal/api/networkpolicy_handlers_test.go orchestrator/internal/auth/permissions.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networkpolicy): add import/list/get HTTP API and CanImportNetworkPolicy permission"
```

---

### Task 6: Evaluation + Reachability Comparison HTTP API

**Files:**
- Create: `orchestrator/internal/api/networkpolicy_evaluation_handlers.go`
- Test: `orchestrator/internal/api/networkpolicy_evaluation_handlers_test.go`
- Modify: `orchestrator/internal/api/routes.go` (register 2 routes)
- Modify: `orchestrator/internal/api/rbac_matrix_test.go` (2 matching rows)

**Interfaces:**
- Consumes: everything from Tasks 1-5 (`networkpolicy.EvaluatePolicyMatrix`/`PolicyQuery`, `networkcorrelation.CorrelateReachability`, `db.GetNetworkPolicyImport`, `db.GetNetworkDiscoveryRun`/`ListNetworkObservationsByRun` (Phase 1, unchanged), `auth.CanImportNetworkPolicy` (Task 5)).
- Produces: nothing consumed by a later task — this is the last task of this plan.

- [ ] **Step 1: Write the failing tests for evaluation and comparison**

Create `orchestrator/internal/api/networkpolicy_evaluation_handlers_test.go`:

```go
package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/networkcorrelation"
	"github.com/audspect/bas/internal/networkpolicy"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func createTestPolicyImport(t *testing.T, h *Handler, pool *pgxpool.Pool) string {
	t.Helper()
	req := networkPolicyImportReq(t, pool, validPolicyImportBody())
	rec := callAuthed(h.CreateNetworkPolicyImport, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create policy import: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created networkpolicy.PolicyImport
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	return created.ID
}

func TestEvaluateNetworkPolicy_ValidRequestReturnsEvaluations(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		importID := createTestPolicyImport(t, h, pool)

		body := map[string]any{
			"policyImportId": importID,
			"queries":        []map[string]any{{"sourceZone": "dmz", "destCidr": "203.0.113.5/32", "protocol": "tcp", "port": 443}},
		}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpolicy-eval-op", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
		var evals []networkpolicy.PolicyEvaluation
		if err := json.Unmarshal(rec.Body.Bytes(), &evals); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(evals) != 1 {
			t.Fatalf("got %d evaluations, want 1", len(evals))
		}
	})
}

func TestEvaluateNetworkPolicy_UnknownPolicyImportReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"policyImportId": "nonexistent-id", "queries": []map[string]any{{"port": 443}}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpolicy-eval-404", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestEvaluateNetworkPolicy_MissingPolicyImportIdRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		body := map[string]any{"queries": []map[string]any{{"port": 443}}}
		b, _ := json.Marshal(body)
		userID := seedUser(t, pool, "netpolicy-eval-noid", "pw12345678", string(auth.RoleAnalyst), true)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(b), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestEvaluateNetworkPolicy_OversizedBodyRejectedBeforeFullDecode(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		userID := seedUser(t, pool, "netpolicy-eval-oversize", "pw12345678", string(auth.RoleAnalyst), true)
		oversized := []byte(`{"policyImportId":"` + strings.Repeat("x", maxNetworkPolicyEvaluationRequestBytes+1) + `"}`)
		req := authedRequest(t, http.MethodPost, "/api/network-policy-evaluations", bytes.NewReader(oversized), auth.RoleAnalyst, userID)
		rec := callAuthed(h.EvaluateNetworkPolicy, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetNetworkReachabilityComparison_EndToEndAgainstRealDiscoveryRun(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		vp := testVantagePoint()
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithNetworkVantagePoint(vp)

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		openPort := ln.Addr().(*net.TCPAddr).Port

		discoveryReq := networkDiscoveryReq(t, pool, map[string]any{"targets": []map[string]any{{"host": "127.0.0.1", "port": openPort}}})
		discoveryRec := callAuthed(h.TriggerNetworkDiscoveryRun, discoveryReq)
		if discoveryRec.Code != http.StatusCreated {
			t.Fatalf("trigger discovery: status = %d, body = %s", discoveryRec.Code, discoveryRec.Body.String())
		}
		var discoveryResp struct{ RunID string `json:"runId"` }
		if err := json.Unmarshal(discoveryRec.Body.Bytes(), &discoveryResp); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}

		// A permissive policy import whose default is allow, so the
		// /32 destination of the actual probed target resolves to
		// PolicySupported -- paired with Phase 1's real Observed result,
		// this must label as consistent-allow end to end.
		policyBody := map[string]any{
			"sourceType": "manual-normalized", "defaultPolicy": "allow",
			"zones": []map[string]any{{"name": "any", "cidrs": []string{"0.0.0.0/0"}}},
			"rules": []map[string]any{{"id": "r1", "order": 1, "sourceZone": "any", "destZone": "any", "action": "allow"}},
		}
		policyReq := networkPolicyImportReq(t, pool, policyBody)
		policyRec := callAuthed(h.CreateNetworkPolicyImport, policyReq)
		if policyRec.Code != http.StatusCreated {
			t.Fatalf("create policy: status = %d, body = %s", policyRec.Code, policyRec.Body.String())
		}
		var policyResp networkpolicy.PolicyImport
		if err := json.Unmarshal(policyRec.Body.Bytes(), &policyResp); err != nil {
			t.Fatalf("decode policy: %v", err)
		}

		compareURL := "/api/network-reachability-comparisons?policyImportId=" + policyResp.ID + "&discoveryRunId=" + discoveryResp.RunID
		compareReq := authedRequest(t, http.MethodGet, compareURL, nil, auth.RoleViewer, "")
		compareRec := callAuthed(h.GetNetworkReachabilityComparison, compareReq)
		if compareRec.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", compareRec.Code, compareRec.Body.String())
		}
		var comparisons []networkcorrelation.ReachabilityComparison
		if err := json.Unmarshal(compareRec.Body.Bytes(), &comparisons); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(comparisons) != 1 {
			t.Fatalf("got %d comparisons, want 1", len(comparisons))
		}
		if comparisons[0].Label != networkcorrelation.ConsistentAllow {
			t.Fatalf("label = %q, want consistent-allow -- a permissive policy plus a real observed-open port must agree", comparisons[0].Label)
		}
	})
}

func TestGetNetworkReachabilityComparison_MissingParamsRejected(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		req := authedRequest(t, http.MethodGet, "/api/network-reachability-comparisons", nil, auth.RoleViewer, "")
		rec := callAuthed(h.GetNetworkReachabilityComparison, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestGetNetworkReachabilityComparison_UnknownDiscoveryRunReturns404(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret)
		importID := createTestPolicyImport(t, h, pool)
		url := "/api/network-reachability-comparisons?policyImportId=" + importID + "&discoveryRunId=nonexistent-run"
		req := authedRequest(t, http.MethodGet, url, nil, auth.RoleViewer, "")
		rec := callAuthed(h.GetNetworkReachabilityComparison, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
		}
	})
}

```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go vet ./internal/api/...`
Expected: FAIL — `h.EvaluateNetworkPolicy`, `h.GetNetworkReachabilityComparison` undefined.

- [ ] **Step 3: Implement the handlers**

Create `orchestrator/internal/api/networkpolicy_evaluation_handlers.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/networkcorrelation"
	"github.com/audspect/bas/internal/networkgraph"
	"github.com/audspect/bas/internal/networkpolicy"
)

const maxNetworkPolicyEvaluationRequestBytes = 1 << 20

// EvaluateNetworkPolicy -- POST /api/network-policy-evaluations. Loads an
// already-persisted policy import and evaluates a caller-supplied query
// batch against it. Computed fresh on every call -- nothing here is
// persisted.
func (h *Handler) EvaluateNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PolicyImportID string                      `json:"policyImportId"`
		Queries        []networkpolicy.PolicyQuery `json:"queries"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNetworkPolicyEvaluationRequestBytes)).Decode(&req); err != nil {
		jsonError(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PolicyImportID == "" {
		jsonError(w, "policyImportId is required", http.StatusBadRequest)
		return
	}
	imp, err := db.GetNetworkPolicyImport(r.Context(), h.db, req.PolicyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network policy import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	evaluations, err := networkpolicy.EvaluatePolicyMatrix(imp, req.Queries)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	respond(w, evaluations)
}

// GetNetworkReachabilityComparison -- GET /api/network-reachability-comparisons.
// Derives one PolicyQuery per observation in the named discovery run (its
// Target.Host as a /32 destination, keeping the comparison apples-to-
// apples with exactly what Phase 1 actually probed, never a caller-
// supplied, possibly-mismatched query list), evaluates them against the
// named policy import, and correlates. Not persisted -- recomputed fresh
// on every call from the two already-persisted evidence sources.
func (h *Handler) GetNetworkReachabilityComparison(w http.ResponseWriter, r *http.Request) {
	policyImportID := r.URL.Query().Get("policyImportId")
	discoveryRunID := r.URL.Query().Get("discoveryRunId")
	if policyImportID == "" || discoveryRunID == "" {
		jsonError(w, "policyImportId and discoveryRunId are both required", http.StatusBadRequest)
		return
	}

	imp, err := db.GetNetworkPolicyImport(r.Context(), h.db, policyImportID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network policy import not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := db.GetNetworkDiscoveryRun(r.Context(), h.db, discoveryRunID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, "network discovery run not found", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	observations, err := db.ListNetworkObservationsByRun(r.Context(), h.db, discoveryRunID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(observations) == 0 {
		respond(w, []networkcorrelation.ReachabilityComparison{})
		return
	}

	queries := queriesFromObservations(observations)
	evaluations, err := networkpolicy.EvaluatePolicyMatrix(imp, queries)
	if err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	comparisons := networkcorrelation.CorrelateReachability(evaluations, observations)
	respond(w, comparisons)
}

// queriesFromObservations turns each observation's target into a direct
// /32-CIDR destination query. A non-IP Target.Host produces an invalid
// CIDR string here, which EvaluatePolicyMatrix's own resolution will
// reject into an Unknown result for that one query -- not a crash --
// since Phase 2A performs no DNS resolution (see networkcorrelation's
// own doc comment for the matching half of this same honesty rule).
func queriesFromObservations(observations []networkgraph.NetworkObservation) []networkpolicy.PolicyQuery {
	out := make([]networkpolicy.PolicyQuery, len(observations))
	for i, o := range observations {
		out[i] = networkpolicy.PolicyQuery{DestCIDR: o.Target.Host + "/32", Port: o.Target.Port, Protocol: o.Target.Protocol}
	}
	return out
}
```

- [ ] **Step 4: Register the routes and RBAC matrix rows**

In `orchestrator/internal/api/routes.go`, right after:

```go
		r.Get("/api/network-policy-imports/{id}", h.GetNetworkPolicyImport)
```

add:

```go
		r.Get("/api/network-reachability-comparisons", h.GetNetworkReachabilityComparison)
```

Right after:

```go
		r.With(auth.RequirePermission(auth.CanImportNetworkPolicy)).Post("/api/network-policy-imports", h.CreateNetworkPolicyImport)
```

add:

```go
		r.With(auth.RequirePermission(auth.CanImportNetworkPolicy)).Post("/api/network-policy-evaluations", h.EvaluateNetworkPolicy)
```

In `orchestrator/internal/api/rbac_matrix_test.go`, right after:

```go
	{http.MethodGet, "/api/network-policy-imports/{id}", tierAny, ""},
```

add:

```go
	{http.MethodGet, "/api/network-reachability-comparisons", tierAny, ""},
```

and right after:

```go
	{http.MethodPost, "/api/network-policy-imports", tierPermission, auth.CanImportNetworkPolicy},
```

add:

```go
	{http.MethodPost, "/api/network-policy-evaluations", tierPermission, auth.CanImportNetworkPolicy},
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go build ./... && go test ./internal/api/... -run 'TestEvaluateNetworkPolicy|TestGetNetworkReachabilityComparison|TestRBACMatrix_NoDrift' -v`
Expected: PASS (all 8 tests).

- [ ] **Step 6: Run the final combined gate for the whole plan**

Per Global Constraints: check memory headroom first.

```powershell
Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize
```

Then:

```bash
cd orchestrator
go build ./...
go test ./internal/networkpolicy/... ./internal/networkcorrelation/... ./internal/db/... ./internal/cloudgraph/... -v
go test ./internal/api/... -run 'TestCreateNetworkPolicyImport|TestListAndGetNetworkPolicyImport|TestEvaluateNetworkPolicy|TestGetNetworkReachabilityComparison|TestRBACMatrix_NoDrift|TestTriggerNetworkDiscoveryRun|TestTriggerCloudPlanRun|TestCreateCloudCampaign' -v
```

Expected: `go build ./...` clean; `networkpolicy`/`networkcorrelation`/`db`/`cloudgraph` suites pass in full; every new test from this plan plus the RBAC matrix test plus the pre-existing Phase 1/cloud-run/cloud-campaign tests (regression check — this plan touches `permissions.go`, `routes.go`, `rbac_matrix_test.go`, `main.go`, `testdb.go`, all shared files) pass with zero failures.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/networkpolicy_evaluation_handlers.go orchestrator/internal/api/networkpolicy_evaluation_handlers_test.go orchestrator/internal/api/routes.go orchestrator/internal/api/rbac_matrix_test.go
git commit -m "feat(networkpolicy): add evaluation and reachability comparison HTTP API"
```

---

## Execution Handoff

Execution method is **Native/inline**, per direct instruction this session ("start inline"). I'll implement every task myself in this session, then dispatch one fresh Sonnet reviewer on the whole branch at the end, per `superpowers:executing-plans`.

