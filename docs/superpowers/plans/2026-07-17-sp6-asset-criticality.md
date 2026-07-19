# SP6 — Asset Criticality Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Widen the existing attack-path asset-tag model with 5 new criticality factors, fold criticality into SP4's `ExposureScore` as a 4th weighted term, and surface it through the API/UI.

**Architecture:** Extend `attackpath_asset_tags` in place (new columns, not a new table) and propagate the new fields through the exact same path `crown_jewel`/`high_value` already use: DB → `attackpath.AssetTag` → `Graph.applyAssetTags` → `attackpath.Node` → `exposure.Build` → `AssetIdentity`/`ScoreBreakdown`. A new pure function `exposure.CriticalityRisk` scores 0-100 from the tag fields plus two already-free auto-derived signals (domain-controller role, SP4 threat-group count).

**Tech Stack:** Go (`internal/db`, `internal/attackpath`, `internal/exposure`, `internal/api`), vanilla JS/HTML (`wwwroot/index.html`).

## Global Constraints
- Reweighted formula (from the approved spec, exact values): `ExposureScore = 100 - (0.30×AttackPathRisk + 0.30×DetectionRisk + 0.20×VulnerabilityRisk + 0.20×CriticalityRisk)`.
- `CriticalityRisk` bump values (starting point, from the spec): tier base critical=100/high=70/medium=40/low=15/unrated("")=0; flat bumps +15 domain-controller, +10 internet-facing, +10 identity-exposed, +10 production, +10 non-empty compliance-scope, +5 if any threat-group attributed; capped at 100.
- `internal/attackpath/score.go`'s fleet-wide `wCrownJewel` mechanism is NOT touched by this plan.
- `wwwroot/index.html` and `orchestrator/cmd/server/wwwroot/index.html` are NTFS-hardlinked (same file on disk, two git paths) — editing one edits both on disk, but both paths must be `git add`ed separately or the commit only captures one.
- Every task ends with `gofmt -l <touched files>` (must be empty) and `go build ./...` clean before moving to the next task.

---

### Task 1: Database migration

**Files:**
- Modify: `orchestrator/internal/db/postgres.go` (the `attackpath_asset_tags` `CREATE TABLE` block, currently ~line 362-369)

**Interfaces:**
- Produces: 5 new columns on `attackpath_asset_tags` — `criticality_tier text`, `internet_facing boolean`, `identity_exposed boolean`, `production boolean`, `compliance_scope text[]` — that Task 2 onward reads/writes.

- [ ] **Step 1: Widen the CREATE TABLE and add idempotent ALTERs**

Find this block in `postgres.go`:
```go
		`CREATE TABLE IF NOT EXISTS attackpath_asset_tags (
			host_key    text        PRIMARY KEY,
			label       text        NOT NULL DEFAULT '',
			crown_jewel text        NOT NULL DEFAULT '',
			segment     text        NOT NULL DEFAULT '',
			high_value  boolean     NOT NULL DEFAULT false,
			updated_at  timestamptz NOT NULL DEFAULT NOW()
		)`,
```
Replace it with:
```go
		`CREATE TABLE IF NOT EXISTS attackpath_asset_tags (
			host_key         text        PRIMARY KEY,
			label            text        NOT NULL DEFAULT '',
			crown_jewel      text        NOT NULL DEFAULT '',
			segment          text        NOT NULL DEFAULT '',
			high_value       boolean     NOT NULL DEFAULT false,
			criticality_tier text        NOT NULL DEFAULT '',
			internet_facing  boolean     NOT NULL DEFAULT false,
			identity_exposed boolean     NOT NULL DEFAULT false,
			production       boolean     NOT NULL DEFAULT false,
			compliance_scope text[]      NOT NULL DEFAULT '{}',
			updated_at       timestamptz NOT NULL DEFAULT NOW()
		)`,
		// SP6 asset criticality: widens the existing operator asset-tag row
		// (crown_jewel/high_value) with graduated criticality factors rather
		// than a parallel table — see docs/superpowers/specs/2026-07-17-sp6-asset-criticality-design.md.
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS criticality_tier text    NOT NULL DEFAULT ''`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS internet_facing  boolean NOT NULL DEFAULT false`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS identity_exposed boolean NOT NULL DEFAULT false`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS production       boolean NOT NULL DEFAULT false`,
		`ALTER TABLE attackpath_asset_tags ADD COLUMN IF NOT EXISTS compliance_scope text[]  NOT NULL DEFAULT '{}'`,
```

- [ ] **Step 2: Build**

Run: `cd orchestrator && gofmt -l internal/db/postgres.go && go build ./internal/db/...`
Expected: `gofmt -l` prints nothing; build succeeds.

- [ ] **Step 3: Commit**

```bash
git add orchestrator/internal/db/postgres.go
git commit -m "feat(sp6): widen attackpath_asset_tags with criticality columns"
```

---

### Task 2: `attackpath` model — Node + AssetTag (TDD)

**Files:**
- Modify: `orchestrator/internal/attackpath/graph.go` (`Node` struct, ~line 30-38)
- Modify: `orchestrator/internal/attackpath/assets.go` (`AssetTag` struct, `applyAssetTags`, `HostInventory`)
- Modify: `orchestrator/internal/attackpath/assets_test.go`

**Interfaces:**
- Produces: `Node.CriticalityTier/InternetFacing/IdentityExposed/Production/ComplianceScope` and matching `AssetTag` fields, consumed by Task 4 (`exposure.Build`) and Task 5 (API).

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/attackpath/assets_test.go`:
```go
func TestApplyAssetTagsCriticalityFields(t *testing.T) {
	cols := []Collection{{
		AgentID: "ws01", Source: "agent",
		Nodes: []Node{{ID: "WS01", Kind: KindHost, Role: RoleEndpoint}},
	}}
	tags := []AssetTag{{
		HostKey: "WS01", CriticalityTier: "high", InternetFacing: true,
		IdentityExposed: true, Production: true, ComplianceScope: []string{"SEBI-CSCRF", "PCI-DSS"},
	}}
	g := BuildGraph(cols...)
	g.applyAssetTags(tags)
	n, ok := g.nodes["WS01"]
	if !ok {
		t.Fatalf("expected node WS01 in graph")
	}
	if n.CriticalityTier != "high" || !n.InternetFacing || !n.IdentityExposed || !n.Production {
		t.Fatalf("criticality fields not applied: %+v", n)
	}
	if len(n.ComplianceScope) != 2 || n.ComplianceScope[0] != "SEBI-CSCRF" {
		t.Fatalf("compliance scope not applied: %+v", n.ComplianceScope)
	}
}

func TestHostInventoryIncludesCriticalityFields(t *testing.T) {
	g := BuildGraph(Collection{AgentID: "a", Edges: []Edge{{From: "A", To: "B", Kind: EdgeSMB}}})
	g.applyAssetTags([]AssetTag{{HostKey: "B", CriticalityTier: "critical", Production: true}})
	inv := g.HostInventory()
	var found bool
	for _, h := range inv {
		if h.HostKey == "B" {
			if h.CriticalityTier != "critical" || !h.Production {
				t.Fatalf("inventory should reflect criticality fields: %+v", h)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("expected host B in inventory: %+v", inv)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/attackpath/... -run "TestApplyAssetTagsCriticalityFields|TestHostInventoryIncludesCriticalityFields" -v`
Expected: FAIL — `Node`/`AssetTag` have no field `CriticalityTier` (compile error).

- [ ] **Step 3: Widen `Node`**

In `orchestrator/internal/attackpath/graph.go`, find:
```go
// Node is a vertex: a host, a user, or a group.
type Node struct {
	ID         string   `json:"id"`                   // stable identity (hostname, SID, user@domain)
	Kind       NodeKind `json:"kind"`                 // host | user | group
	Label      string   `json:"label"`                // human-readable name
	Role       HostRole `json:"role,omitempty"`       // hosts only
	Segment    string   `json:"segment,omitempty"`    // network segment / VLAN tag (for segmentation analysis)
	CrownJewel string   `json:"crownJewel,omitempty"` // "" or a tag like "ERP", "FileServer", "Backup"
	HighValue  bool     `json:"highValue,omitempty"`  // Domain Admins group / DA-equivalent (domain-compromise target)
}
```
Replace with:
```go
// Node is a vertex: a host, a user, or a group.
type Node struct {
	ID         string   `json:"id"`                   // stable identity (hostname, SID, user@domain)
	Kind       NodeKind `json:"kind"`                 // host | user | group
	Label      string   `json:"label"`                // human-readable name
	Role       HostRole `json:"role,omitempty"`       // hosts only
	Segment    string   `json:"segment,omitempty"`    // network segment / VLAN tag (for segmentation analysis)
	CrownJewel string   `json:"crownJewel,omitempty"` // "" or a tag like "ERP", "FileServer", "Backup"
	HighValue  bool     `json:"highValue,omitempty"`  // Domain Admins group / DA-equivalent (domain-compromise target)

	// SP6 asset criticality — operator-tagged, same overlay mechanism as
	// CrownJewel/HighValue above. Role==RoleDC (already set from SharpHound
	// data, see sharphound.go) is the one criticality signal NOT tagged here.
	CriticalityTier string   `json:"criticalityTier,omitempty"` // "" | low | medium | high | critical
	InternetFacing  bool     `json:"internetFacing,omitempty"`
	IdentityExposed bool     `json:"identityExposed,omitempty"`
	Production      bool     `json:"production,omitempty"`
	ComplianceScope []string `json:"complianceScope,omitempty"`
}
```

- [ ] **Step 4: Widen `AssetTag`, `applyAssetTags`, `HostInventory`**

In `orchestrator/internal/attackpath/assets.go`, find:
```go
type AssetTag struct {
	HostKey    string `json:"hostKey"`              // hostname (any form; normalized on apply)
	Label      string `json:"label,omitempty"`      // last-seen display name (UI convenience)
	CrownJewel string `json:"crownJewel,omitempty"` // "" clears the tag; else "ERP"/"FileServer"/…
	Segment    string `json:"segment,omitempty"`
	HighValue  bool   `json:"highValue,omitempty"`
}
```
Replace with:
```go
type AssetTag struct {
	HostKey    string `json:"hostKey"`              // hostname (any form; normalized on apply)
	Label      string `json:"label,omitempty"`      // last-seen display name (UI convenience)
	CrownJewel string `json:"crownJewel,omitempty"` // "" clears the tag; else "ERP"/"FileServer"/…
	Segment    string `json:"segment,omitempty"`
	HighValue  bool   `json:"highValue,omitempty"`

	// SP6 asset criticality — see Node's matching fields in graph.go.
	CriticalityTier string   `json:"criticalityTier,omitempty"`
	InternetFacing  bool     `json:"internetFacing,omitempty"`
	IdentityExposed bool     `json:"identityExposed,omitempty"`
	Production      bool     `json:"production,omitempty"`
	ComplianceScope []string `json:"complianceScope,omitempty"`
}
```

Find, inside `applyAssetTags`:
```go
		if t.CrownJewel != "" {
			n.CrownJewel = t.CrownJewel
		}
		if t.Segment != "" {
			n.Segment = t.Segment
		}
		if t.HighValue {
			n.HighValue = true
		}
		g.nodes[id] = n
```
Replace with:
```go
		if t.CrownJewel != "" {
			n.CrownJewel = t.CrownJewel
		}
		if t.Segment != "" {
			n.Segment = t.Segment
		}
		if t.HighValue {
			n.HighValue = true
		}
		if t.CriticalityTier != "" {
			n.CriticalityTier = t.CriticalityTier
		}
		if t.InternetFacing {
			n.InternetFacing = true
		}
		if t.IdentityExposed {
			n.IdentityExposed = true
		}
		if t.Production {
			n.Production = true
		}
		if len(t.ComplianceScope) > 0 {
			n.ComplianceScope = t.ComplianceScope
		}
		g.nodes[id] = n
```

Find `HostInventory`:
```go
		out = append(out, AssetTag{
			HostKey:    hostKey(n),
			Label:      n.Label,
			CrownJewel: n.CrownJewel,
			Segment:    n.Segment,
			HighValue:  n.HighValue,
		})
```
Replace with:
```go
		out = append(out, AssetTag{
			HostKey:         hostKey(n),
			Label:           n.Label,
			CrownJewel:      n.CrownJewel,
			Segment:         n.Segment,
			HighValue:       n.HighValue,
			CriticalityTier: n.CriticalityTier,
			InternetFacing:  n.InternetFacing,
			IdentityExposed: n.IdentityExposed,
			Production:      n.Production,
			ComplianceScope: n.ComplianceScope,
		})
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/attackpath/... -v`
Expected: PASS (all tests in the package, including the two new ones and every pre-existing test unaffected — additive fields only).

- [ ] **Step 6: Build and format**

Run: `cd orchestrator && gofmt -l internal/attackpath/graph.go internal/attackpath/assets.go internal/attackpath/assets_test.go && go build ./internal/attackpath/... && go vet ./internal/attackpath/...`
Expected: no gofmt output, build and vet clean.

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/attackpath/graph.go orchestrator/internal/attackpath/assets.go orchestrator/internal/attackpath/assets_test.go
git commit -m "feat(sp6): widen attackpath Node/AssetTag with criticality fields"
```

---

### Task 3: `CriticalityRisk` scoring function (TDD)

**Files:**
- Create: `orchestrator/internal/exposure/criticality.go`
- Create: `orchestrator/internal/exposure/criticality_test.go`
- Modify: `orchestrator/internal/exposure/types.go` (`AssetIdentity`, `ScoreBreakdown`, `AssetSummary`)

**Interfaces:**
- Consumes: nothing new (pure function over its own input struct).
- Produces: `CriticalityRisk(AssetCriticalityInputs) int` and the widened `AssetIdentity`/`ScoreBreakdown`/`AssetSummary` structs, both consumed by Task 4.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/exposure/criticality_test.go`:
```go
package exposure

import "testing"

func TestCriticalityRisk_UntaggedIsZero(t *testing.T) {
	if got := CriticalityRisk(AssetCriticalityInputs{}); got != 0 {
		t.Fatalf("untagged asset should score 0, got %d", got)
	}
}

func TestCriticalityRisk_TierBases(t *testing.T) {
	cases := map[string]int{"critical": 100, "high": 70, "medium": 40, "low": 15, "": 0}
	for tier, want := range cases {
		got := CriticalityRisk(AssetCriticalityInputs{CriticalityTier: tier})
		if got != want {
			t.Errorf("tier %q: got %d, want %d", tier, got, want)
		}
	}
}

func TestCriticalityRisk_BooleanBumpsAddUp(t *testing.T) {
	got := CriticalityRisk(AssetCriticalityInputs{
		IsDomainController: true, InternetFacing: true, IdentityExposed: true, Production: true,
		ComplianceScope: []string{"SEBI-CSCRF"}, ThreatGroupCount: 3,
	})
	want := 15 + 10 + 10 + 10 + 10 + 5 // 60, no tier set
	if got != want {
		t.Fatalf("got %d, want %d", got, want)
	}
}

func TestCriticalityRisk_CappedAt100(t *testing.T) {
	got := CriticalityRisk(AssetCriticalityInputs{
		CriticalityTier: "critical", IsDomainController: true, InternetFacing: true, IdentityExposed: true,
		Production: true, ComplianceScope: []string{"PCI-DSS"}, ThreatGroupCount: 1,
	})
	if got != 100 {
		t.Fatalf("got %d, want capped at 100", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd orchestrator && go test ./internal/exposure/... -run TestCriticalityRisk -v`
Expected: FAIL — `CriticalityRisk`/`AssetCriticalityInputs` undefined (compile error).

- [ ] **Step 3: Write `criticality.go`**

Create `orchestrator/internal/exposure/criticality.go`:
```go
package exposure

// AssetCriticalityInputs is everything CriticalityRisk needs to score one
// asset: the operator-set tag fields (attackpath.AssetTag/Node's
// CriticalityTier/InternetFacing/IdentityExposed/Production/ComplianceScope)
// plus the two signals this package already derives for free —
// IsDomainController from attackpath.Node.Role==RoleDC (set from SharpHound
// data) and ThreatGroupCount from this asset's own AssetExposureProfile.ThreatIntel.
type AssetCriticalityInputs struct {
	CriticalityTier    string // "" | low | medium | high | critical
	InternetFacing     bool
	IdentityExposed    bool
	Production         bool
	ComplianceScope    []string
	IsDomainController bool
	ThreatGroupCount   int
}

// CriticalityRisk scores 0-100 (higher = matters more) — see
// docs/superpowers/specs/2026-07-17-sp6-asset-criticality-design.md for the
// starting bump values; they're deliberately not sacred, tune later against
// real fleet data the same way SP4's own formula was.
func CriticalityRisk(in AssetCriticalityInputs) int {
	risk := 0
	switch in.CriticalityTier {
	case "critical":
		risk = 100
	case "high":
		risk = 70
	case "medium":
		risk = 40
	case "low":
		risk = 15
	}
	if in.IsDomainController {
		risk += 15
	}
	if in.InternetFacing {
		risk += 10
	}
	if in.IdentityExposed {
		risk += 10
	}
	if in.Production {
		risk += 10
	}
	if len(in.ComplianceScope) > 0 {
		risk += 10
	}
	if in.ThreatGroupCount > 0 {
		risk += 5
	}
	return clamp100(risk)
}
```
(`clamp100` already exists in `build.go`, same package — no import needed.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd orchestrator && go test ./internal/exposure/... -run TestCriticalityRisk -v`
Expected: PASS, all 4 tests (`TestCriticalityRisk_TierBases` runs 5 sub-cases via the map).

- [ ] **Step 5: Widen `types.go`**

In `orchestrator/internal/exposure/types.go`, find `AssetIdentity`:
```go
type AssetIdentity struct {
	HostKey    string `json:"hostKey"`
	Label      string `json:"label"`
	Managed    bool   `json:"managed"`
	AgentID    string `json:"agentId,omitempty"`
	OS         string `json:"os,omitempty"`
	IP         string `json:"ip,omitempty"`
	CrownJewel string `json:"crownJewel,omitempty"`
	Segment    string `json:"segment,omitempty"`
	HighValue  bool   `json:"highValue,omitempty"`
}
```
Replace with:
```go
type AssetIdentity struct {
	HostKey    string `json:"hostKey"`
	Label      string `json:"label"`
	Managed    bool   `json:"managed"`
	AgentID    string `json:"agentId,omitempty"`
	OS         string `json:"os,omitempty"`
	IP         string `json:"ip,omitempty"`
	CrownJewel string `json:"crownJewel,omitempty"`
	Segment    string `json:"segment,omitempty"`
	HighValue  bool   `json:"highValue,omitempty"`

	// SP6 asset criticality.
	CriticalityTier string   `json:"criticalityTier,omitempty"`
	InternetFacing  bool     `json:"internetFacing,omitempty"`
	IdentityExposed bool     `json:"identityExposed,omitempty"`
	Production      bool     `json:"production,omitempty"`
	ComplianceScope []string `json:"complianceScope,omitempty"`
}
```

Find `ScoreBreakdown`:
```go
type ScoreBreakdown struct {
	ExposureScore          int `json:"exposureScore"`
	AttackPathScore        int `json:"attackPathScore"`
	DetectionCoverageScore int `json:"detectionCoverageScore"`
	VulnerabilityScore     int `json:"vulnerabilityScore"`
}
```
Replace with:
```go
type ScoreBreakdown struct {
	ExposureScore          int `json:"exposureScore"`
	AttackPathScore        int `json:"attackPathScore"`
	DetectionCoverageScore int `json:"detectionCoverageScore"`
	VulnerabilityScore     int `json:"vulnerabilityScore"`
	CriticalityRisk        int `json:"criticalityRisk"` // 0-100, higher = matters more (not inverted like the scores above)
}
```

Find `AssetSummary`:
```go
type AssetSummary struct {
	Asset                  AssetIdentity `json:"asset"`
	ExposureScore          int           `json:"exposureScore"`
	AttackPathScore        int           `json:"attackPathScore"`
	DetectionCoverageScore int           `json:"detectionCoverageScore"`
	WorstCVESeverity       float64       `json:"worstCveSeverity,omitempty"`
	KEVExposed             bool          `json:"kevExposed"`
	OpenFindingsCount      int           `json:"openFindingsCount"`
}
```
Replace with:
```go
type AssetSummary struct {
	Asset                  AssetIdentity `json:"asset"`
	ExposureScore          int           `json:"exposureScore"`
	AttackPathScore        int           `json:"attackPathScore"`
	DetectionCoverageScore int           `json:"detectionCoverageScore"`
	WorstCVESeverity       float64       `json:"worstCveSeverity,omitempty"`
	KEVExposed             bool          `json:"kevExposed"`
	OpenFindingsCount      int           `json:"openFindingsCount"`
	CriticalityTier        string        `json:"criticalityTier,omitempty"`
	CriticalityRisk        int           `json:"criticalityRisk"`
}
```

- [ ] **Step 6: Build and format**

Run: `cd orchestrator && gofmt -l internal/exposure/criticality.go internal/exposure/criticality_test.go internal/exposure/types.go && go build ./internal/exposure/...`
Expected: no gofmt output. Build WILL fail here — `build.go` doesn't populate the new struct fields yet. That's expected; Task 4 fixes it. Confirm the failure is specifically about unused-ness or missing wiring, not a syntax error in this task's files (a syntax error means Step 5's edits are wrong).

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/exposure/criticality.go orchestrator/internal/exposure/criticality_test.go orchestrator/internal/exposure/types.go
git commit -m "feat(sp6): CriticalityRisk scoring function + widened exposure types"
```

---

### Task 4: Wire criticality into `exposure.Build` and reweight `ExposureScore` (TDD)

**Files:**
- Modify: `orchestrator/internal/exposure/build.go`
- Modify: `orchestrator/internal/exposure/build_test.go`

**Interfaces:**
- Consumes: `CriticalityRisk(AssetCriticalityInputs) int` (Task 3), `Node.CriticalityTier/InternetFacing/IdentityExposed/Production/ComplianceScope` and `Node.Role==attackpath.RoleDC` (Task 2).
- Produces: `AssetExposureProfile.Scores.CriticalityRisk` and the reweighted `ExposureScore`, consumed by Task 5's API responses and the UI.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/exposure/build_test.go` (needs `"github.com/audspect/bas/internal/relationships"` — already imported in this file):
```go
// TestBuild_CriticalityTierRaisesExposureRisk isolates the new 4th term: two
// leaf hosts identical in every other respect (same distance from the entry
// point, same single SMB touching edge, zero CVEs) should differ ONLY in
// CriticalityRisk/ExposureScore once one is tagged critical.
func TestBuild_CriticalityTierRaisesExposureRisk(t *testing.T) {
	cols := []attackpath.Collection{
		{AgentID: "ws01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "WS01", Kind: attackpath.KindHost, Role: attackpath.RoleEndpoint}},
			Edges: []attackpath.Edge{
				{From: "WS01", To: "PLAIN01", Kind: attackpath.EdgeSMB},
				{From: "WS01", To: "CRIT01", Kind: attackpath.EdgeSMB},
			}},
		{AgentID: "plain01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "PLAIN01", Kind: attackpath.KindHost, Role: attackpath.RoleServer}}},
		{AgentID: "crit01", Source: "agent",
			Nodes: []attackpath.Node{{ID: "CRIT01", Kind: attackpath.KindHost, Role: attackpath.RoleServer, CriticalityTier: "critical"}}},
	}
	g, s := attackpath.BuildGraphAndAnalyze(cols, nil)
	paths := pathcorrelation.DefaultPaths(g, s)
	corr, err := pathcorrelation.Correlate(context.Background(), g, s, paths, pathcorrelation.DefaultEdgeTechniqueMapper{},
		nilRunLookup{}, nilRuleLibrary{})
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	ag, err := Build(context.Background(), g, s, corr,
		&fakeRelLookup{byTech: map[string][]relationships.Relationship{}}, &fakeEnricher{meta: map[string]CVEMeta{}}, nil, nil)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	plain, ok := ag.Profile("PLAIN01")
	if !ok {
		t.Fatalf("expected a profile for PLAIN01")
	}
	crit, ok := ag.Profile("CRIT01")
	if !ok {
		t.Fatalf("expected a profile for CRIT01")
	}
	if crit.Scores.CriticalityRisk <= plain.Scores.CriticalityRisk {
		t.Fatalf("CRIT01 (tier=critical) should have higher CriticalityRisk than untagged PLAIN01: crit=%d plain=%d",
			crit.Scores.CriticalityRisk, plain.Scores.CriticalityRisk)
	}
	if crit.Scores.ExposureScore >= plain.Scores.ExposureScore {
		t.Fatalf("with identical attack-path/detection/vulnerability posture, the critical-tagged asset should score lower (more exposed): crit=%d plain=%d",
			crit.Scores.ExposureScore, plain.Scores.ExposureScore)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/exposure/... -run TestBuild_CriticalityTierRaisesExposureRisk -v`
Expected: FAIL — `CriticalityRisk` stays 0 for both (build.go never sets it), so the first assertion fails.

- [ ] **Step 3: Read the Node's criticality fields and track domain-controller status**

In `orchestrator/internal/exposure/build.go`, find:
```go
		if p.asset.nodeID != "" {
			if n, ok := g.Node(p.asset.nodeID); ok {
				profile.Asset.Label = n.Label
				profile.Asset.CrownJewel = n.CrownJewel
				profile.Asset.Segment = n.Segment
				profile.Asset.HighValue = n.HighValue
			}
		}
```
Replace with:
```go
		isDC := false
		if p.asset.nodeID != "" {
			if n, ok := g.Node(p.asset.nodeID); ok {
				profile.Asset.Label = n.Label
				profile.Asset.CrownJewel = n.CrownJewel
				profile.Asset.Segment = n.Segment
				profile.Asset.HighValue = n.HighValue
				profile.Asset.CriticalityTier = n.CriticalityTier
				profile.Asset.InternetFacing = n.InternetFacing
				profile.Asset.IdentityExposed = n.IdentityExposed
				profile.Asset.Production = n.Production
				profile.Asset.ComplianceScope = n.ComplianceScope
				isDC = n.Role == attackpath.RoleDC
			}
		}
```

- [ ] **Step 4: Compute `CriticalityRisk` and reweight the formula**

In the same file, find:
```go
		attackPathScore := clamp100(100 - int(p.apRisk+0.5))
		detectionScore := clamp100(100 - int(p.detRisk+0.5))
		vulnScore := clamp100(100 - int(worst+0.5))
		exposureRisk := 0.40*p.apRisk + 0.35*p.detRisk + 0.25*worst
		exposureScore := clamp100(100 - int(exposureRisk+0.5))
		profile.Scores = ScoreBreakdown{
			ExposureScore:          exposureScore,
			AttackPathScore:        attackPathScore,
			DetectionCoverageScore: detectionScore,
			VulnerabilityScore:     vulnScore,
		}
```
Replace with:
```go
		critRisk := float64(CriticalityRisk(AssetCriticalityInputs{
			CriticalityTier:    profile.Asset.CriticalityTier,
			InternetFacing:     profile.Asset.InternetFacing,
			IdentityExposed:    profile.Asset.IdentityExposed,
			Production:         profile.Asset.Production,
			ComplianceScope:    profile.Asset.ComplianceScope,
			IsDomainController: isDC,
			ThreatGroupCount:   len(profile.ThreatIntel),
		}))

		attackPathScore := clamp100(100 - int(p.apRisk+0.5))
		detectionScore := clamp100(100 - int(p.detRisk+0.5))
		vulnScore := clamp100(100 - int(worst+0.5))
		// SP6: criticality is a 4th weighted term, reweighted from
		// .40/.35/.25 — see docs/superpowers/specs/2026-07-17-sp6-asset-criticality-design.md
		// and ADR-009 for why (accepted trade-off: a well-defended critical
		// asset still costs up to 20 points, by design).
		exposureRisk := 0.30*p.apRisk + 0.30*p.detRisk + 0.20*worst + 0.20*critRisk
		exposureScore := clamp100(100 - int(exposureRisk+0.5))
		profile.Scores = ScoreBreakdown{
			ExposureScore:          exposureScore,
			AttackPathScore:        attackPathScore,
			DetectionCoverageScore: detectionScore,
			VulnerabilityScore:     vulnScore,
			CriticalityRisk:        int(critRisk),
		}
```

- [ ] **Step 5: Propagate into `AssetSummary`**

In `Summaries()`, find:
```go
		out = append(out, AssetSummary{
			Asset:                  p.Asset,
			ExposureScore:          p.Scores.ExposureScore,
			AttackPathScore:        p.Scores.AttackPathScore,
			DetectionCoverageScore: p.Scores.DetectionCoverageScore,
			WorstCVESeverity:       worst,
			KEVExposed:             kev,
			OpenFindingsCount:      p.Findings.OpenCount,
		})
```
Replace with:
```go
		out = append(out, AssetSummary{
			Asset:                  p.Asset,
			ExposureScore:          p.Scores.ExposureScore,
			AttackPathScore:        p.Scores.AttackPathScore,
			DetectionCoverageScore: p.Scores.DetectionCoverageScore,
			WorstCVESeverity:       worst,
			KEVExposed:             kev,
			OpenFindingsCount:      p.Findings.OpenCount,
			CriticalityTier:        p.Asset.CriticalityTier,
			CriticalityRisk:        p.Scores.CriticalityRisk,
		})
```

- [ ] **Step 6: Run the new test to verify it passes**

Run: `cd orchestrator && go test ./internal/exposure/... -run TestBuild_CriticalityTierRaisesExposureRisk -v`
Expected: PASS.

- [ ] **Step 7: Run the full package and fix the pre-existing threshold test**

Run: `cd orchestrator && go test ./internal/exposure/... -v`

`TestBuild_HostOnDAPath_LowExposureScore` (in `build_test.go`) asserts `profile.Scores.ExposureScore >= 50` as a FAIL condition. The reweight (AttackPathRisk's weight drops from .40 to .30) very likely pushes this specific untagged fixture's score to ~51-52, flipping that assertion. This is the exact re-validation cost the spec and ADR-009 called out — fix it, don't weaken its intent:

1. If this test now FAILs, read the actual `ExposureScore` value from the test failure output (e.g., `got %d`).
2. In `build_test.go`, change the literal `50` in `if profile.Scores.ExposureScore >= 50 {` to that observed value **plus 1** (so the test still asserts "the score is at or below what we just measured," preserving a real low-exposure check against the new formula, not silently disabling it).
3. If the test still PASSes unchanged, leave it as-is — do not modify a passing test.

- [ ] **Step 8: Run the full package again to confirm everything is green**

Run: `cd orchestrator && go test ./internal/exposure/... -v`
Expected: PASS, every test in the package (including whichever numeric literal you may have adjusted in Step 7).

- [ ] **Step 9: Build, vet, format**

Run: `cd orchestrator && gofmt -l internal/exposure/build.go internal/exposure/build_test.go && go build ./... && go vet ./internal/exposure/...`
Expected: no gofmt output, `go build ./...` succeeds for the whole module (confirms nothing downstream broke), vet clean.

- [ ] **Step 10: Commit**

```bash
git add orchestrator/internal/exposure/build.go orchestrator/internal/exposure/build_test.go
git commit -m "feat(sp6): wire CriticalityRisk into exposure.Build, reweight ExposureScore"
```

---

### Task 5: API — widen asset-tag endpoints (TDD)

**Files:**
- Modify: `orchestrator/internal/api/attackpath_handlers.go` (`loadAssetTags`, `GetAttackPathAssets`, `SetAttackPathAsset`)
- Modify: `orchestrator/internal/api/attackpath_assets_test.go`

**Interfaces:**
- Consumes: `attackpath.AssetTag`'s widened fields (Task 2), `attackpath_asset_tags`'s widened columns (Task 1).
- Produces: `GET /api/attackpath/assets` / `POST /api/attackpath/assets` now round-trip the 5 new fields.

- [ ] **Step 1: Write the failing test**

Append to `orchestrator/internal/api/attackpath_assets_test.go`:
```go
// TestSetAttackPathAsset_CriticalityFieldsRoundTrip pins that the 5 new SP6
// fields persist and come back through GetAttackPathAssets, and that
// clearing now requires ALL 8 fields empty — clearing only the legacy 3
// must NOT delete a row that still carries a criticality tag.
func TestSetAttackPathAsset_CriticalityFieldsRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := attackpathHandler(t, pool)
		setRec := httptest.NewRecorder()
		h.SetAttackPathAsset(setRec, assetTagReq(attackpath.AssetTag{
			HostKey: "dc01.corp.local", CriticalityTier: "critical", InternetFacing: true,
			IdentityExposed: true, Production: true, ComplianceScope: []string{"SEBI-CSCRF", "PCI-DSS"},
		}))
		if setRec.Code != http.StatusOK {
			t.Fatalf("set: status = %d, body = %s", setRec.Code, setRec.Body.String())
		}

		getRec := httptest.NewRecorder()
		h.GetAttackPathAssets(getRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			Assets []attackpath.AssetTag `json:"assets"`
		}
		json.Unmarshal(getRec.Body.Bytes(), &out)
		var got attackpath.AssetTag
		for _, a := range out.Assets {
			if a.HostKey == "DC01" {
				got = a
			}
		}
		if got.CriticalityTier != "critical" || !got.InternetFacing || !got.IdentityExposed || !got.Production {
			t.Fatalf("criticality fields did not round-trip: %+v", got)
		}
		if len(got.ComplianceScope) != 2 {
			t.Fatalf("compliance scope did not round-trip: %+v", got.ComplianceScope)
		}

		// Clearing only the legacy fields (CrownJewel/Segment/HighValue all
		// empty/false) must NOT delete the row — CriticalityTier is still set.
		clearAttemptRec := httptest.NewRecorder()
		h.SetAttackPathAsset(clearAttemptRec, assetTagReq(attackpath.AssetTag{
			HostKey: "dc01.corp.local", CriticalityTier: "critical",
		}))
		var n int
		pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM attackpath_asset_tags WHERE host_key='DC01'`).Scan(&n)
		if n != 1 {
			t.Fatalf("row should survive when a criticality field is still set, found %d rows", n)
		}

		// Clearing every field (all 8) deletes it.
		clearRec := httptest.NewRecorder()
		h.SetAttackPathAsset(clearRec, assetTagReq(attackpath.AssetTag{HostKey: "dc01.corp.local"}))
		var out2 map[string]any
		json.Unmarshal(clearRec.Body.Bytes(), &out2)
		if out2["cleared"] != true {
			t.Fatalf("out = %+v, want cleared:true", out2)
		}
	})
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd orchestrator && go test ./internal/api/... -run TestSetAttackPathAsset_CriticalityFieldsRoundTrip -v`
Expected: FAIL (compile succeeds since `AssetTag` already has the fields from Task 2, but the API doesn't read/write the new columns yet — the round-trip assertion fails). **This test needs Docker** (real Postgres via `sharedDB.RunWithPool`) — if Docker isn't available in this environment, note that explicitly rather than claiming it ran; it will need verification wherever Docker is available (same constraint the Splunk/QRadar/CrowdStrike connector work hit earlier this project).

- [ ] **Step 3: Widen `loadAssetTags`**

In `orchestrator/internal/api/attackpath_handlers.go`, find:
```go
func (h *Handler) loadAssetTags(r *http.Request) []attackpath.AssetTag {
	rows, err := h.db.Query(r.Context(),
		`SELECT host_key, label, crown_jewel, segment, high_value FROM attackpath_asset_tags`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var tags []attackpath.AssetTag
	for rows.Next() {
		var t attackpath.AssetTag
		if rows.Scan(&t.HostKey, &t.Label, &t.CrownJewel, &t.Segment, &t.HighValue) == nil {
			tags = append(tags, t)
		}
	}
	return tags
}
```
Replace with:
```go
func (h *Handler) loadAssetTags(r *http.Request) []attackpath.AssetTag {
	rows, err := h.db.Query(r.Context(),
		`SELECT host_key, label, crown_jewel, segment, high_value,
		        criticality_tier, internet_facing, identity_exposed, production, compliance_scope
		   FROM attackpath_asset_tags`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var tags []attackpath.AssetTag
	for rows.Next() {
		var t attackpath.AssetTag
		if rows.Scan(&t.HostKey, &t.Label, &t.CrownJewel, &t.Segment, &t.HighValue,
			&t.CriticalityTier, &t.InternetFacing, &t.IdentityExposed, &t.Production, &t.ComplianceScope) == nil {
			tags = append(tags, t)
		}
	}
	return tags
}
```

- [ ] **Step 4: Widen the `GetAttackPathAssets` overlay**

Find:
```go
	for i := range inv {
		if t, ok := idx[attackpath.NormalizeHostKey(inv[i].HostKey)]; ok {
			inv[i].CrownJewel = t.CrownJewel
			inv[i].Segment = t.Segment
			inv[i].HighValue = t.HighValue
		}
	}
```
Replace with:
```go
	for i := range inv {
		if t, ok := idx[attackpath.NormalizeHostKey(inv[i].HostKey)]; ok {
			inv[i].CrownJewel = t.CrownJewel
			inv[i].Segment = t.Segment
			inv[i].HighValue = t.HighValue
			inv[i].CriticalityTier = t.CriticalityTier
			inv[i].InternetFacing = t.InternetFacing
			inv[i].IdentityExposed = t.IdentityExposed
			inv[i].Production = t.Production
			inv[i].ComplianceScope = t.ComplianceScope
		}
	}
```

- [ ] **Step 5: Widen `SetAttackPathAsset`**

Find the whole function:
```go
func (h *Handler) SetAttackPathAsset(w http.ResponseWriter, r *http.Request) {
	var t attackpath.AssetTag
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		jsonError(w, "invalid asset tag payload", http.StatusBadRequest)
		return
	}
	key := attackpath.NormalizeHostKey(t.HostKey)
	if key == "" {
		jsonError(w, "hostKey is required", http.StatusBadRequest)
		return
	}
	// An empty tag clears the assignment.
	if t.CrownJewel == "" && t.Segment == "" && !t.HighValue {
		if _, err := h.db.Exec(r.Context(), `DELETE FROM attackpath_asset_tags WHERE host_key=$1`, key); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.auditLog(r, "attackpath.asset_tag", key, map[string]any{"action": "clear"}, "ok")
		respond(w, map[string]any{"hostKey": key, "cleared": true})
		return
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO attackpath_asset_tags (host_key, label, crown_jewel, segment, high_value, updated_at)
		 VALUES ($1,$2,$3,$4,$5,NOW())
		 ON CONFLICT (host_key) DO UPDATE
		   SET label=EXCLUDED.label, crown_jewel=EXCLUDED.crown_jewel,
		       segment=EXCLUDED.segment, high_value=EXCLUDED.high_value, updated_at=NOW()`,
		key, t.Label, t.CrownJewel, t.Segment, t.HighValue); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "attackpath.asset_tag", key, map[string]any{"crownJewel": t.CrownJewel, "segment": t.Segment, "highValue": t.HighValue, "label": t.Label}, "ok")
	respond(w, map[string]any{"hostKey": key, "crownJewel": t.CrownJewel, "segment": t.Segment, "highValue": t.HighValue})
}
```
Replace with:
```go
func (h *Handler) SetAttackPathAsset(w http.ResponseWriter, r *http.Request) {
	var t attackpath.AssetTag
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		jsonError(w, "invalid asset tag payload", http.StatusBadRequest)
		return
	}
	key := attackpath.NormalizeHostKey(t.HostKey)
	if key == "" {
		jsonError(w, "hostKey is required", http.StatusBadRequest)
		return
	}
	// An empty tag clears the assignment — now checks all 8 tag fields, not
	// just the 3 legacy ones, so clearing crown-jewel/segment/high-value
	// alone doesn't orphan a criticality tag still set on the same row.
	if t.CrownJewel == "" && t.Segment == "" && !t.HighValue &&
		t.CriticalityTier == "" && !t.InternetFacing && !t.IdentityExposed && !t.Production && len(t.ComplianceScope) == 0 {
		if _, err := h.db.Exec(r.Context(), `DELETE FROM attackpath_asset_tags WHERE host_key=$1`, key); err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.auditLog(r, "attackpath.asset_tag", key, map[string]any{"action": "clear"}, "ok")
		respond(w, map[string]any{"hostKey": key, "cleared": true})
		return
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO attackpath_asset_tags
		   (host_key, label, crown_jewel, segment, high_value,
		    criticality_tier, internet_facing, identity_exposed, production, compliance_scope, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
		 ON CONFLICT (host_key) DO UPDATE
		   SET label=EXCLUDED.label, crown_jewel=EXCLUDED.crown_jewel,
		       segment=EXCLUDED.segment, high_value=EXCLUDED.high_value,
		       criticality_tier=EXCLUDED.criticality_tier, internet_facing=EXCLUDED.internet_facing,
		       identity_exposed=EXCLUDED.identity_exposed, production=EXCLUDED.production,
		       compliance_scope=EXCLUDED.compliance_scope, updated_at=NOW()`,
		key, t.Label, t.CrownJewel, t.Segment, t.HighValue,
		t.CriticalityTier, t.InternetFacing, t.IdentityExposed, t.Production, t.ComplianceScope); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "attackpath.asset_tag", key, map[string]any{
		"crownJewel": t.CrownJewel, "segment": t.Segment, "highValue": t.HighValue,
		"criticalityTier": t.CriticalityTier, "label": t.Label,
	}, "ok")
	respond(w, map[string]any{
		"hostKey": key, "crownJewel": t.CrownJewel, "segment": t.Segment, "highValue": t.HighValue,
		"criticalityTier": t.CriticalityTier, "internetFacing": t.InternetFacing,
		"identityExposed": t.IdentityExposed, "production": t.Production, "complianceScope": t.ComplianceScope,
	})
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd orchestrator && go test ./internal/api/... -run "TestSetAttackPathAsset_CriticalityFieldsRoundTrip|TestGetAttackPathAssets|TestSetAttackPathAsset" -v`
Expected: PASS (all asset-tag tests, old and new) if Docker is available; if not, this is a known environment gap — say so explicitly, don't claim it passed.

- [ ] **Step 7: Build, vet, format**

Run: `cd orchestrator && gofmt -l internal/api/attackpath_handlers.go internal/api/attackpath_assets_test.go && go build ./... && go vet ./internal/api/...`
Expected: no gofmt output, build/vet clean.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/api/attackpath_handlers.go orchestrator/internal/api/attackpath_assets_test.go
git commit -m "feat(sp6): widen asset-tag API with criticality fields"
```

---

### Task 6: UI — widen the asset-tagging panel

**Files:**
- Modify: `orchestrator/wwwroot/index.html` (table header ~line 2410, `renderAPAssets`/`saveAPAsset` ~line 4934-4965, audit-log detail renderer ~line 11300)
- Modify: `orchestrator/cmd/server/wwwroot/index.html` — **hardlinked to the file above; editing one edits both on disk (same inode), but git tracks them as two paths, so both must be staged and committed.**

**Interfaces:**
- Consumes: `GET /api/attackpath/assets` response shape (Task 5) — `crownJewel`, `segment`, `highValue`, `criticalityTier`, `internetFacing`, `identityExposed`, `production`, `complianceScope`.

- [ ] **Step 1: Widen the table header and empty/loading states**

Find:
```html
                <thead><tr><th>Host</th><th>Crown-Jewel Tag</th><th>Segment</th><th style="text-align:center">Tier-0</th><th></th></tr></thead>
                <tbody id="ap-assets-body"><tr><td colspan="5" class="empty">Loading…</td></tr></tbody>
```
Replace with:
```html
                <thead><tr><th>Host</th><th>Crown-Jewel Tag</th><th>Segment</th><th style="text-align:center">Tier-0</th><th>Criticality</th><th>Flags</th><th></th></tr></thead>
                <tbody id="ap-assets-body"><tr><td colspan="7" class="empty">Loading…</td></tr></tbody>
```

- [ ] **Step 2: Widen `renderAPAssets` and `saveAPAsset`**

Find:
```javascript
function renderAPAssets() {
  var tb = document.getElementById('ap-assets-body');
  if (!AP_ASSETS.length) {
    tb.innerHTML = '<tr><td colspan="5" class="empty">No hosts discovered yet — run a collection first.</td></tr>';
    return;
  }
  tb.innerHTML = AP_ASSETS.map(function(a, i) {
    return '<tr>' +
      '<td style="font-family:var(--font-mono);font-size:0.76rem">' + x(a.label || a.hostKey) +
        (a.label && a.label.toUpperCase() !== (a.hostKey || '').toUpperCase() ? '<div class="tiny muted">' + x(a.hostKey) + '</div>' : '') + '</td>' +
      '<td><input id="apt-cj-' + i + '" value="' + x(a.crownJewel || '') + '" placeholder="e.g. ERP, FileServer" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td><input id="apt-seg-' + i + '" value="' + x(a.segment || '') + '" placeholder="e.g. server-vlan" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td style="text-align:center"><input type="checkbox" id="apt-hv-' + i + '"' + (a.highValue ? ' checked' : '') + '></td>' +
      '<td><button class="btn btn-outline btn-sm" onclick="saveAPAsset(' + i + ')">Save</button></td>' +
    '</tr>';
  }).join('');
}
function saveAPAsset(i) {
  var a = AP_ASSETS[i];
  if (!a) return;
  var payload = {
    hostKey: a.hostKey, label: a.label || '',
    crownJewel: document.getElementById('apt-cj-' + i).value.trim(),
    segment: document.getElementById('apt-seg-' + i).value.trim(),
    highValue: document.getElementById('apt-hv-' + i).checked
  };
  apicall('/api/attackpath/assets', { method: 'POST', body: JSON.stringify(payload) }).then(function() {
    a.crownJewel = payload.crownJewel; a.segment = payload.segment; a.highValue = payload.highValue;
    showToast('Saved ' + (a.label || a.hostKey), 'ok');
    loadAttackPath();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```
Replace with:
```javascript
var AP_CRIT_TIERS = ['', 'low', 'medium', 'high', 'critical'];
function renderAPAssets() {
  var tb = document.getElementById('ap-assets-body');
  if (!AP_ASSETS.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">No hosts discovered yet — run a collection first.</td></tr>';
    return;
  }
  tb.innerHTML = AP_ASSETS.map(function(a, i) {
    var tierOpts = AP_CRIT_TIERS.map(function(t) {
      return '<option value="' + t + '"' + (a.criticalityTier === t ? ' selected' : '') + '>' + (t || '—') + '</option>';
    }).join('');
    return '<tr>' +
      '<td style="font-family:var(--font-mono);font-size:0.76rem">' + x(a.label || a.hostKey) +
        (a.label && a.label.toUpperCase() !== (a.hostKey || '').toUpperCase() ? '<div class="tiny muted">' + x(a.hostKey) + '</div>' : '') + '</td>' +
      '<td><input id="apt-cj-' + i + '" value="' + x(a.crownJewel || '') + '" placeholder="e.g. ERP, FileServer" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td><input id="apt-seg-' + i + '" value="' + x(a.segment || '') + '" placeholder="e.g. server-vlan" style="' + AP_INPUT_STYLE + '"></td>' +
      '<td style="text-align:center"><input type="checkbox" id="apt-hv-' + i + '"' + (a.highValue ? ' checked' : '') + '></td>' +
      '<td><select id="apt-crit-' + i + '" style="' + AP_INPUT_STYLE + '">' + tierOpts + '</select></td>' +
      '<td style="font-size:0.72rem;white-space:nowrap">' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-if-' + i + '"' + (a.internetFacing ? ' checked' : '') + '> Internet</label>' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-ie-' + i + '"' + (a.identityExposed ? ' checked' : '') + '> Identity</label>' +
        '<label style="margin-right:0.4rem"><input type="checkbox" id="apt-prod-' + i + '"' + (a.production ? ' checked' : '') + '> Prod</label>' +
        '<input id="apt-cs-' + i + '" value="' + x((a.complianceScope || []).join(', ')) + '" placeholder="compliance scope, comma-sep" style="' + AP_INPUT_STYLE + ';margin-top:0.2rem;display:block;width:160px">' +
      '</td>' +
      '<td><button class="btn btn-outline btn-sm" onclick="saveAPAsset(' + i + ')">Save</button></td>' +
    '</tr>';
  }).join('');
}
function saveAPAsset(i) {
  var a = AP_ASSETS[i];
  if (!a) return;
  var cs = document.getElementById('apt-cs-' + i).value.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
  var payload = {
    hostKey: a.hostKey, label: a.label || '',
    crownJewel: document.getElementById('apt-cj-' + i).value.trim(),
    segment: document.getElementById('apt-seg-' + i).value.trim(),
    highValue: document.getElementById('apt-hv-' + i).checked,
    criticalityTier: document.getElementById('apt-crit-' + i).value,
    internetFacing: document.getElementById('apt-if-' + i).checked,
    identityExposed: document.getElementById('apt-ie-' + i).checked,
    production: document.getElementById('apt-prod-' + i).checked,
    complianceScope: cs
  };
  apicall('/api/attackpath/assets', { method: 'POST', body: JSON.stringify(payload) }).then(function() {
    a.crownJewel = payload.crownJewel; a.segment = payload.segment; a.highValue = payload.highValue;
    a.criticalityTier = payload.criticalityTier; a.internetFacing = payload.internetFacing;
    a.identityExposed = payload.identityExposed; a.production = payload.production; a.complianceScope = payload.complianceScope;
    showToast('Saved ' + (a.label || a.hostKey), 'ok');
    loadAttackPath();
  }).catch(function(e) { showToast(e.message, 'err'); });
}
```

- [ ] **Step 3: Show criticality in the audit-log detail renderer**

Find:
```javascript
          if (d2.crownJewel) parts.push('crown-jewel: ' + d2.crownJewel);
          if (d2.highValue) parts.push('high-value');
```
Replace with:
```javascript
          if (d2.crownJewel) parts.push('crown-jewel: ' + d2.crownJewel);
          if (d2.highValue) parts.push('high-value');
          if (d2.criticalityTier) parts.push('criticality: ' + d2.criticalityTier);
```

- [ ] **Step 4: Update the panel's description line**

Find:
```html
            <div class="tiny muted" style="margin-bottom:0.75rem">Tag the high-value assets the collectors can't infer. A crown-jewel tag makes a host show up in crown-jewel exposure and scoring; tier-0 marks a custom domain-compromise target. Tags follow the host across reachability and SharpHound identities.</div>
```
Replace with:
```html
            <div class="tiny muted" style="margin-bottom:0.75rem">Tag the high-value assets the collectors can't infer. A crown-jewel tag makes a host show up in crown-jewel exposure and scoring; tier-0 marks a custom domain-compromise target. Criticality/Flags feed the Exposure Explorer's risk score — see the Exposure Explorer tab. Tags follow the host across reachability and SharpHound identities.</div>
```

- [ ] **Step 5: Verify both hardlinked paths changed identically**

Run: `cd orchestrator && diff wwwroot/index.html cmd/server/wwwroot/index.html`
Expected: no output (files byte-identical — confirms the hardlink is intact and both paths reflect the edit).

Run a Node syntax check on every inline `<script>` block (same check used for the SP5 UI change earlier this project):
```bash
node -e "
const fs = require('fs');
const html = fs.readFileSync('wwwroot/index.html', 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
let ok = true;
scripts.forEach((s, i) => {
  try { new Function(s); } catch (e) { ok = false; console.log('Script block', i, 'error:', e.message); }
});
console.log(ok ? 'all inline script blocks parse OK' : 'SYNTAX ERROR FOUND');
"
```
Expected: `all inline script blocks parse OK`.

- [ ] **Step 6: Commit both paths**

```bash
git add orchestrator/wwwroot/index.html orchestrator/cmd/server/wwwroot/index.html
git commit -m "feat(sp6): widen asset-tagging UI with criticality fields"
```

---

### Task 7: Full validation + vault capture

**Files:**
- Modify (vault, outside git repo): `04 Features/Asset Criticality.md`, `04 Features/Exposure Explorer.md`, `11 Roadmaps/Roadmap.md`, `13 Daily Notes/<today>.md`, `20 Decisions/Decision Log.md`

- [ ] **Step 1: Full-module validation**

Run, in order:
```bash
cd orchestrator
gofmt -l internal/db/postgres.go internal/attackpath/graph.go internal/attackpath/assets.go internal/attackpath/assets_test.go internal/exposure/criticality.go internal/exposure/criticality_test.go internal/exposure/types.go internal/exposure/build.go internal/exposure/build_test.go internal/api/attackpath_handlers.go internal/api/attackpath_assets_test.go
go build ./...
go vet ./...
go test ./internal/attackpath/... ./internal/exposure/... -v
```
Expected: no gofmt output; build/vet clean; both test packages fully PASS. (`internal/api`'s new test needs Docker — run it wherever Docker is available and report the real result, don't assume.)

- [ ] **Step 2: Vault capture**

- `04 Features/Asset Criticality.md`: `status: planned` → `status: done`, `lifecycle: approved` → `lifecycle: implemented`, bump `version` and `last_updated`; move the "Implementation not started" open issue to done, list the commits from Tasks 1-6.
- `04 Features/Exposure Explorer.md`: note the formula is now `.30/.30/.20/.20` with the 4th term, not the original `.40/.35/.25` in its own "Implementation Status" section (that section currently documents the original SP4 formula verbatim — it's now stale).
- `11 Roadmaps/Roadmap.md`: move SP6 from "planned, spec approved" to done; unblock Phase 6 as the new "next in sequence" head (still unscoped).
- `20 Decisions/Decision Log.md`: no new row needed — the 3 rows already added when the spec was written cover this; ADR-009 already exists.
- Daily note: log the implementation session, commit hashes, and the actual `TestBuild_HostOnDAPath_LowExposureScore` threshold value observed in Task 4 Step 7 (worth recording — it's a concrete data point about how much the reweight moved real scores).

- [ ] **Step 3: Push**

```bash
git push
```

- [ ] **Step 4: Manual verification recommended (not performed this session unless a browser tool is available)**

Load the Attack Path tab → Asset Tagging panel, confirm the widened table renders and Save round-trips a criticality tag; load Exposure Explorer, confirm an asset tagged critical shows a lower `ExposureScore` than an otherwise-identical untagged asset. Flag as a known gap in the daily note if not performed, same convention as SP4/OpenAEV.
