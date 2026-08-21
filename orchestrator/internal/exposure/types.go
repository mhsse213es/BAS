// Package exposure is the SP4 Exposure Explorer: an asset-centric aggregator
// over the attack-path graph (internal/attackpath), detection coverage
// (internal/pathcorrelation), the CVE Relationship Store
// (internal/relationships), and ATT&CK threat-intel enrichment
// (internal/reporting/attackdata). It is a pure consumer — it owns no DB
// tables and never modifies any of those subsystems' own state.
package exposure

import (
	"context"

	"github.com/audspect/bas/internal/pathcorrelation"
	"github.com/audspect/bas/internal/relationships"
)

// AssetIdentity is who/what this asset is.
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

// ScoreBreakdown — all fields 0-100, higher = safer. AttackPathScore and
// DetectionCoverageScore here are ASSET-SCOPED derived values computed by
// this package (see riskscore.go), NOT the fleet-wide numbers from
// attackpath.Summary / pathcorrelation.AttackPathCorrelation.
type ScoreBreakdown struct {
	ExposureScore          int `json:"exposureScore"`
	AttackPathScore        int `json:"attackPathScore"`
	DetectionCoverageScore int `json:"detectionCoverageScore"`
	VulnerabilityScore     int `json:"vulnerabilityScore"`
	CriticalityRisk        int `json:"criticalityRisk"` // 0-100, higher = matters more (not inverted like the scores above)

	// Every score above is a pure-deficit model (100 - risk), so an asset
	// about which NOTHING has been collected scores a flawless 100 across
	// the board -- no data means no deficit means "perfect". That is the
	// most dangerous possible default on a security dashboard labelled
	// "higher is safer", so each score carries an explicit measurability
	// flag. False means "not collected / nothing to measure", NOT "safe":
	// consumers must render it as unknown and must exclude it from any
	// aggregate (see internal/endpointrisk.ComputeHealth, which drops
	// uncollected categories from HealthScore rather than averaging in a
	// fabricated 100).
	AttackPathMeasurable    bool `json:"attackPathMeasurable"`
	DetectionMeasurable     bool `json:"detectionMeasurable"`
	VulnerabilityMeasurable bool `json:"vulnerabilityMeasurable"`
	ExposureMeasurable      bool `json:"exposureMeasurable"`
}

// AttackPathContext is this asset's position in the attack-path graph.
// DistanceToNearestCrownJewel is -1 when no crown jewel is reachable FROM
// this asset (distinct from 0, which means this asset IS a crown jewel).
type AttackPathContext struct {
	Reachable                   bool    `json:"reachable"`
	OnShortestDAPath            bool    `json:"onShortestDaPath"`
	DistanceToNearestCrownJewel int     `json:"distanceToNearestCrownJewel"`
	IsChokePoint                bool    `json:"isChokePoint"`
	ChokePointCoverage          float64 `json:"chokePointCoverage,omitempty"`
}

// DetectionContext is the subset of SP3's annotated edges that touch this
// asset (From or To), plus a count rollup.
type DetectionContext struct {
	Edges   []pathcorrelation.AnnotatedEdge `json:"edges"`
	Covered int                             `json:"covered"`
	Partial int                             `json:"partial"`
	Gap     int                             `json:"gap"`
	Unknown int                             `json:"unknown"`
}

// CVEExposure is one CVE reached via an Active, High/Medium-confidence
// technique-CVE relationship for a technique threatening this asset.
type CVEExposure struct {
	CVEID       string  `json:"cveId"`
	CVSS        float64 `json:"cvss,omitempty"`
	KEV         bool    `json:"kev"`
	EPSSScore   float64 `json:"epssScore,omitempty"`
	TechniqueID string  `json:"techniqueId"`
	Severity    float64 `json:"severity"`
}

// FindingSummary is the API-facing projection of one open finding row.
// Deliberately NOT findings.FindingRef (that struct has no json tags and
// no finding ID).
type FindingSummary struct {
	ID            string `json:"id"`
	TechniqueID   string `json:"techniqueId"`
	TechniqueName string `json:"techniqueName"`
	Tactic        string `json:"tactic"`
	Severity      string `json:"severity"`
	ExposureState string `json:"exposureState"`
}

// FindingsContext is this asset's finding history. Collected is false for
// discovered-only (unmanaged) assets — an honest "not enrolled" state, never
// a fabricated empty list rendered as if it were a real zero.
type FindingsContext struct {
	Collected     bool             `json:"collected"`
	OpenCount     int              `json:"openCount"`
	CriticalCount int              `json:"criticalCount"`
	Findings      []FindingSummary `json:"findings,omitempty"`
}

// ThreatGroupExposure is one ATT&CK group attributed to one or more
// techniques threatening this asset.
type ThreatGroupExposure struct {
	GroupName    string   `json:"groupName"`
	TechniqueIDs []string `json:"techniqueIds"`
}

// AssetExposureProfile is the full per-asset detail payload.
type AssetExposureProfile struct {
	Asset           AssetIdentity                    `json:"asset"`
	Scores          ScoreBreakdown                   `json:"scores"`
	AttackPath      AttackPathContext                `json:"attackPath"`
	Detection       DetectionContext                 `json:"detection"`
	Vulnerabilities []CVEExposure                    `json:"vulnerabilities"`
	Findings        FindingsContext                  `json:"findings"`
	ThreatIntel     []ThreatGroupExposure            `json:"threatIntel"`
	Recommendations []pathcorrelation.PrioritizedGap `json:"recommendations"`
}

// AssetSummary is the lightweight index row for GET /api/exposure/assets.
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

// AgentRow is the minimal projection of the `agents` table Build needs to
// extend the asset union beyond the attack-path graph's own host nodes.
type AgentRow struct {
	AgentID  string
	Hostname string
	IP       string
	OS       string
}

// RelationshipLookup is the slice of the Relationship Store this package
// needs. *relationships.Store satisfies it directly; tests substitute a fake.
type RelationshipLookup interface {
	ForTechnique(ctx context.Context, techniqueID string) ([]relationships.Relationship, error)
}

// CVEMeta is CVSS/KEV/EPSS metadata for one CVE.
type CVEMeta struct {
	CVSS      float64
	KEV       bool
	EPSSScore float64
}

// CVEEnricher batch-resolves CVE IDs to CVSS/KEV/EPSS metadata. SQLCVEEnricher
// (sql.go) is the production implementation; tests use a fake.
type CVEEnricher interface {
	Enrich(ctx context.Context, cveIDs []string) (map[string]CVEMeta, error)
}

// FindingsLookup reads open findings, grouped by agent ID, in one batched
// call. SQLFindingsLookup (sql.go) is the production implementation; tests
// use a fake.
type FindingsLookup interface {
	AllOpenFindings(ctx context.Context) (map[string][]FindingSummary, error)
}
