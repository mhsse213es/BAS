package webgwefficacy

import (
	"fmt"
	"sort"
	"strings"
)

// IndustryProfile is pure configuration -- priorities, data
// classifications, and business-impact weighting layered onto this
// package's existing scenario library. It computes nothing and
// verifies nothing itself, and never gains a method returning a
// WebGWVerdict or VerdictDetail -- per the architecture spec's own
// explicit instruction, an industry profile is never a second scoring
// system. PrioritySummary and Describe are its two real readers
// today: PrioritySummary filters an existing CoverageReport down to
// this profile's priorities and renders their already-computed
// coverage status, followed by DataClassifications rendered as-is
// (never matched against evidence or used to infer data
// sensitivity); Describe renders Name and Note together as a plain
// human-readable line. Note is deliberately kept out of
// PrioritySummary -- it is free-text metadata, not a value meant for
// a structured summary -- which is exactly why Describe exists as a
// separate reader for it. Neither method computes a verdict of its
// own. Three production surfaces now call PrioritySummary and
// Describe through IndustryProfileNames/BuildIndustryProfile below:
// the cmd/webgwprofile CLI, the GET /api/webgw/industry-profiles JSON
// endpoint, and the GET /api/webgw/industry-profiles.html report --
// all three resolve profile names through the same registry, so none
// can drift from the others.
type IndustryProfile struct {
	Name                 string             `json:"name"`
	PriorityDomainIDs    []string           `json:"priorityDomainIds"`
	DataClassifications  []string           `json:"dataClassifications"`
	BusinessImpactWeight map[string]float64 `json:"businessImpactWeight"`
	Note                 string             `json:"note,omitempty"`
}

// NewIndustryProfile validates at construction time, never at render
// time: name must be non-empty; every domain ID this profile
// references -- in priorityDomainIDs and as businessImpactWeight keys
// -- must be one of Audspect's real, current WebGW domains per
// AudspectWebGWCoverageReport's own 12-domain set, never a fictional
// or stale reference; and every businessImpactWeight value must fall
// within [0, 1].
func NewIndustryProfile(
	name string,
	priorityDomainIDs []string,
	dataClassifications []string,
	businessImpactWeight map[string]float64,
	note string,
) (IndustryProfile, error) {
	if name == "" {
		return IndustryProfile{}, fmt.Errorf("name must not be empty")
	}
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		return IndustryProfile{}, fmt.Errorf("loading domain set: %w", err)
	}
	known := make(map[string]bool, len(report.domains))
	for _, d := range report.domains {
		known[d.DomainID] = true
	}
	for _, id := range priorityDomainIDs {
		if !known[id] {
			return IndustryProfile{}, fmt.Errorf("priority domain ID %q is not one of Audspect's real WebGW domains", id)
		}
	}
	for id, weight := range businessImpactWeight {
		if !known[id] {
			return IndustryProfile{}, fmt.Errorf("business-impact-weight domain ID %q is not one of Audspect's real WebGW domains", id)
		}
		if weight < 0 || weight > 1 {
			return IndustryProfile{}, fmt.Errorf("business-impact weight for domain %q is %v, want a value in [0, 1]", id, weight)
		}
	}
	return IndustryProfile{
		Name:                 name,
		PriorityDomainIDs:    priorityDomainIDs,
		DataClassifications:  dataClassifications,
		BusinessImpactWeight: businessImpactWeight,
		Note:                 note,
	}, nil
}

// BFSINBFCProfile returns the BFSI/NBFC industry profile. Financial
// data protection, strict configuration change control, and
// availability dominate; DLP (03), configuration drift (09), and
// availability/resilience (11) are prioritized -- matching
// RBI/CERT-In's own emphasis on data residency, encryption, and
// perimeter controls (see the real obligations mapped in
// regulatory_test.go).
func BFSINBFCProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"BFSI/NBFC",
		[]string{"03", "09", "11"},
		[]string{"PII", "financial-transaction-data", "payment-card-data"},
		map[string]float64{"03": 1.0, "09": 0.8, "11": 0.9},
		"Financial-sector priorities: data loss prevention, configuration-drift control, and availability dominate.",
	)
}

// HealthcareProfile returns the Healthcare industry profile.
// Patient-data protection dominates: TLS inspection of PHI in transit
// (02), DLP (03), and CASB/shadow-IT detection for unauthorized SaaS
// carrying patient data (06) are prioritized.
func HealthcareProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"Healthcare",
		[]string{"02", "03", "06"},
		[]string{"PHI", "PII"},
		map[string]float64{"02": 0.9, "03": 1.0, "06": 0.8},
		"Patient-data-protection priorities: TLS inspection of PHI in transit, DLP, and CASB dominate.",
	)
}

// ManufacturingOTProfile returns the Manufacturing/OT-adjacent
// industry profile. OT uptime dominates over confidentiality:
// availability/resilience (11), configuration drift (09), and
// egress-bypass control for unusual OT network patterns (08) are
// prioritized. This profile is configuration only, never a probe --
// the architecture spec's own safety contract already prohibits any
// active probing into OT-adjacent deployments without a
// separately-approved test design, and nothing in this profile
// initiates one.
func ManufacturingOTProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"Manufacturing/OT-adjacent",
		[]string{"11", "09", "08"},
		[]string{"OT-telemetry", "industrial-control-data"},
		map[string]float64{"11": 1.0, "09": 0.7, "08": 0.6},
		"OT-uptime priorities: availability/resilience dominates over confidentiality.",
	)
}

// MSPSharedTenantProfile returns the MSP/shared-tenant industry
// profile. Tenant isolation dominates: CASB/tenant-isolation (06),
// identity-scoped per-client policy differentiation (05), and
// cross-control chains (12, since each client relationship must be
// proven separately) are prioritized.
func MSPSharedTenantProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"MSP/shared-tenant",
		[]string{"06", "05", "12"},
		[]string{"multi-tenant-client-data"},
		map[string]float64{"06": 1.0, "05": 0.9, "12": 0.8},
		"Multi-tenant priorities: tenant isolation and per-client policy differentiation dominate.",
	)
}

// PrioritySummary filters an existing CoverageReport down to this
// profile's PriorityDomainIDs and renders each one's real
// CoverageStatus, ordered by BusinessImpactWeight descending (a
// priority domain with no assigned weight sorts last, at weight 0).
// It reads CoverageReport, never computes a verdict of its own --
// consistent with IndustryProfile never becoming a second scoring
// system. A priority domain absent from the given report is named
// explicitly, never silently dropped.
func (p IndustryProfile) PrioritySummary(report CoverageReport) string {
	if len(p.PriorityDomainIDs) == 0 {
		return fmt.Sprintf("%s: no priority domains defined%s", p.Name, p.dataClassificationSuffix())
	}

	byID := make(map[string]DomainCoverage, len(report.domains))
	for _, d := range report.domains {
		byID[d.DomainID] = d
	}

	ids := make([]string, len(p.PriorityDomainIDs))
	copy(ids, p.PriorityDomainIDs)
	sort.SliceStable(ids, func(i, j int) bool {
		return p.BusinessImpactWeight[ids[i]] > p.BusinessImpactWeight[ids[j]]
	})

	entries := make([]string, 0, len(ids))
	for _, id := range ids {
		d, ok := byID[id]
		if !ok {
			entries = append(entries, fmt.Sprintf("%s (%s): not present in this report", id, p.weightLabel(id)))
			continue
		}
		entries = append(entries, fmt.Sprintf("%s %s (%s): %s", d.DomainID, d.DomainName, p.weightLabel(id), d.Status))
	}
	return fmt.Sprintf("%s priorities: %s%s", p.Name, strings.Join(entries, "; "), p.dataClassificationSuffix())
}

// dataClassificationSuffix renders this profile's DataClassifications
// as-is, in their configured order, appended after the domain-priority
// list -- no classification matching or data-sensitivity inference,
// just the labels the profile was configured with. Empty when
// DataClassifications is nil or empty, so PrioritySummary's output is
// unchanged for any profile that doesn't set it.
func (p IndustryProfile) dataClassificationSuffix() string {
	if len(p.DataClassifications) == 0 {
		return ""
	}
	return "; data classifications: " + strings.Join(p.DataClassifications, ", ")
}

// Describe renders this profile's Name and Note together as a plain
// human-readable line -- "<Name>: <Note>" -- or just Name alone when
// Note is empty, never a dangling separator. Note is rendered as-is,
// never parsed or matched against anything; this is Note's one real
// reader, kept deliberately separate from PrioritySummary's terser,
// structured output.
func (p IndustryProfile) Describe() string {
	if p.Note == "" {
		return p.Name
	}
	return p.Name + ": " + p.Note
}

// weightLabel renders a priority domain's assigned BusinessImpactWeight,
// or "no weight assigned" when the domain has no entry -- distinct
// from a deliberate weight of exactly 0.0, which is itself a valid
// value per NewIndustryProfile's own [0, 1] bound.
func (p IndustryProfile) weightLabel(id string) string {
	w, ok := p.BusinessImpactWeight[id]
	if !ok {
		return "no weight assigned"
	}
	return fmt.Sprintf("weight %.1f", w)
}

// industryProfileConstructors is the single source of truth mapping
// each shipped industry profile's lookup key to its constructor -- a
// CLI, HTTP handler, or report renderer reads this via
// IndustryProfileNames/BuildIndustryProfile rather than maintaining
// its own, potentially drifting copy of this list.
var industryProfileConstructors = map[string]func() (IndustryProfile, error){
	"bfsi":             BFSINBFCProfile,
	"healthcare":       HealthcareProfile,
	"manufacturing-ot": ManufacturingOTProfile,
	"msp":              MSPSharedTenantProfile,
}

// IndustryProfileNames returns every shipped industry profile's
// lookup key, sorted.
func IndustryProfileNames() []string {
	names := make([]string, 0, len(industryProfileConstructors))
	for name := range industryProfileConstructors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BuildIndustryProfile resolves name to its built IndustryProfile.
// The second return value is false when name isn't one of
// IndustryProfileNames' keys -- distinct from a genuine construction
// error (a non-nil err), which none of the 4 shipped profiles produce
// today but is still surfaced rather than panicking.
func BuildIndustryProfile(name string) (IndustryProfile, bool, error) {
	ctor, ok := industryProfileConstructors[name]
	if !ok {
		return IndustryProfile{}, false, nil
	}
	profile, err := ctor()
	return profile, true, err
}
