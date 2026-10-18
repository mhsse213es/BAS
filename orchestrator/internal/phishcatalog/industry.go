package phishcatalog

import (
	"fmt"
	"sort"
	"strings"
)

// IndustryProfile mirrors internal/webgwefficacy.IndustryProfile's own
// pattern exactly, one layer over this package's PH-* scenario catalog
// instead of WebGW's domain set: pure configuration -- priorities, data
// classifications, business-impact weighting -- that computes nothing
// and verifies nothing itself. It never gains a method returning a
// phishval.Verdict, per the same explicit instruction webgwefficacy's
// own copy of this type carries: an industry profile is never a second
// scoring system. PrioritySummary and Describe are its two real
// readers, mirroring webgwefficacy's own.
type IndustryProfile struct {
	Name                 string
	PriorityScenarioIDs  []string
	DataClassifications  []string
	BusinessImpactWeight map[string]float64
	Note                 string
}

// NewIndustryProfile validates at construction time, never at render
// time: name must be non-empty, and every scenario ID this profile
// references -- in PriorityScenarioIDs and as BusinessImpactWeight keys
// -- must be one of AudspectPhishingCatalog's real, current PH-*
// scenario IDs, never a fictional or stale reference. Every
// BusinessImpactWeight value must fall within [0, 1].
func NewIndustryProfile(
	name string,
	priorityScenarioIDs []string,
	dataClassifications []string,
	businessImpactWeight map[string]float64,
	note string,
) (IndustryProfile, error) {
	if name == "" {
		return IndustryProfile{}, fmt.Errorf("name must not be empty")
	}
	scenarios, err := AudspectPhishingCatalog()
	if err != nil {
		return IndustryProfile{}, fmt.Errorf("loading scenario catalog: %w", err)
	}
	known := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		known[s.ID] = true
	}
	for _, id := range priorityScenarioIDs {
		if !known[id] {
			return IndustryProfile{}, fmt.Errorf("priority scenario ID %q is not one of Audspect's real PH-* scenarios", id)
		}
	}
	for id, weight := range businessImpactWeight {
		if !known[id] {
			return IndustryProfile{}, fmt.Errorf("business-impact-weight scenario ID %q is not one of Audspect's real PH-* scenarios", id)
		}
		if weight < 0 || weight > 1 {
			return IndustryProfile{}, fmt.Errorf("business-impact weight for scenario %q is %v, want a value in [0, 1]", id, weight)
		}
	}
	return IndustryProfile{
		Name: name, PriorityScenarioIDs: priorityScenarioIDs, DataClassifications: dataClassifications,
		BusinessImpactWeight: businessImpactWeight, Note: note,
	}, nil
}

// BFSINBFCProfile returns the BFSI/NBFC phishing profile. Financial
// fraud (BEC/invoice diversion) and domain-spoofing defense dominate,
// matching phishing.txt's own "financial-fraud detection" framing for
// PH-BEC-002/003.
func BFSINBFCProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"BFSI/NBFC",
		[]string{"PH-BEC-002", "PH-AUTH-004", "PH-ID-002"},
		[]string{"PII", "financial-transaction-data", "payment-card-data"},
		map[string]float64{"PH-BEC-002": 1.0, "PH-AUTH-004": 0.8, "PH-ID-002": 0.7},
		"Financial-sector priorities: BEC/invoice-diversion fraud, domain-spoofing (DMARC) defense, and OAuth consent abuse against fintech SaaS integrations dominate.",
	)
}

// HealthcareProfile returns the Healthcare phishing profile.
// Credential-harvesting of clinical staff (PHI exposure risk) and
// malicious-attachment defense dominate.
func HealthcareProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"Healthcare",
		[]string{"PH-URL-001", "PH-ATT-001", "PH-AUTH-008"},
		[]string{"PHI", "PII"},
		map[string]float64{"PH-URL-001": 1.0, "PH-ATT-001": 0.9, "PH-AUTH-008": 0.7},
		"Patient-data-protection priorities: credential-harvesting defense for clinical staff, malicious-attachment inspection, and trusted-sender exception abuse dominate.",
	)
}

// ManufacturingOTProfile returns the Manufacturing/OT-adjacent
// phishing profile. Supplier/invoice fraud and spoofed-vendor-domain
// defense dominate -- phishing.txt's own "supplier invoice changes...
// and phishing aimed at privileged IT/OT personnel" framing. This
// profile is configuration only, never a probe, consistent with
// webgwefficacy's own OT-adjacent profile's safety contract.
func ManufacturingOTProfile() (IndustryProfile, error) {
	return NewIndustryProfile(
		"Manufacturing/OT-adjacent",
		[]string{"PH-BEC-002", "PH-AUTH-004", "PH-CHN-001"},
		[]string{"OT-telemetry", "supplier-contract-data"},
		map[string]float64{"PH-BEC-002": 1.0, "PH-AUTH-004": 0.8, "PH-CHN-001": 0.5},
		"Supply-chain priorities: supplier invoice/payment diversion and spoofed-vendor-domain defense dominate over collaboration-platform lures.",
	)
}

// PrioritySummary filters AudspectPhishingCatalog's own real scenarios
// down to this profile's PriorityScenarioIDs and renders each one's
// already-computed Coverage, ordered by BusinessImpactWeight
// descending (a priority scenario with no assigned weight sorts last,
// at weight 0). It reads the catalog, never computes a verdict of its
// own. A priority scenario ID absent from scenarios is named
// explicitly, never silently dropped.
func (p IndustryProfile) PrioritySummary(scenarios []Scenario) string {
	if len(p.PriorityScenarioIDs) == 0 {
		return fmt.Sprintf("%s: no priority scenarios defined%s", p.Name, p.dataClassificationSuffix())
	}

	byID := make(map[string]Scenario, len(scenarios))
	for _, s := range scenarios {
		byID[s.ID] = s
	}

	ids := make([]string, len(p.PriorityScenarioIDs))
	copy(ids, p.PriorityScenarioIDs)
	sort.SliceStable(ids, func(i, j int) bool {
		return p.BusinessImpactWeight[ids[i]] > p.BusinessImpactWeight[ids[j]]
	})

	entries := make([]string, 0, len(ids))
	for _, id := range ids {
		s, ok := byID[id]
		if !ok {
			entries = append(entries, fmt.Sprintf("%s (%s): not present in this catalog", id, p.weightLabel(id)))
			continue
		}
		entries = append(entries, fmt.Sprintf("%s %s (%s): %s", s.ID, s.Name, p.weightLabel(id), s.Coverage))
	}
	return fmt.Sprintf("%s priorities: %s%s", p.Name, strings.Join(entries, "; "), p.dataClassificationSuffix())
}

func (p IndustryProfile) dataClassificationSuffix() string {
	if len(p.DataClassifications) == 0 {
		return ""
	}
	return "; data classifications: " + strings.Join(p.DataClassifications, ", ")
}

// Describe renders this profile's Name and Note together -- "<Name>:
// <Note>" -- or just Name alone when Note is empty.
func (p IndustryProfile) Describe() string {
	if p.Note == "" {
		return p.Name
	}
	return p.Name + ": " + p.Note
}

func (p IndustryProfile) weightLabel(id string) string {
	w, ok := p.BusinessImpactWeight[id]
	if !ok {
		return "no weight assigned"
	}
	return fmt.Sprintf("weight %.1f", w)
}

// industryProfileConstructors is the single source of truth mapping
// each shipped phishing industry profile's lookup key to its
// constructor.
var industryProfileConstructors = map[string]func() (IndustryProfile, error){
	"bfsi":             BFSINBFCProfile,
	"healthcare":       HealthcareProfile,
	"manufacturing-ot": ManufacturingOTProfile,
}

// IndustryProfileNames returns every shipped phishing industry
// profile's lookup key, sorted.
func IndustryProfileNames() []string {
	names := make([]string, 0, len(industryProfileConstructors))
	for name := range industryProfileConstructors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BuildIndustryProfile resolves name to its built IndustryProfile. The
// second return value is false when name isn't one of
// IndustryProfileNames' keys.
func BuildIndustryProfile(name string) (IndustryProfile, bool, error) {
	ctor, ok := industryProfileConstructors[name]
	if !ok {
		return IndustryProfile{}, false, nil
	}
	profile, err := ctor()
	return profile, true, err
}
