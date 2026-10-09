package admatrix

import "github.com/audspect/bas/internal/adprimitive"

// CoverageStatus is the product-facing, highest-achieved coverage state for a
// capability. It is derived from the matrix, strictly separating what is merely
// modeled from what has runnable content, what has actually executed, and what
// has been proven by observed telemetry.
type CoverageStatus string

const (
	StatusModeled            CoverageStatus = "modeled"             // represented + graph-reachable in a synthetic model only
	StatusScenarioComposable CoverageStatus = "scenario_composable" // reusable executable content exists (ART atomic / Caldera ability)
	StatusExecuted           CoverageStatus = "executed"            // executed against an endpoint or a real domain
	StatusTelemetryObserved  CoverageStatus = "telemetry_observed"  // outcome proven by observed telemetry/detection
)

// CapabilityCoverage is one capability's product-facing coverage record.
type CapabilityCoverage struct {
	PrimitiveID            string                    `json:"primitiveId"`
	Name                   string                    `json:"name"`
	TechniqueID            string                    `json:"techniqueId,omitempty"`
	CoverageStatus         CoverageStatus            `json:"coverageStatus"`
	ValidationLevel        string                    `json:"validationLevel"`
	RequiredEnvToExecute   string                    `json:"requiredEnvToExecute"`
	ExecutionMethod        string                    `json:"executionMethod"`
	ReuseSource            string                    `json:"reuseSource,omitempty"`
	Prerequisites          adprimitive.Prerequisites `json:"prerequisites"`
	ExpectedPostconditions []adprimitive.Capability  `json:"expectedPostconditions,omitempty"`
	EvidenceRequirements   []string                  `json:"evidenceRequirements,omitempty"`
	TelemetrySources       []string                  `json:"telemetrySources,omitempty"`
	Cleanup                []string                  `json:"cleanup,omitempty"`
	Limitations            []string                  `json:"limitations"`
}

// ReportSummary is the measurable rollup. Every count is traceable to the
// Capabilities list (each capability contributes to exactly one coverage-status
// and one validation-level bucket).
type ReportSummary struct {
	Total                     int            `json:"total"`
	ByValidationLevel         map[string]int `json:"byValidationLevel"`
	ByCoverageStatus          map[string]int `json:"byCoverageStatus"`
	WithReusableContent       int            `json:"withReusableContent"`
	RequiringDomainController int            `json:"requiringDomainController"`
	RequiringDomainJoinedHost int            `json:"requiringDomainJoinedHost"`
}

// CoverageReport is the full product-facing AD coverage report.
type CoverageReport struct {
	Summary      ReportSummary        `json:"summary"`
	Capabilities []CapabilityCoverage `json:"capabilities"`
}

func catalogByID() map[string]adprimitive.Primitive {
	m := map[string]adprimitive.Primitive{}
	for _, c := range [][]adprimitive.Primitive{
		adprimitive.ADCSCatalog, adprimitive.ACLAbuseCatalog, adprimitive.RBCDCatalog, adprimitive.DCSyncCatalog,
		adprimitive.DelegationCatalog, adprimitive.TrustAbuseCatalog, adprimitive.GPOAbuseCatalog,
	} {
		for _, p := range c {
			m[p.ID] = p
		}
	}
	return m
}

// coverageStatusFor derives the honest highest-achieved status from an entry.
// It never returns executed/telemetry_observed off a synthetic model; those
// require a real execution result, which this matrix (by design) does not mint.
func coverageStatusFor(e Entry) CoverageStatus {
	switch e.CurrentValidation {
	case LevelTelemetryObserved:
		return StatusTelemetryObserved
	case LevelEndpointExecuted, LevelRealADExecuted:
		return StatusExecuted
	}
	if e.ExecutionMethod == "art-atomic" || e.ExecutionMethod == "caldera-ability" {
		return StatusScenarioComposable
	}
	return StatusModeled
}

func limitationsFor(e Entry, status CoverageStatus) []string {
	var lim []string
	if e.CurrentValidation == LevelModelSimulated {
		lim = append(lim, "Validated only in a synthetic model; not executed against a real domain.")
	}
	switch status {
	case StatusModeled:
		lim = append(lim, "No reusable executable content yet (synthetic predicate only); not scenario-composable.")
	case StatusScenarioComposable:
		lim = append(lim, "Reusable content exists ("+e.ReuseSource+") but has not been executed or observed against a real domain.")
	}
	lim = append(lim, "Requires "+string(e.RequiredEnvToExecute)+" to actually execute.")
	return lim
}

// Report builds the product-facing AD coverage report from the matrix. It reuses
// AllEntries and the real adprimitive catalog (for names/prerequisites); it adds
// no new catalog and executes nothing.
func Report() CoverageReport {
	cat := catalogByID()
	entries := AllEntries()

	rep := CoverageReport{
		Summary: ReportSummary{
			Total:             len(entries),
			ByValidationLevel: map[string]int{},
			ByCoverageStatus:  map[string]int{},
		},
	}
	for _, e := range entries {
		p := cat[e.PrimitiveID]
		status := coverageStatusFor(e)
		rep.Capabilities = append(rep.Capabilities, CapabilityCoverage{
			PrimitiveID:            e.PrimitiveID,
			Name:                   p.Name,
			TechniqueID:            e.TechniqueID,
			CoverageStatus:         status,
			ValidationLevel:        e.CurrentValidation.String(),
			RequiredEnvToExecute:   string(e.RequiredEnvToExecute),
			ExecutionMethod:        e.ExecutionMethod,
			ReuseSource:            e.ReuseSource,
			Prerequisites:          p.Prerequisites,
			ExpectedPostconditions: e.ExpectedPostconditions,
			EvidenceRequirements:   e.EvidenceRequirements,
			TelemetrySources:       e.TelemetrySources,
			Cleanup:                e.Cleanup,
			Limitations:            limitationsFor(e, status),
		})
		rep.Summary.ByValidationLevel[e.CurrentValidation.String()]++
		rep.Summary.ByCoverageStatus[string(status)]++
		if e.ExecutionMethod == "art-atomic" || e.ExecutionMethod == "caldera-ability" {
			rep.Summary.WithReusableContent++
		}
		switch e.RequiredEnvToExecute {
		case EnvDomainController:
			rep.Summary.RequiringDomainController++
		case EnvDomainJoinedHost:
			rep.Summary.RequiringDomainJoinedHost++
		}
	}
	return rep
}
