package webgwefficacy

import (
	"strings"
	"testing"
)

func TestNewIndustryProfile_UnknownPriorityDomainID_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", []string{"99"}, nil, nil, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an unknown priority domain ID, got nil")
	}
}

func TestNewIndustryProfile_UnknownBusinessImpactWeightDomainID_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", nil, nil, map[string]float64{"99": 1.0}, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an unknown business-impact-weight domain ID, got nil")
	}
}

func TestNewIndustryProfile_EmptyName_Errors(t *testing.T) {
	_, err := NewIndustryProfile("", []string{"01"}, nil, nil, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for an empty name, got nil")
	}
}

func TestNewIndustryProfile_BusinessImpactWeightBelowZero_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", nil, nil, map[string]float64{"01": -0.1}, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for a business-impact weight below 0, got nil")
	}
}

func TestNewIndustryProfile_BusinessImpactWeightAboveOne_Errors(t *testing.T) {
	_, err := NewIndustryProfile("test", nil, nil, map[string]float64{"01": 1.1}, "")
	if err == nil {
		t.Fatal("NewIndustryProfile: want error for a business-impact weight above 1, got nil")
	}
}

func TestNewIndustryProfile_ValidDomainIDs_Succeeds(t *testing.T) {
	_, err := NewIndustryProfile("test", []string{"01", "02"}, []string{"PII"}, map[string]float64{"01": 1.0}, "note")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
}

func TestBFSINBFCProfile_RealDomainReferences(t *testing.T) {
	profile, err := BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestHealthcareProfile_RealDomainReferences(t *testing.T) {
	profile, err := HealthcareProfile()
	if err != nil {
		t.Fatalf("HealthcareProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestManufacturingOTProfile_RealDomainReferences(t *testing.T) {
	profile, err := ManufacturingOTProfile()
	if err != nil {
		t.Fatalf("ManufacturingOTProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestMSPSharedTenantProfile_RealDomainReferences(t *testing.T) {
	profile, err := MSPSharedTenantProfile()
	if err != nil {
		t.Fatalf("MSPSharedTenantProfile: %v", err)
	}
	if len(profile.PriorityDomainIDs) == 0 {
		t.Error("PriorityDomainIDs is empty, want real domain references")
	}
}

func TestIndustryProfile_PrioritySummary_SortsByWeightDescendingAndRendersStatus(t *testing.T) {
	profile, err := NewIndustryProfile(
		"test-profile",
		[]string{"01", "02", "03"},
		nil,
		map[string]float64{"01": 0.5, "02": 1.0, "03": 0.8},
		"",
	)
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "URL filtering", Status: CoverageCovered},
		{DomainID: "02", DomainName: "TLS inspection", Status: CoverageNotCovered},
		{DomainID: "03", DomainName: "DLP", Status: CoverageExcluded, ExclusionReason: "deferred"},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}

	summary := profile.PrioritySummary(report)

	idxTLS := strings.Index(summary, "02 TLS inspection")
	idxDLP := strings.Index(summary, "03 DLP")
	idxURL := strings.Index(summary, "01 URL filtering")
	if idxTLS == -1 || idxDLP == -1 || idxURL == -1 {
		t.Fatalf("PrioritySummary() = %q, want all three priority domains rendered", summary)
	}
	if !(idxTLS < idxDLP && idxDLP < idxURL) {
		t.Errorf("PrioritySummary() = %q, want weight-descending order: 02 (1.0), 03 (0.8), 01 (0.5)", summary)
	}
	if !strings.Contains(summary, "01 URL filtering (weight 0.5): covered") {
		t.Errorf("PrioritySummary() = %q, want domain 01's own covered status rendered -- not merely a \"covered\" substring match against domain 02's \"not-covered\"", summary)
	}
	if !strings.Contains(summary, "not-covered") {
		t.Errorf("PrioritySummary() = %q, want domain 02's not-covered status rendered", summary)
	}
	if !strings.Contains(summary, "excluded") {
		t.Errorf("PrioritySummary() = %q, want domain 03's excluded status rendered", summary)
	}
}

func TestIndustryProfile_PrioritySummary_AppendsDataClassificationsWhenPresent(t *testing.T) {
	profile, err := NewIndustryProfile(
		"test-profile",
		[]string{"01"},
		[]string{"PHI", "PII", "financial-transaction-data"},
		map[string]float64{"01": 1.0},
		"",
	)
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "URL filtering", Status: CoverageCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}

	summary := profile.PrioritySummary(report)

	want := "test-profile priorities: 01 URL filtering (weight 1.0): covered; data classifications: PHI, PII, financial-transaction-data"
	if summary != want {
		t.Errorf("PrioritySummary() = %q, want %q -- classifications appended after the domain-priority list, in their configured order, as-is", summary, want)
	}
}

func TestIndustryProfile_PrioritySummary_OmitsClassificationSuffixWhenEmpty(t *testing.T) {
	withNilClassifications, err := NewIndustryProfile("test-profile", []string{"01"}, nil, map[string]float64{"01": 1.0}, "")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	withEmptyClassifications, err := NewIndustryProfile("test-profile", []string{"01"}, []string{}, map[string]float64{"01": 1.0}, "")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "URL filtering", Status: CoverageCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}

	want := "test-profile priorities: 01 URL filtering (weight 1.0): covered"
	if got := withNilClassifications.PrioritySummary(report); got != want {
		t.Errorf("PrioritySummary() with nil DataClassifications = %q, want %q -- output unchanged from before this field was wired in, never a dangling \"data classifications: \" label", got, want)
	}
	if got := withEmptyClassifications.PrioritySummary(report); got != want {
		t.Errorf("PrioritySummary() with empty DataClassifications = %q, want %q", got, want)
	}
}

func TestIndustryProfile_PrioritySummary_NoPriorityDomainsStillAppendsClassifications(t *testing.T) {
	profile, err := NewIndustryProfile("test-profile", nil, []string{"PII"}, nil, "")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}

	want := "test-profile: no priority domains defined; data classifications: PII"
	if got := profile.PrioritySummary(report); got != want {
		t.Errorf("PrioritySummary() = %q, want %q", got, want)
	}
}

func TestIndustryProfile_PrioritySummary_MissingDomainIncludesItsAssignedWeight(t *testing.T) {
	profile, err := NewIndustryProfile("test-profile", []string{"01"}, nil, map[string]float64{"01": 0.7}, "")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "02", DomainName: "TLS inspection", Status: CoverageCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}

	summary := profile.PrioritySummary(report)

	if !strings.Contains(summary, "01 (weight 0.7): not present in this report") {
		t.Errorf("PrioritySummary() = %q, want the missing domain's own assigned weight carried into its \"not present\" entry", summary)
	}
}

func TestIndustryProfile_PrioritySummary_NoWeightAssigned_DistinctFromZeroWeight(t *testing.T) {
	profile, err := NewIndustryProfile(
		"test-profile",
		[]string{"01", "02"},
		nil,
		map[string]float64{"01": 0.0},
		"",
	)
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "01", DomainName: "URL filtering", Status: CoverageCovered},
		{DomainID: "02", DomainName: "TLS inspection", Status: CoverageCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}

	summary := profile.PrioritySummary(report)

	if !strings.Contains(summary, "01 URL filtering (weight 0.0): covered") {
		t.Errorf("PrioritySummary() = %q, want domain 01's deliberate zero weight rendered as \"weight 0.0\"", summary)
	}
	if !strings.Contains(summary, "02 TLS inspection (no weight assigned): covered") {
		t.Errorf("PrioritySummary() = %q, want domain 02's absent weight rendered as \"no weight assigned\", distinct from a deliberate 0.0", summary)
	}
}

func TestIndustryProfile_PrioritySummary_PriorityDomainMissingFromReport_NotSilentlyDropped(t *testing.T) {
	profile, err := NewIndustryProfile("test-profile", []string{"01"}, nil, nil, "")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := NewCoverageReport([]DomainCoverage{
		{DomainID: "02", DomainName: "TLS inspection", Status: CoverageCovered},
	})
	if err != nil {
		t.Fatalf("NewCoverageReport: %v", err)
	}

	summary := profile.PrioritySummary(report)

	if !strings.Contains(summary, "01") {
		t.Errorf("PrioritySummary() = %q, want the missing priority domain ID named, never silently dropped", summary)
	}
	if !strings.Contains(summary, "not present in this report") {
		t.Errorf("PrioritySummary() = %q, want an explicit note that domain 01 is absent from the given report", summary)
	}
}

func TestIndustryProfile_PrioritySummary_NoPriorityDomains_ReturnsSensibleMessage(t *testing.T) {
	profile, err := NewIndustryProfile("test-profile", nil, nil, nil, "")
	if err != nil {
		t.Fatalf("NewIndustryProfile: %v", err)
	}
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}

	summary := profile.PrioritySummary(report)

	want := "test-profile: no priority domains defined"
	if summary != want {
		t.Errorf("PrioritySummary() = %q, want %q -- an exact match, not merely non-empty, so a regression in the no-priority-domains branch (e.g. a dangling \"; data classifications: \" suffix) can't slip through", summary, want)
	}
}

// TestBFSINBFCProfile_PrioritySummary_AgainstRealCoverageReport proves
// an industry profile actually has a real caller: every one of
// BFSINBFCProfile's priority domains (03, 09, 11) is covered against
// Audspect's real, current coverage data, not a synthetic report
// built only for this test.
func TestBFSINBFCProfile_PrioritySummary_AgainstRealCoverageReport(t *testing.T) {
	profile, err := BFSINBFCProfile()
	if err != nil {
		t.Fatalf("BFSINBFCProfile: %v", err)
	}
	report, err := AudspectWebGWCoverageReport()
	if err != nil {
		t.Fatalf("AudspectWebGWCoverageReport: %v", err)
	}

	summary := profile.PrioritySummary(report)

	for _, id := range profile.PriorityDomainIDs {
		if !strings.Contains(summary, id) {
			t.Errorf("PrioritySummary() = %q, want priority domain %q named", summary, id)
		}
	}
	if strings.Contains(summary, "not present in this report") {
		t.Errorf("PrioritySummary() = %q, want every BFSI/NBFC priority domain present in the real coverage report", summary)
	}
}
