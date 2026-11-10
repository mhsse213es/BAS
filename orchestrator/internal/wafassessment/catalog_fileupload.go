package wafassessment

import (
	"fmt"

	"github.com/audspect/bas/internal/wafcatalog"
)

// AudspectFileUploadContentTrustScenario returns Audspect's real,
// current seed "File Upload and Content Trust" scenario: the 3 real
// wafcatalog file-upload vectors, validated against the real catalog
// before returning. FILEUP-003 is deliberately left out of
// AudspectFileUploadContentTrustFixtures so this scenario's own
// UntestedVectorIDs/Incomplete path is exercised directly, not just the
// suite overall through unrelated scenarios' seed data.
func AudspectFileUploadContentTrustScenario() (EnterpriseScenario, error) {
	scenario, err := NewEnterpriseScenario(
		"WAFSCENARIO-FILE-UPLOAD-CONTENT-TRUST",
		"File Upload and Content Trust",
		"evaluate whether the WAF prevents malicious file uploads that evade extension-based filtering (double extensions), exhaust server resources (decompression bombs), or escape the upload directory (filename path traversal)",
		[]string{"FILEUP-001", "FILEUP-002", "FILEUP-003"},
		"target exposes a file-upload endpoint reachable through the WAF whose accepted file types and decompression behavior are known",
		"a WAF-mechanism CollectionResult per contributing vector, fixture-backed in this phase",
		"manually authored from the user's enterprise-scenario critique, scenario 07",
	)
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading file-upload-content-trust scenario: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading file-upload-content-trust scenario: %w", err)
	}
	if err := ValidateAgainstCatalog(scenario, catalog); err != nil {
		return EnterpriseScenario{}, fmt.Errorf("loading file-upload-content-trust scenario: %w", err)
	}
	return scenario, nil
}

// AudspectFileUploadContentTrustFixtures returns Audspect's real,
// current seed fixture set for the file-upload-content-trust scenario
// -- deliberately NOT a uniform pass. FILEUP-001 (SeverityCritical,
// web-shell upload via double extension) is seeded as Missed, a
// deliberate simulated bypass, so the scenario genuinely resolves to
// ScenarioFail. FILEUP-002 is seeded as Blocked. FILEUP-003 is
// deliberately absent (untested).
func AudspectFileUploadContentTrustFixtures() (map[string]VectorFixture, error) {
	return map[string]VectorFixture{
		"FILEUP-001": missed("FILEUP-001"),
		"FILEUP-002": blocked("FILEUP-002"),
	}, nil
}
