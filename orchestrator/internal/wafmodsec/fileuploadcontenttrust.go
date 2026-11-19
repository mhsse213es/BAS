package wafmodsec

import (
	"context"
	"fmt"
	"time"

	"github.com/audspect/bas/internal/vendors/modsecwaf"
	"github.com/audspect/bas/internal/wafassessment"
	"github.com/audspect/bas/internal/wafcatalog"
	"github.com/audspect/bas/internal/wafval"
)

// FileUploadContentTrustLiveVectorIDs is 2 of
// AudspectFileUploadContentTrustScenario's 3 contributing vectors --
// FILEUP-001 (web-shell upload, PayloadLocation "body:multipart:file")
// and FILEUP-003 (path traversal via a crafted filename, PayloadLocation
// "body:multipart:filename") -- now that modsecwaf.BuildRequest supports
// real multipart/form-data bodies. FILEUP-002 (a decompression-bomb
// archive) is a real, disclosed gap: its catalog Payload is a human
// description ("<highly compressed archive engineered to expand to many
// GB on extraction>"), not actual bytes -- there is no honest way to turn
// that string into a genuine zip bomb, and this lab's origin has no
// archive-extraction logic for a bomb to even detonate against.
var FileUploadContentTrustLiveVectorIDs = []string{"FILEUP-001", "FILEUP-003"}

// BuildFileUploadContentTrustLiveFixtures drives each of
// FileUploadContentTrustLiveVectorIDs' real malicious request against the
// live WAF client and returns one wafassessment.VectorFixture per vector,
// labeled EvidenceSourceLiveExecution.
func BuildFileUploadContentTrustLiveFixtures(ctx context.Context, client *modsecwaf.Client) (map[string]wafassessment.VectorFixture, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	byID := make(map[string]wafcatalog.AttackVector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	fixtures := make(map[string]wafassessment.VectorFixture, len(FileUploadContentTrustLiveVectorIDs))
	for _, id := range FileUploadContentTrustLiveVectorIDs {
		v, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("vector %q not found in the real catalog", id)
		}
		resp, err := client.Send(ctx, v.Malicious)
		if err != nil {
			return nil, fmt.Errorf("driving %s live against the WAF: %w", id, err)
		}
		key := wafval.CorrelationKey{TestExecutionID: id, RequestID: id}
		results := BuildCollectionResults(resp, key, time.Now())
		fixtures[id] = wafassessment.VectorFixture{
			VectorID:       id,
			Results:        results,
			EvidenceSource: wafassessment.EvidenceSourceLiveExecution,
		}
	}
	return fixtures, nil
}

// RunFileUploadContentTrustLive loads the real file-upload-content-trust
// scenario and catalog, builds its live fixtures, and evaluates them
// through the real, unmodified wafassessment.EvaluateScenario.
func RunFileUploadContentTrustLive(ctx context.Context, client *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectFileUploadContentTrustScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading file-upload-content-trust scenario: %w", err)
	}
	fixtures, err := BuildFileUploadContentTrustLiveFixtures(ctx, client)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("building live fixtures: %w", err)
	}
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading wafcatalog: %w", err)
	}
	result, err := wafassessment.EvaluateScenario(scenario, fixtures, catalog)
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("evaluating scenario: %w", err)
	}
	return scenario, result, nil
}
