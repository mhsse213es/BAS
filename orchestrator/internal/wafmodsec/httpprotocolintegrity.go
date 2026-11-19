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

// HTTPProtocolIntegrityLiveVectorIDs is the one of
// AudspectHTTPProtocolIntegrityScenario's 3 contributing vectors that can
// be genuinely replayed live today: HTTPPARSE-002 (HTTP verb tampering,
// PayloadLocation ""). The other two are real, disclosed gaps, not an
// oversight -- HTTPPARSE-001 (CL/TE request smuggling) needs a raw,
// desynchronized frame Go's net/http client cannot send, and
// HTTPPARSE-003 (CRLF response-splitting) needs a literal CR/LF inside a
// header value, which net/url's query-encoding and net/http's own header
// validation both refuse to transmit raw -- replaying either honestly
// would require a raw-socket client, not modsecwaf.Client.
var HTTPProtocolIntegrityLiveVectorIDs = []string{"HTTPPARSE-002"}

// BuildHTTPProtocolIntegrityLiveFixtures drives HTTPPARSE-002's real
// malicious request against the live WAF client and returns one
// wafassessment.VectorFixture for it, labeled EvidenceSourceLiveExecution.
func BuildHTTPProtocolIntegrityLiveFixtures(ctx context.Context, client *modsecwaf.Client) (map[string]wafassessment.VectorFixture, error) {
	catalog, err := wafcatalog.AudspectWAFAttackCatalog()
	if err != nil {
		return nil, fmt.Errorf("loading wafcatalog: %w", err)
	}
	byID := make(map[string]wafcatalog.AttackVector, len(catalog))
	for _, v := range catalog {
		byID[v.ID] = v
	}

	fixtures := make(map[string]wafassessment.VectorFixture, len(HTTPProtocolIntegrityLiveVectorIDs))
	for _, id := range HTTPProtocolIntegrityLiveVectorIDs {
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

// RunHTTPProtocolIntegrityLive loads the real HTTP-protocol-integrity
// scenario and catalog, builds its live fixtures, and evaluates them
// through the real, unmodified wafassessment.EvaluateScenario.
func RunHTTPProtocolIntegrityLive(ctx context.Context, client *modsecwaf.Client) (wafassessment.EnterpriseScenario, wafassessment.ScenarioResult, error) {
	scenario, err := wafassessment.AudspectHTTPProtocolIntegrityScenario()
	if err != nil {
		return wafassessment.EnterpriseScenario{}, wafassessment.ScenarioResult{}, fmt.Errorf("loading http-protocol-integrity scenario: %w", err)
	}
	fixtures, err := BuildHTTPProtocolIntegrityLiveFixtures(ctx, client)
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
