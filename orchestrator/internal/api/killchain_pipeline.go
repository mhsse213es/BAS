package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/pipelinecheck"
)

// pipelineConnectorLoader returns a stored detection connector, with its credentials.
type pipelineConnectorLoader func(ctx context.Context, id string) (*detectverify.Config, error)

// pipelineStageRunner runs server-side pipeline stages. A check is synchronous and read-only,
// so Start runs it and holds the result until Collect, which the orchestrator calls straight
// after. A result lost before collection is reported as a failed stage, never as a pass.
type pipelineStageRunner struct {
	load pipelineConnectorLoader
	now  func() time.Time

	mu      sync.Mutex
	results map[string][]killchain.PipelineStageResult
}

func newPipelineStageRunner(load pipelineConnectorLoader, now func() time.Time) *pipelineStageRunner {
	if now == nil {
		now = time.Now
	}
	return &pipelineStageRunner{load: load, now: now, results: map[string][]killchain.PipelineStageResult{}}
}

const pipelineExecPrefix = "pipeline-"

func (p *pipelineStageRunner) start(ctx context.Context, campaignID string, st killchain.StageDef) (string, error) {
	execID := fmt.Sprintf("%s%s-%s-%d", pipelineExecPrefix, campaignID, st.Key, p.now().UnixNano())
	res := p.run(ctx, st)
	p.mu.Lock()
	p.results[execID] = res
	p.mu.Unlock()
	return execID, nil
}

// collect returns a finished pipeline stage. An unknown ID means the result was not retained
// (for example after a restart); that is reported as a failed stage.
func (p *pipelineStageRunner) collect(executionID string) (killchain.StageEvidence, bool, bool, error) {
	p.mu.Lock()
	res, ok := p.results[executionID]
	delete(p.results, executionID)
	p.mu.Unlock()
	if !ok {
		return killchain.StageEvidence{}, true, true, nil
	}
	return killchain.StageEvidence{Pipeline: res}, true, false, nil
}

// run performs the read-only checks for one pipeline stage and returns every stage's result.
func (p *pipelineStageRunner) run(ctx context.Context, st killchain.StageDef) []killchain.PipelineStageResult {
	spec := *st.Pipeline
	now := p.now()
	to := now
	from := now.Add(-time.Duration(spec.LookbackMinutes) * time.Minute)

	if p.load == nil {
		return pipelineStageErrors("pipeline connector loader is not wired", now)
	}
	cfg, err := p.load(ctx, spec.ConnectorID)
	if err != nil {
		return pipelineStageErrors(fmt.Sprintf("connector %s could not be loaded: %v", spec.ConnectorID, err), now)
	}
	if cfg.Provider != "elastic" {
		return pipelineStageErrors(fmt.Sprintf("provider %q has no read-only ingestion check in this build", cfg.Provider), now)
	}

	client := &http.Client{Timeout: 30 * time.Second, Transport: pipelineTransport(cfg.InsecureTLS)}
	rep := pipelinecheck.CheckElasticIngestion(ctx, client,
		pipelinecheck.ElasticConfig{BaseURL: cfg.BaseURL, APIKey: cfg.APIToken},
		pipelinecheck.IngestionQuery{Index: spec.Index, Field: spec.Field, Identifier: spec.Identifier, From: from, To: to},
		p.now)

	out := make([]killchain.PipelineStageResult, 0, len(pipelinecheck.PipelineStages))
	for _, s := range pipelinecheck.PipelineStages {
		switch s {
		case pipelinecheck.StageConnectivity:
			out = append(out, connectivityFromIngestion(rep, cfg.ID, now))
		case pipelinecheck.StageIngestion:
			out = append(out, toKillchainResult(rep))
		default:
			out = append(out, killchain.PipelineStageResult{
				Stage: string(s), Status: "NOT_TESTED", CheckedAt: now,
				Reason: "not checked by this stage; raw ingestion evidence does not show this stage ran",
			})
		}
	}
	return out
}

// connectivityFromIngestion derives reachability from the ingestion response. Any HTTP
// response below 500 proves the connector was reached; 401 and 403 are reached but rejected.
// No response at all is not reachable. This is not a second probe.
func connectivityFromIngestion(rep pipelinecheck.StageReport, connectorID string, now time.Time) killchain.PipelineStageResult {
	r := killchain.PipelineStageResult{Stage: string(pipelinecheck.StageConnectivity), Connector: connectorID, CheckedAt: now}
	code := rep.Evidence.HTTPStatus
	switch {
	case code == 0:
		r.Status, r.Reason = "ERROR", "connector not reachable: no response received"
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		r.Status, r.Reason = "ERROR", fmt.Sprintf("connector reached but rejected (HTTP %d)", code)
	case code >= 500:
		r.Status, r.Reason = "ERROR", fmt.Sprintf("connector reached but returned a server error (HTTP %d)", code)
	default:
		r.Status, r.Reason = "VERIFIED", fmt.Sprintf("connector reachable and authenticated (HTTP %d); not proof of event ingestion", code)
	}
	return r
}

func toKillchainResult(rep pipelinecheck.StageReport) killchain.PipelineStageResult {
	return killchain.PipelineStageResult{
		Stage:      string(rep.Stage),
		Status:     string(rep.Status),
		Reason:     rep.Reason,
		Connector:  rep.Evidence.Connector,
		Target:     rep.Evidence.Target,
		Identifier: rep.Evidence.Identifier,
		WindowFrom: rep.Evidence.WindowFrom,
		WindowTo:   rep.Evidence.WindowTo,
		MatchCount: rep.Evidence.MatchCount,
		EventIDs:   rep.Evidence.EventIDs,
		HTTPStatus: rep.Evidence.HTTPStatus,
		CheckedAt:  rep.CheckedAt,
	}
}

// pipelineStageErrors reports a failure before any check ran: connectivity and ingestion
// are ERROR, every other stage NOT_TESTED.
func pipelineStageErrors(reason string, now time.Time) []killchain.PipelineStageResult {
	out := make([]killchain.PipelineStageResult, 0, len(pipelinecheck.PipelineStages))
	for _, s := range pipelinecheck.PipelineStages {
		r := killchain.PipelineStageResult{Stage: string(s), Status: "NOT_TESTED", CheckedAt: now,
			Reason: "not checked by this stage; the stage did not run"}
		if s == pipelinecheck.StageConnectivity || s == pipelinecheck.StageIngestion {
			r.Status, r.Reason = "ERROR", reason
		}
		out = append(out, r)
	}
	return out
}

// pipelineTransport honours a connector's insecure-TLS setting, which exists for self-signed
// on-premises appliances. Verification stays on by default.
func pipelineTransport(insecure bool) http.RoundTripper {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- explicit per-connector setting
	}
	return t
}
