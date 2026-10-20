package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/killchain"
	"github.com/audspect/bas/internal/pipelinecheck"
)

// pipelineConnectorConfig is a stored detection connector, with its credentials.
type pipelineConnectorConfig = detectverify.Config

// pipelineConnectorLoader returns a stored detection connector by ID.
type pipelineConnectorLoader func(ctx context.Context, id string) (*pipelineConnectorConfig, error)

// pipelineRunStore is the durable record of pipeline checks. db.KillChainStore satisfies it.
type pipelineRunStore interface {
	BeginPipelineRun(ctx context.Context, r db.PipelineRun) error
	CompletePipelineRun(ctx context.Context, executionID string, results []byte, at time.Time) error
	PipelineRun(ctx context.Context, executionID string) (db.PipelineRun, error)
}

// pipelineStageRunner runs read-only pipeline checks and keeps their results in the durable
// store. Start runs the check and writes its result before it returns. Collect reads the
// result back from the store, so a restart between the two does not lose a completed check.
type pipelineStageRunner struct {
	runs pipelineRunStore
	load pipelineConnectorLoader
	now  func() time.Time
}

func newPipelineStageRunner(runs pipelineRunStore, load pipelineConnectorLoader, now func() time.Time) *pipelineStageRunner {
	if now == nil {
		now = time.Now
	}
	return &pipelineStageRunner{runs: runs, load: load, now: now}
}

const pipelineExecPrefix = "pipeline-"

// pipelineExecutionID is deterministic per campaign and stage. A stage is started once, so
// re-starting it finds the same run instead of creating a second one.
func pipelineExecutionID(campaignID, stageKey string) string {
	return pipelineExecPrefix + campaignID + "-" + stageKey
}

// start runs the check unless a completed result already exists. A check that runs but whose
// result cannot be written is an error, so it is never mistaken for a pass.
func (p *pipelineStageRunner) start(ctx context.Context, campaignID string, st killchain.StageDef) (string, error) {
	execID := pipelineExecutionID(campaignID, st.Key)
	existing, err := p.runs.PipelineRun(ctx, execID)
	switch {
	case err == nil && existing.State == db.PipelineCompleted:
		return execID, nil
	case err != nil && !errors.Is(err, db.ErrPipelineRunNotFound):
		return "", fmt.Errorf("pipeline run could not be read: %w", err)
	}
	if err := p.runs.BeginPipelineRun(ctx, db.PipelineRun{ExecutionID: execID, CampaignID: campaignID,
		StageKey: st.Key, ConnectorID: st.Pipeline.ConnectorID, StartedAt: p.now()}); err != nil {
		return "", fmt.Errorf("pipeline run could not be recorded: %w", err)
	}
	res := p.run(ctx, st)
	payload, err := json.Marshal(res)
	if err != nil {
		return "", fmt.Errorf("pipeline result could not be encoded: %w", err)
	}
	if err := p.runs.CompletePipelineRun(ctx, execID, payload, p.now()); err != nil {
		return "", fmt.Errorf("pipeline result could not be persisted: %w", err)
	}
	return execID, nil
}

// collect reads a stage's result from the store. A run that never completed, or has no record,
// is an unknown outcome: reported as not done, so recovery marks it interrupted. Only a read
// failure is returned as an error, so recovery retries it later.
func (p *pipelineStageRunner) collect(ctx context.Context, executionID string) (killchain.StageEvidence, bool, bool, error) {
	run, err := p.runs.PipelineRun(ctx, executionID)
	if errors.Is(err, db.ErrPipelineRunNotFound) {
		return killchain.StageEvidence{}, false, false, nil
	}
	if err != nil {
		return killchain.StageEvidence{}, false, false, err
	}
	if run.State != db.PipelineCompleted {
		return killchain.StageEvidence{}, false, false, nil
	}
	var res []killchain.PipelineStageResult
	if err := json.Unmarshal(run.Results, &res); err != nil {
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
	if !cfg.Enabled {
		return pipelineStageErrors(fmt.Sprintf("connector %s is disabled", spec.ConnectorID), now)
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
