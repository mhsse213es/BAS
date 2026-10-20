package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudrun"
)

// ObserveSpec asks a scenario run to check its predictions against audit
// evidence. ActionTime is when the scenario was executed; Window bounds the
// search either side of it. Events is the provider's live log source.
type ObserveSpec struct {
	ActionTime time.Time
	Window     time.Duration
	Events     cloudgraph.EventSource
}

// CloudScenarioRunRequest runs one builtin cloud scenario for one principal
// against one resource, using a live discovery pass for the graph.
type CloudScenarioRunRequest struct {
	ScenarioID    string                  `json:"scenarioId"`
	Account       cloudgraph.AccountScope `json:"account"`
	Principal     string                  `json:"principal"`
	Resource      string                  `json:"resource"`
	InitiatedBy   string                  `json:"-"`
	SessionPolicy string                  `json:"sessionPolicy,omitempty"` // AWS assumed-role session policy; optional

	// Discoverer and Observe are server-supplied, never decoded from a body.
	Discoverer cloudgraph.Discoverer `json:"-"`
	Observe    *ObserveSpec          `json:"-"`
}

// cloudScenarioRunResult is the stored result of one scenario run.
type cloudScenarioRunResult struct {
	ScenarioID    string                            `json:"scenarioId"`
	Verdict       string                            `json:"verdict"`
	Prerequisites []*cloudgraph.PrerequisiteResult  `json:"prerequisites"`
	Steps         []*cloudgraph.CloudControlOutcome `json:"steps"`
	Observed      bool                              `json:"observed"`
	Report        cloudgraph.DiscoveryReport        `json:"report"`
}

// ExecuteCloudScenarioRun records a cloud_runs row for one scenario run. The
// graph comes from live discovery; a discovery or validation failure marks the
// row failed. A verdict of "inconclusive" is stored as partial, never as a
// clean result.
func ExecuteCloudScenarioRun(ctx context.Context, pool *pgxpool.Pool, req CloudScenarioRunRequest) (*cloudrun.CloudRun, error) {
	run := &cloudrun.CloudRun{
		ID:          newRunID(),
		ScenarioID:  req.ScenarioID,
		Provider:    req.Account.Provider,
		AccountID:   req.Account.AccountID,
		TenantID:    req.Account.TenantID,
		Region:      req.Account.Region,
		Status:      cloudrun.StatusRunning,
		InitiatedBy: req.InitiatedBy,
		StartedAt:   time.Now().UTC(),
	}
	if err := InsertCloudRun(ctx, pool, run); err != nil {
		return nil, err
	}
	fail := func(err error) (*cloudrun.CloudRun, error) {
		_ = UpdateCloudRunStatus(ctx, pool, run.ID, cloudrun.StatusFailed, nil, err.Error())
		return currentRunOrNil(ctx, pool, run.ID), fmt.Errorf("cloud scenario run %s: %w", run.ID, err)
	}

	scenario := cloudgraph.CloudScenarioByID(req.ScenarioID)
	if scenario == nil {
		return fail(fmt.Errorf("unknown scenario %q", req.ScenarioID))
	}
	if scenario.Provider != req.Account.Provider {
		return fail(fmt.Errorf("scenario %s targets %s, run names %s", scenario.ID, scenario.Provider, req.Account.Provider))
	}
	evaluator, err := evaluatorFor(req.Account.Provider)
	if err != nil {
		return fail(err)
	}
	if req.Discoverer == nil {
		return fail(fmt.Errorf("scenario runs require a discovery source"))
	}

	dctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	graph, report, err := req.Discoverer.Discover(dctx)
	cancel()
	if err == nil && graph == nil {
		err = fmt.Errorf("discovery returned no graph")
	}
	if err != nil {
		return fail(fmt.Errorf("discovery: %w", err))
	}

	sessionDoc := ""
	if req.SessionPolicy != "" {
		doc, err := cloudgraph.NormalizeAWSSessionPolicy(req.SessionPolicy)
		if err != nil {
			return fail(err)
		}
		sessionDoc = doc
	}
	result := cloudgraph.ExecuteCloudScenarioInSession(scenario, graph, evaluator, req.Principal, req.Resource, sessionDoc)
	if req.Observe != nil && req.Observe.Events != nil && result.OverallVerdict != "not-attempted" {
		correlator := &cloudgraph.LiveCorrelator{Source: req.Observe.Events}
		cloudgraph.ObserveCloudScenario(result, correlator, req.Principal, req.Resource, req.Observe.ActionTime, req.Observe.Window)
	}

	stored := cloudScenarioRunResult{
		ScenarioID:    scenario.ID,
		Verdict:       result.OverallVerdict,
		Prerequisites: result.Prerequisites,
		Steps:         result.Steps,
		Observed:      req.Observe != nil && req.Observe.Events != nil,
		Report:        report,
	}
	resultJSON, err := json.Marshal(stored)
	if err != nil {
		return fail(err)
	}

	status := cloudrun.StatusCompleted
	if result.OverallVerdict == "inconclusive" {
		status = cloudrun.StatusPartial
	}
	if err := UpdateCloudRunStatus(ctx, pool, run.ID, status, resultJSON, ""); err != nil {
		return currentRunOrNil(ctx, pool, run.ID), fmt.Errorf("cloud scenario run %s: %w", run.ID, err)
	}
	return GetCloudRun(ctx, pool, run.ID)
}
