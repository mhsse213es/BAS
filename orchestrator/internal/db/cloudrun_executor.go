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

// CloudPlanRunRequest is the input to ExecuteCloudPlanRun. The caller
// supplies the graph data directly -- this package holds no embedded
// fixtures; fixtures exist only in this package's own tests. Lives in
// package db (not cloudrun) to avoid an import cycle: db already imports
// cloudrun for the CloudRun/Status types, so the executor -- which needs
// both the cloudrun types AND db's own store functions -- cannot live in
// cloudrun without db importing back into it.
type CloudPlanRunRequest struct {
	ScenarioID  string
	Account     cloudgraph.AccountScope
	Edges       []*cloudgraph.CloudPermission
	Held        []string
	Target      string
	MaxHops     int
	InitiatedBy string
}

// evaluatorFor maps a cloud_runs.provider value to the concrete evaluator
// that understands it. All three evaluators are zero-arg structs with
// pointer-receiver EvaluatePermission methods. No fallback: an unrecognized
// provider is always rejected, never silently evaluated by another provider's
// logic.
func evaluatorFor(provider string) (cloudgraph.AuthorizationEvaluator, error) {
	switch provider {
	case "aws":
		return &cloudgraph.AWSEvaluator{}, nil
	case "azure":
		return &cloudgraph.AzureEvaluator{}, nil
	case "gcp":
		return &cloudgraph.GCPEvaluator{}, nil
	default:
		return nil, fmt.Errorf("cloudrun: unknown provider %q", provider)
	}
}

// validateEdgesMatchProvider rejects an edge whose Source/Target explicitly
// claims a different provider than the run is scoped to. A nil AccountScope
// makes no claim and is not a mismatch.
func validateEdgesMatchProvider(edges []*cloudgraph.CloudPermission, provider string) error {
	for _, edge := range edges {
		for _, scope := range []*cloudgraph.AccountScope{edge.Source.AccountScope, edge.Target.AccountScope} {
			if scope != nil && scope.Provider != "" && scope.Provider != provider {
				return fmt.Errorf("cloudrun: edge references provider %q, run is scoped to %q", scope.Provider, provider)
			}
		}
	}
	return nil
}

func newRunID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

// statusForPath maps a CloudPlan result to a cloud_runs status. ok=false is
// a confirmed no-path result -- a successfully completed search, not a
// failure or an incomplete one. Partial is reserved for a hop whose
// evaluation rode through an unresolved condition; none of today's three
// evaluators ever populate UnresolvedConds, so this branch is unreachable
// through ExecuteCloudPlanRun as currently wired -- it is still coded,
// correctly, against EvaluationResult's own documented meaning.
func statusForPath(path *cloudgraph.CloudPath, ok bool) cloudrun.Status {
	if !ok {
		return cloudrun.StatusCompleted
	}
	for _, hop := range path.Hops {
		if len(hop.Result.UnresolvedConds) > 0 {
			return cloudrun.StatusPartial
		}
	}
	return cloudrun.StatusCompleted
}

// ExecuteCloudPlanRun runs cloudgraph.CloudPlan for one account and records
// the outcome as a cloud_runs row. It is a plain Go function, not an HTTP
// handler -- a later sub-project decides how (or whether) this is exposed
// over the API.
func ExecuteCloudPlanRun(ctx context.Context, pool *pgxpool.Pool, req CloudPlanRunRequest) (*cloudrun.CloudRun, error) {
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

	evaluator, err := evaluatorFor(req.Account.Provider)
	if err != nil {
		_ = UpdateCloudRunStatus(ctx, pool, run.ID, cloudrun.StatusFailed, nil, err.Error())
		return nil, err
	}
	if err := validateEdgesMatchProvider(req.Edges, req.Account.Provider); err != nil {
		_ = UpdateCloudRunStatus(ctx, pool, run.ID, cloudrun.StatusFailed, nil, err.Error())
		return nil, err
	}

	path, ok := cloudgraph.CloudPlan(req.Edges, req.Held, req.Target, evaluator, &cloudgraph.RequestContext{}, req.MaxHops)

	resultJSON, marshalErr := json.Marshal(path)
	if marshalErr != nil {
		_ = UpdateCloudRunStatus(ctx, pool, run.ID, cloudrun.StatusFailed, nil, marshalErr.Error())
		return nil, marshalErr
	}

	status := statusForPath(path, ok)
	if err := UpdateCloudRunStatus(ctx, pool, run.ID, status, resultJSON, ""); err != nil {
		return nil, err
	}

	return GetCloudRun(ctx, pool, run.ID)
}
