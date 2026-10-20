package db_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
)

// fakeDiscoverer returns a fixed graph, or a fixed error, and records that it ran.
type fakeDiscoverer struct {
	graph  *cloudgraph.DiscoveredGraph
	err    error
	called bool
	// preflight, when set, is returned by Preflight. Nil means every check passes.
	preflight []cloudgraph.PreflightCheck
}

func (f *fakeDiscoverer) Preflight(context.Context) []cloudgraph.PreflightCheck {
	if f.preflight != nil {
		return f.preflight
	}
	return []cloudgraph.PreflightCheck{{Name: "fake", Status: "PASS", Detail: "ok"}}
}

func (f *fakeDiscoverer) Discover(context.Context) (*cloudgraph.DiscoveredGraph, cloudgraph.DiscoveryReport, error) {
	f.called = true
	if f.err != nil {
		return nil, nil, f.err
	}
	return f.graph, cloudgraph.DiscoveryReport{"items_found": len(f.graph.Permissions)}, nil
}

func TestExecuteCloudPlanRun_DiscoveredGraphDrivesPath(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		adminRole := resource("arn:aws:iam::111:role/admin", "iam-role")
		disc := &fakeDiscoverer{graph: &cloudgraph.DiscoveredGraph{
			Identities:  []*cloudgraph.CloudIdentity{alice},
			Resources:   []*cloudgraph.CloudResource{adminRole},
			Permissions: []*cloudgraph.CloudPermission{allowEdge(alice, adminRole, "sts:AssumeRole")},
		}}
		req := db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Held:       []string{alice.CanonicalID},
			Target:     adminRole.CanonicalID,
			MaxHops:    3,
			Discoverer: disc,
		}
		run, err := db.ExecuteCloudPlanRun(ctx, pool, req)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun: %v", err)
		}
		if !disc.called {
			t.Fatal("discoverer was not invoked")
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status = %s, want completed", run.Status)
		}
		var result struct {
			Path       *cloudgraph.CloudPath `json:"path"`
			Discovered bool                  `json:"discovered"`
			Counts     struct {
				Permissions int `json:"permissions"`
			} `json:"counts"`
		}
		if err := json.Unmarshal(run.Result, &result); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if !result.Discovered || result.Counts.Permissions != 1 {
			t.Errorf("result should record the discovered graph, got %+v", result)
		}
		if result.Path == nil || len(result.Path.Hops) != 1 {
			t.Fatalf("expected a one-hop path from the discovered edges, got %+v", result.Path)
		}
	})
}

func TestExecuteCloudPlanRun_DiscoveryFailureMarksRowFailed(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &fakeDiscoverer{err: errors.New("iam listing failed")}
		req := db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Held:       []string{"arn:aws:iam::111:user/alice"},
			Target:     "arn:aws:iam::111:role/admin",
			MaxHops:    3,
			Discoverer: disc,
		}
		run, err := db.ExecuteCloudPlanRun(context.Background(), pool, req)
		if err == nil {
			t.Fatal("a failed discovery pass must return an error")
		}
		if run == nil || run.Status != cloudrun.StatusFailed {
			t.Fatalf("row should be failed, got %+v", run)
		}
		if !strings.Contains(run.Error, "iam listing failed") {
			t.Errorf("failure reason not recorded: %q", run.Error)
		}
	})
}
