package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
)

// bareDiscoverer discovers but cannot be preflighted.
type bareDiscoverer struct{ called bool }

func (b *bareDiscoverer) Discover(context.Context) (*cloudgraph.DiscoveredGraph, cloudgraph.DiscoveryReport, error) {
	b.called = true
	return &cloudgraph.DiscoveredGraph{}, cloudgraph.DiscoveryReport{}, nil
}

var failingPreflight = []cloudgraph.PreflightCheck{
	{Name: "sts-identity", Status: "PASS", Detail: "caller identity is readable"},
	{Name: "iam-authorization-details", Status: "FAIL", Detail: "authorization details not readable (needs iam:GetAccountAuthorizationDetails)"},
}

func TestExecuteCloudPlanRun_PreflightFailureBlocksDiscovery(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &fakeDiscoverer{graph: &cloudgraph.DiscoveredGraph{}, preflight: failingPreflight}
		run, err := db.ExecuteCloudPlanRun(context.Background(), pool, db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Target:     "arn:aws:iam::111:role/admin",
			MaxHops:    3,
			Discoverer: disc,
		})
		if disc.called {
			t.Fatal("discovery ran although preflight failed")
		}
		if err == nil || !strings.Contains(err.Error(), "iam:GetAccountAuthorizationDetails") {
			t.Fatalf("err = %v, want the failed check named", err)
		}
		if run.Status != cloudrun.StatusFailed {
			t.Fatalf("status = %s, want failed", run.Status)
		}
	})
}

func TestExecuteCloudScenarioRun_PreflightFailureBlocksDiscovery(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &fakeDiscoverer{graph: scenarioGraph("backup:ListRecoveryPointsByBackupVault"), preflight: failingPreflight}
		run, err := db.ExecuteCloudScenarioRun(context.Background(), pool, scenarioRunReq(disc))
		if disc.called {
			t.Fatal("discovery ran although preflight failed")
		}
		if err == nil || !strings.Contains(err.Error(), "preflight failed") {
			t.Fatalf("err = %v, want a preflight failure", err)
		}
		if run.Status != cloudrun.StatusFailed {
			t.Fatalf("status = %s, want failed", run.Status)
		}
	})
}

// A SKIPPED check is not a failure: the optional client is unconfigured by
// design, and the run goes ahead. The checks are kept on the stored result.
func TestExecuteCloudPlanRun_SkippedCheckDoesNotBlockAndIsRecorded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &fakeDiscoverer{graph: &cloudgraph.DiscoveredGraph{}, preflight: []cloudgraph.PreflightCheck{
			{Name: "organizations-readable", Status: "SKIPPED", Detail: "no Organizations client configured"},
		}}
		run, err := db.ExecuteCloudPlanRun(context.Background(), pool, db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Target:     "arn:aws:iam::111:role/admin",
			MaxHops:    3,
			Discoverer: disc,
		})
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun: %v", err)
		}
		if !disc.called {
			t.Fatal("discovery did not run after a skipped check")
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status = %s, want completed", run.Status)
		}
		if !strings.Contains(string(run.Result), "organizations-readable") {
			t.Errorf("stored result does not record the preflight checks: %s", run.Result)
		}
	})
}

// A source that cannot be preflighted is refused, so discovery never runs unchecked.
func TestExecuteCloudPlanRun_UnpreflightableSourceRefused(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		disc := &bareDiscoverer{}
		run, err := db.ExecuteCloudPlanRun(context.Background(), pool, db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Target:     "arn:aws:iam::111:role/admin",
			MaxHops:    3,
			Discoverer: disc,
		})
		if disc.called {
			t.Fatal("an unpreflightable source ran discovery")
		}
		if err == nil || !strings.Contains(err.Error(), "cannot be preflighted") {
			t.Fatalf("err = %v, want the refusal", err)
		}
		if run.Status != cloudrun.StatusFailed {
			t.Fatalf("status = %s, want failed", run.Status)
		}
	})
}
