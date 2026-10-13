package db_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudrun"
	"github.com/audspect/bas/internal/db"
)

func identity(canonicalID, kind string) *cloudgraph.CloudIdentity {
	return &cloudgraph.CloudIdentity{CanonicalID: canonicalID, Kind: kind}
}

func resource(canonicalID, kind string) *cloudgraph.CloudResource {
	return &cloudgraph.CloudResource{CanonicalID: canonicalID, Kind: kind}
}

// allowEdge returns a CloudPermission that AWSEvaluator evaluates to PolicySupported:
// an identity-policy with an explicit Allow statement for action, and SourceType
// "identity-policy" (not "role-trust", so principalMatches short-circuits to true).
func allowEdge(source *cloudgraph.CloudIdentity, target *cloudgraph.CloudResource, action string) *cloudgraph.CloudPermission {
	return &cloudgraph.CloudPermission{
		Source: source, Target: target, Action: action, SourceType: "identity-policy",
		Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"` + action + `"}]}`},
	}
}

// denyEdge returns a CloudPermission that AWSEvaluator evaluates to Blocked
// (explicit deny) for action.
func denyEdge(source *cloudgraph.CloudIdentity, target *cloudgraph.CloudResource, action string) *cloudgraph.CloudPermission {
	return &cloudgraph.CloudPermission{
		Source: source, Target: target, Action: action, SourceType: "identity-policy",
		Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Deny","Action":"` + action + `"}]}`},
	}
}

func TestExecuteCloudPlanRun_ValidPathFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		adminRole := resource("arn:aws:iam::111:role/admin", "iam-role")
		req := db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      []*cloudgraph.CloudPermission{allowEdge(alice, adminRole, "sts:AssumeRole")},
			Held:       []string{alice.CanonicalID},
			Target:     adminRole.CanonicalID,
			MaxHops:    3,
		}
		run, err := db.ExecuteCloudPlanRun(ctx, pool, req)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun: %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status: got %s want completed", run.Status)
		}
		var path cloudgraph.CloudPath
		if err := json.Unmarshal(run.Result, &path); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(path.Hops) != 1 {
			t.Fatalf("hops: got %d want 1", len(path.Hops))
		}
		if path.Hops[0].Result.State != cloudgraph.PolicySupported {
			t.Fatalf("hop state: got %s want policy_supported", path.Hops[0].Result.State)
		}
		if path.OverallState != cloudgraph.PolicySupported {
			t.Fatalf("overallState: got %s want policy_supported", path.OverallState)
		}
	})
}

func TestExecuteCloudPlanRun_NoPathFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		adminRole := resource("arn:aws:iam::111:role/admin", "iam-role")
		unreachable := resource("arn:aws:iam::111:role/unreachable", "iam-role")
		req := db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      []*cloudgraph.CloudPermission{allowEdge(alice, adminRole, "sts:AssumeRole")},
			Held:       []string{alice.CanonicalID},
			Target:     unreachable.CanonicalID,
			MaxHops:    3,
		}
		run, err := db.ExecuteCloudPlanRun(ctx, pool, req)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun: %v", err)
		}
		// A confirmed no-path result is a successfully completed search, not a
		// failure or an incomplete one -- see the spec's amendment.
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("status: got %s want completed", run.Status)
		}
		if string(run.Result) != "null" {
			t.Fatalf("result: got %s want null (no path confirmed)", run.Result)
		}
	})
}

func TestExecuteCloudPlanRun_InsertFailurePropagates(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		req := db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      nil,
			Held:       []string{"x"},
			Target:     "y",
			MaxHops:    1,
		}
		_, err := db.ExecuteCloudPlanRun(ctx, pool, req)
		if err == nil {
			t.Fatal("want non-nil error, got nil")
		}
	})
}
