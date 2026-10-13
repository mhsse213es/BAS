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

func TestExecuteCloudPlanRun_BlockedEdgeDoesNotPreventPathViaAnotherEdge(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		deniedRole := resource("arn:aws:iam::111:role/denied", "iam-role")
		adminRole := resource("arn:aws:iam::111:role/admin", "iam-role")
		req := db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges: []*cloudgraph.CloudPermission{
				denyEdge(alice, deniedRole, "sts:AssumeRole"),
				allowEdge(alice, adminRole, "sts:AssumeRole"),
			},
			Held:    []string{alice.CanonicalID},
			Target:  adminRole.CanonicalID,
			MaxHops: 3,
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
			t.Fatalf("hops: got %d want 1 (the blocked edge must not appear)", len(path.Hops))
		}
		if path.Hops[0].Edge.Target.CanonicalID != adminRole.CanonicalID {
			t.Fatalf("hop target: got %s want %s", path.Hops[0].Edge.Target.CanonicalID, adminRole.CanonicalID)
		}
		if path.Hops[0].Result.State != cloudgraph.PolicySupported {
			t.Fatalf("hop state: got %s want policy_supported", path.Hops[0].Result.State)
		}
	})
}

func TestExecuteCloudPlanRun_MaxHopsIsPlumbedThroughNotHardcoded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		alice := identity("arn:aws:iam::111:user/alice", "iam-user")
		middleRole := identity("arn:aws:iam::111:role/middle", "iam-role")
		middleResource := resource("arn:aws:iam::111:role/middle", "iam-role")
		targetRole := resource("arn:aws:iam::111:role/target", "iam-role")
		// Edges are listed in REVERSE dependency order on purpose: CloudPlan tries
		// edges in slice order within a single pass, and a legitimate hop can
		// advance reachedAsSource mid-pass -- if hop2 (middle->target) were listed
		// BEFORE hop1 (alice->middle), a single pass could cascade through both
		// hops at once, making MaxHops=1 behave identically to MaxHops=5 and
		// proving nothing. Listing hop2 first means pass 1 tries hop2 while
		// "middle" is not yet a reachable source, so only hop1 advances in pass 1.
		edges := []*cloudgraph.CloudPermission{
			allowEdge(middleRole, targetRole, "sts:AssumeRole"), // hop2
			allowEdge(alice, middleResource, "sts:AssumeRole"),  // hop1
		}
		reqOneHop := db.CloudPlanRunRequest{
			ScenarioID: "test-scenario",
			Account:    cloudgraph.AccountScope{Provider: "aws", AccountID: "111"},
			Edges:      edges,
			Held:       []string{alice.CanonicalID},
			Target:     targetRole.CanonicalID,
			MaxHops:    1,
		}
		run, err := db.ExecuteCloudPlanRun(ctx, pool, reqOneHop)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun (MaxHops=1): %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("MaxHops=1 status: got %s want completed", run.Status)
		}
		if string(run.Result) != "null" {
			t.Fatalf("MaxHops=1 result: got %s want null (hop budget exhausted before reaching target)", run.Result)
		}

		reqFiveHops := reqOneHop
		reqFiveHops.MaxHops = 5
		run, err = db.ExecuteCloudPlanRun(ctx, pool, reqFiveHops)
		if err != nil {
			t.Fatalf("ExecuteCloudPlanRun (MaxHops=5): %v", err)
		}
		if run.Status != cloudrun.StatusCompleted {
			t.Fatalf("MaxHops=5 status: got %s want completed", run.Status)
		}
		var path cloudgraph.CloudPath
		if err := json.Unmarshal(run.Result, &path); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(path.Hops) != 2 {
			t.Fatalf("MaxHops=5 hops: got %d want 2", len(path.Hops))
		}
		if path.Hops[0].Edge.Target.CanonicalID != middleResource.CanonicalID {
			t.Fatalf("hop 0 target: got %s want %s", path.Hops[0].Edge.Target.CanonicalID, middleResource.CanonicalID)
		}
		if path.Hops[1].Edge.Target.CanonicalID != targetRole.CanonicalID {
			t.Fatalf("hop 1 target: got %s want %s", path.Hops[1].Edge.Target.CanonicalID, targetRole.CanonicalID)
		}
		if path.Hops[0].Result.State != cloudgraph.PolicySupported || path.Hops[1].Result.State != cloudgraph.PolicySupported {
			t.Fatalf("hop states: got %s/%s want policy_supported/policy_supported", path.Hops[0].Result.State, path.Hops[1].Result.State)
		}
	})
}
