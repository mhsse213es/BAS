package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/cloudgraph"
	"github.com/audspect/bas/internal/cloudrun"
)

// TestStatusForPath_UnresolvedConditionYieldsPartial exercises a branch no
// real evaluator can trigger today (AWSEvaluator/AzureEvaluator/GCPEvaluator
// never populate EvaluationResult.UnresolvedConds) -- a hand-built
// EvaluationResult is the only way to prove this mapping logic is correct
// against the type's own documented meaning. See the spec's amendment.
func TestStatusForPath_UnresolvedConditionYieldsPartial(t *testing.T) {
	path := &cloudgraph.CloudPath{
		Hops: []*cloudgraph.CloudHop{
			{Result: &cloudgraph.EvaluationResult{State: cloudgraph.PolicySupported, UnresolvedConds: []string{"mfa-required"}}},
		},
		OverallState: cloudgraph.PolicySupported,
	}
	if got := statusForPath(path, true); got != cloudrun.StatusPartial {
		t.Fatalf("status: got %s want partial", got)
	}
}

func TestStatusForPath_NoPathFoundYieldsCompleted(t *testing.T) {
	if got := statusForPath(nil, false); got != cloudrun.StatusCompleted {
		t.Fatalf("status: got %s want completed", got)
	}
}

func TestStatusForPath_AllHopsResolvedYieldsCompleted(t *testing.T) {
	path := &cloudgraph.CloudPath{
		Hops:         []*cloudgraph.CloudHop{{Result: &cloudgraph.EvaluationResult{State: cloudgraph.PolicySupported}}},
		OverallState: cloudgraph.PolicySupported,
	}
	if got := statusForPath(path, true); got != cloudrun.StatusCompleted {
		t.Fatalf("status: got %s want completed", got)
	}
}

// TestEvaluatorFor_UnsupportedProviderIsRejected proves evaluatorFor's own
// rejection logic directly -- unreachable through ExecuteCloudPlanRun's
// actual call sequence today, since cloud_runs.provider's CHECK constraint
// rejects the same unsupported values at InsertCloudRun first. See the
// ruling in this plan's Task 3.
func TestEvaluatorFor_UnsupportedProviderIsRejected(t *testing.T) {
	if _, err := evaluatorFor("unknown"); err == nil {
		t.Fatal("want non-nil error, got nil")
	}
}

func TestEvaluatorFor_SupportedProvidersAreAccepted(t *testing.T) {
	for _, provider := range []string{"aws", "azure", "gcp"} {
		if _, err := evaluatorFor(provider); err != nil {
			t.Errorf("provider=%q: got error %v, want nil", provider, err)
		}
	}
}

// Both functions below live in package db, not cloudrun, after the Task 1
// import-cycle relocation -- their error messages must not claim the stale
// "cloudrun:" package prefix, which would mislead anyone grepping logs by
// package name.

func TestEvaluatorFor_ErrorMessageDoesNotClaimStalePackageName(t *testing.T) {
	_, err := evaluatorFor("unknown")
	if err == nil {
		t.Fatal("want non-nil error, got nil")
	}
	if strings.Contains(err.Error(), "cloudrun:") {
		t.Fatalf("error message %q still uses the stale cloudrun: package prefix", err.Error())
	}
}

func TestValidateEdgesMatchProvider_ErrorMessageDoesNotClaimStalePackageName(t *testing.T) {
	source := &cloudgraph.CloudIdentity{CanonicalID: "alice", Kind: "iam-user"}
	target := &cloudgraph.CloudResource{
		CanonicalID:  "azure-role",
		Kind:         "iam-role",
		AccountScope: &cloudgraph.AccountScope{Provider: "azure"},
	}
	edge := &cloudgraph.CloudPermission{Source: source, Target: target, Action: "sts:AssumeRole"}
	err := validateEdgesMatchProvider([]*cloudgraph.CloudPermission{edge}, "aws")
	if err == nil {
		t.Fatal("want non-nil error, got nil")
	}
	if strings.Contains(err.Error(), "cloudrun:") {
		t.Fatalf("error message %q still uses the stale cloudrun: package prefix", err.Error())
	}
}

// TestCurrentRunOrNil_ReturnsNilWhenTheRowCannotBeFetched is a hermetic unit
// test -- no live Postgres needed. pgxpool.New never connects eagerly (only
// the first query attempt does), so a pool pointed at an unreachable address
// is enough to force GetCloudRun's error path without a testcontainer. This
// package's internal test files cannot import internal/testutil for a real
// pool: testutil imports internal/db itself, so that import would be a
// genuine cycle (confirmed directly: `go vet` reports "import cycle not
// allowed in test" for exactly this). currentRunOrNil's happy path (a real
// row comes back) is already proven by
// TestExecuteCloudPlanRun_MismatchedProviderEdgeMarksRowFailed in
// cloudrun_executor_test.go (package db_test, which *can* reach a real
// pool) -- that test exercises this exact function via ExecuteCloudPlanRun's
// validateEdgesMatchProvider branch.
func TestCurrentRunOrNil_ReturnsNilWhenTheRowCannotBeFetched(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://nouser:nopass@127.0.0.1:1/nodb")
	if err != nil {
		t.Fatalf("construct pool: %v", err)
	}
	defer pool.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if got := currentRunOrNil(ctx, pool, "any-id"); got != nil {
		t.Fatalf("want nil when the row can't be fetched, got %+v", got)
	}
}
