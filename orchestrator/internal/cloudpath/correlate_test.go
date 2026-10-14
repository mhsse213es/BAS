package cloudpath

import (
	"testing"

	"github.com/audspect/bas/internal/cloudgraph"
)

// TestCorrelateCloudFinding_DemonstratesReportLayerCorrelation
// satisfies the spec's §2/§5.3 Definition-of-Done requirement: a
// report-layer example correlating a cloud-topology path result with
// a Cloud BAS IAM finding for the same account, without merging their
// verdicts -- built from a synthetic/fixture EvaluationResult, since
// the Cloud BAS Initiative itself is currently held with no live
// evaluation pipeline.
func TestCorrelateCloudFinding_DemonstratesReportLayerCorrelation(t *testing.T) {
	path := CloudPathResult{State: cloudgraph.PolicySupported}
	iamFinding := cloudgraph.EvaluationResult{State: cloudgraph.ConditionallyReachable, AllowedBy: "identity-policy"}
	account := cloudgraph.AccountScope{Provider: "aws", AccountID: "111122223333"}

	correlation := CorrelateCloudFinding(path, iamFinding, account)
	if correlation == nil {
		t.Fatal("want a non-nil correlation when an account is given")
	}
	if correlation.Source != "cloudgraph" {
		t.Fatalf("Source = %q, want %q", correlation.Source, "cloudgraph")
	}
	if correlation.Account != "111122223333" {
		t.Fatalf("Account = %q, want %q", correlation.Account, "111122223333")
	}
	// The correlation must never alter the path's own verdict -- it is
	// purely additive context.
	if path.State != cloudgraph.PolicySupported {
		t.Fatalf("path.State changed to %q -- correlation must never mutate the path's own State", path.State)
	}
}

func TestCorrelateCloudFinding_ZeroAccountScope_NilCorrelation(t *testing.T) {
	path := CloudPathResult{State: cloudgraph.Blocked}
	iamFinding := cloudgraph.EvaluationResult{State: cloudgraph.Blocked}
	if got := CorrelateCloudFinding(path, iamFinding, cloudgraph.AccountScope{}); got != nil {
		t.Fatalf("got %v, want nil for a zero-value account scope -- nothing to cite", got)
	}
}
