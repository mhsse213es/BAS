package cloudpath

import (
	"fmt"

	"github.com/audspect/bas/internal/cloudgraph"
)

// CloudFindingCorrelation is purely additive context cited from a
// Cloud BAS IAM evaluation. It never changes a CloudPathResult's own
// State -- a report may say "this network path and this IAM finding
// both involve account X", never "therefore this IAM finding is more
// or less exploitable". Mirrors networkpath.CorroboratingEvidence's
// own additive-only discipline.
type CloudFindingCorrelation struct {
	Source  string `json:"source"` // "cloudgraph"
	Account string `json:"account"`
	Note    string `json:"note,omitempty"`
}

// CorrelateCloudFinding cites a Cloud BAS IAM evaluation result
// alongside a cloud path result when both reference the same
// account -- matching only on AccountScope, nothing deeper (no
// inference that the IAM path and the network path involve the same
// specific resource). Returns nil only when there is nothing to cite
// (a zero-value account), never when the finding is "uninteresting" --
// interest judgments belong to the report layer, not this function.
func CorrelateCloudFinding(path CloudPathResult, iamFinding cloudgraph.EvaluationResult, account cloudgraph.AccountScope) *CloudFindingCorrelation {
	if account == (cloudgraph.AccountScope{}) {
		return nil
	}
	return &CloudFindingCorrelation{
		Source:  "cloudgraph",
		Account: account.AccountID,
		Note:    fmt.Sprintf("cloud network path (%s) and IAM finding (%s) both reference account %s -- cited together, not merged", path.State, iamFinding.State, account.AccountID),
	}
}
