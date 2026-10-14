package cloudgraph

// AuthorizationEvaluator is Layer C's contract: given a permission edge and a
// request context, decide its authorization state. AWSEvaluator,
// AzureEvaluator, and GCPEvaluator each implement this independently -- the
// interface exists so that Layer A (CloudPermission) and Layer B (graph
// traversal, prerequisite resolution) never need to know which provider they
// are evaluating against. See the spec's critical boundary: a shared edge
// type must not imply shared authorization meaning -- this interface shares
// the CALLING CONTRACT, never the evaluation logic itself.
type AuthorizationEvaluator interface {
	EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult
}
