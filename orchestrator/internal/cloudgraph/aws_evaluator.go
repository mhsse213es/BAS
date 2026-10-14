package cloudgraph

import "strings"

// AWSEvaluator implements authorization evaluation for AWS IAM policies.
// Phase 2: hand-coded statement matching. Phase 3+: full IAM simulator with
// conditions, organization SCPs, and resource-policy intersection.
type AWSEvaluator struct{}

// EvaluatePermission determines if a permission edge is allowed, denied, or conditional.
// AWS evaluation order: explicit Deny always wins, then explicit Allow, else implicit deny.
func (e *AWSEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	policyDoc, hasPolicy := edge.Attributes["policy_document"]

	if hasPolicy && hasDenyStatement(policyDoc, edge.Action) {
		return &EvaluationResult{
			State:            Blocked,
			BlockedBy:        "explicit-deny",
			AllowedBy:        "none",
			EvaluationMethod: "hand-coded-rules",
		}
	}

	if hasPolicy && hasAllowStatement(policyDoc, edge.Action) && principalMatches(edge, policyDoc) {
		return &EvaluationResult{
			State:            PolicySupported,
			AllowedBy:        edge.SourceType,
			EvaluationMethod: "hand-coded-rules",
		}
	}

	return &EvaluationResult{
		State:            Blocked,
		BlockedBy:        "implicit-deny",
		EvaluationMethod: "hand-coded-rules",
	}
}

// hasDenyStatement checks if policy has an explicit Deny for the action
func hasDenyStatement(policyDoc, action string) bool {
	return strings.Contains(policyDoc, `"Effect":"Deny"`) && strings.Contains(policyDoc, action)
}

// hasAllowStatement checks if policy has an Allow for the action
func hasAllowStatement(policyDoc, action string) bool {
	return strings.Contains(policyDoc, `"Effect":"Allow"`) && strings.Contains(policyDoc, action)
}

// principalMatches verifies that role-trust policies name the requesting identity as Principal.
// Non-trust policies (identity-policy, resource-policy) have no Principal clause to check here.
func principalMatches(edge *CloudPermission, policyDoc string) bool {
	if edge.SourceType != "role-trust" {
		return true
	}
	return strings.Contains(policyDoc, edge.Source.CanonicalID)
}
