package cloudgraph

import "strings"

// GCPEvaluator implements authorization evaluation for GCP IAM. Independent
// from AWSEvaluator/AzureEvaluator: GCP's resource hierarchy has an extra
// level (organizations -> folders -> projects -> resource) and its own Deny
// policy mechanism, neither of which maps onto AWS or Azure semantics.
//
// Known limitation (Phase 5): scope coverage is prefix-matched against
// CanonicalID strings, the same approach AzureEvaluator uses. This resolves
// organization-to-project-resource and project-to-resource correctly when the
// CanonicalID literally embeds the parent path (as in these fixtures), but it
// cannot resolve folder membership, since a project's CanonicalID does not
// embed its folder ID without a real resource-hierarchy lookup. A real GCP
// integration needs the Cloud Resource Manager hierarchy API for that; this
// evaluator does not model it and documents the gap via
// TestGCPEvaluator_FolderScopeInheritsToProjectUnderIt.
type GCPEvaluator struct{}

// gcpBindingCondition names the unresolved IAM condition on a conditional binding.
const gcpBindingCondition = "gcp-binding-condition"

// gcpDenyCondition names the unresolved condition on a deny rule.
const gcpDenyCondition = "gcp-deny-condition"

// EvaluatePermission determines if a permission edge is allowed, denied, or
// conditional under GCP IAM. Evaluation order: a matching Deny policy always
// wins, then a binding whose scope covers the target and whose actions
// include the requested action, else implicit deny.
func (e *GCPEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	// An unconditional deny blocks outright.
	if isGCPDenyPolicyMatch(edge) {
		return &EvaluationResult{
			State:            Blocked,
			BlockedBy:        "deny-policy",
			EvaluationMethod: "hand-coded-rules",
		}
	}

	if isGCPBindingMatch(edge) {
		// Each condition that may stop the grant is named. Conditions are not
		// evaluated: a conditional binding may not grant, and a conditional deny
		// may not apply.
		var conds []string
		if edge.Attributes["binding_condition"] == "true" {
			conds = append(conds, gcpBindingCondition)
		}
		if isGCPConditionalDenyMatch(edge) {
			conds = append(conds, gcpDenyCondition)
		}
		if len(conds) > 0 {
			return &EvaluationResult{
				State:            ConditionallyReachable,
				AllowedBy:        edge.SourceType,
				UnresolvedConds:  conds,
				EvaluationMethod: "hand-coded-rules",
			}
		}
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

func isGCPDenyPolicyMatch(edge *CloudPermission) bool {
	if edge.Attributes["deny_policy"] != "true" {
		return false
	}
	denyScope := edge.Attributes["deny_scope"]
	denyActions := edge.Attributes["deny_actions"]
	return gcpScopeCovers(denyScope, edge.Target.CanonicalID) && actionListContains(denyActions, edge.Action)
}

// isGCPConditionalDenyMatch reports whether a conditional deny rule applies to the
// edge's action on its target. The rule may not apply, since its condition is not
// evaluated.
func isGCPConditionalDenyMatch(edge *CloudPermission) bool {
	if edge.Attributes["deny_policy"] != "true" {
		return false
	}
	denyScope := edge.Attributes["deny_scope"]
	return gcpScopeCovers(denyScope, edge.Target.CanonicalID) && actionListContains(edge.Attributes["deny_conditional_actions"], edge.Action)
}

func isGCPBindingMatch(edge *CloudPermission) bool {
	bindingScope, hasScope := edge.Attributes["binding_scope"]
	bindingActions, hasActions := edge.Attributes["binding_actions"]
	if !hasScope || !hasActions {
		return false
	}
	return gcpScopeCovers(bindingScope, edge.Target.CanonicalID) && actionListContains(bindingActions, edge.Action)
}

// gcpScopeCovers reports whether a binding/deny scope covers a target
// resource ID, using the same prefix-based approach as AzureEvaluator's
// scopeCovers. See the GCPEvaluator doc comment for the folder-membership
// limitation this implies.
func gcpScopeCovers(scope, resourceID string) bool {
	if scope == "" {
		return false
	}
	return strings.HasPrefix(resourceID, scope+"/") || resourceID == scope
}
