package cloudgraph

import "strings"

// AzureEvaluator implements authorization evaluation for Azure RBAC.
// Independent from AWSEvaluator: Azure's scope-inheritance and deny-assignment
// semantics have no AWS equivalent, so this is a separate implementation, not
// a shared one parameterized by provider.
type AzureEvaluator struct{}

// EvaluatePermission determines if a permission edge is allowed, denied, or
// conditional under Azure RBAC. Evaluation order: a matching deny assignment
// always wins, then a role assignment whose scope covers the target and whose
// actions include the requested action, else implicit deny.
func (e *AzureEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	if isDenyAssignmentMatch(edge) {
		return &EvaluationResult{
			State:            Blocked,
			BlockedBy:        "deny-assignment",
			EvaluationMethod: "hand-coded-rules",
		}
	}

	if isRoleAssignmentMatch(edge) {
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

// isDenyAssignmentMatch checks for a deny assignment whose scope covers the
// target and whose actions include the requested action.
func isDenyAssignmentMatch(edge *CloudPermission) bool {
	if edge.Attributes["deny_assignment"] != "true" {
		return false
	}
	denyScope := edge.Attributes["deny_scope"]
	denyActions := edge.Attributes["deny_actions"]
	return scopeCovers(denyScope, edge.Target.CanonicalID) && actionListContains(denyActions, edge.Action)
}

// isRoleAssignmentMatch checks for a role assignment whose scope covers the
// target and whose actions include the requested action.
func isRoleAssignmentMatch(edge *CloudPermission) bool {
	roleScope, hasScope := edge.Attributes["role_scope"]
	roleActions, hasActions := edge.Attributes["role_actions"]
	if !hasScope || !hasActions {
		return false
	}
	return scopeCovers(roleScope, edge.Target.CanonicalID) && actionListContains(roleActions, edge.Action)
}

// scopeCovers reports whether a role/deny assignment scope covers a target
// resource ID. Azure scope inheritance is prefix-based and downward-only:
// "/subscriptions/sub-1" covers everything under it; "/subscriptions/sub-1/
// resourceGroups/rg-data" covers only resources in that resource group, never
// a sibling resource group even under the same subscription.
func scopeCovers(scope, resourceID string) bool {
	if scope == "" {
		return false
	}
	return strings.HasPrefix(resourceID, scope+"/") || resourceID == scope
}

// actionListContains checks a comma-separated action list for an exact action match.
func actionListContains(actionList, action string) bool {
	for _, a := range strings.Split(actionList, ",") {
		if strings.TrimSpace(a) == action {
			return true
		}
	}
	return false
}
