package cloudgraph

import (
	"testing"
)

// TestAzureEvaluator_SubscriptionScopeRoleInheritsToResourceGroup verifies that a
// role assignment at subscription scope grants access to a resource nested in a
// resource group under that subscription — Azure's scope-inheritance semantic,
// which has no AWS equivalent (AWS matches ARNs, not hierarchical scope).
func TestAzureEvaluator_SubscriptionScopeRoleInheritsToResourceGroup(t *testing.T) {
	identity := &CloudIdentity{
		CanonicalID: "/subscriptions/sub-1/users/alice",
		Kind:        "entra-user",
	}

	storageAccount := &CloudResource{
		CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1",
		Kind:        "storage-account",
	}

	edge := &CloudPermission{
		Source:     identity,
		Target:     storageAccount,
		Action:     "Microsoft.Storage/storageAccounts/read",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":      "/subscriptions/sub-1",
			"role_actions":    "Microsoft.Storage/storageAccounts/read,Microsoft.Storage/storageAccounts/write",
			"assignment_kind": "role-assignment",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != PolicySupported {
		t.Errorf("Expected PolicySupported (subscription scope inherits to RG resource), got %s", result.State)
	}
	if result.AllowedBy != "role-assignment" {
		t.Errorf("Expected AllowedBy=role-assignment, got %s", result.AllowedBy)
	}
}

// TestAzureEvaluator_ResourceGroupScopeDoesNotGrantSiblingResourceGroup verifies
// scope inheritance is downward-only: an RG-scoped role does not reach resources
// in a DIFFERENT resource group under the same subscription.
func TestAzureEvaluator_ResourceGroupScopeDoesNotGrantSiblingResourceGroup(t *testing.T) {
	identity := &CloudIdentity{CanonicalID: "/subscriptions/sub-1/users/alice"}

	resourceInOtherRG := &CloudResource{
		CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-other/providers/Microsoft.Storage/storageAccounts/sa2",
	}

	edge := &CloudPermission{
		Source:     identity,
		Target:     resourceInOtherRG,
		Action:     "Microsoft.Storage/storageAccounts/read",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":   "/subscriptions/sub-1/resourceGroups/rg-data",
			"role_actions": "Microsoft.Storage/storageAccounts/read",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked (RG-scoped role must not reach a sibling RG), got %s", result.State)
	}
}

// TestAzureEvaluator_DenyAssignmentOverridesRoleAssignment verifies Azure's
// explicit deny-assignment mechanism takes precedence over an otherwise-valid
// role assignment — distinct from AWS's statement-level Deny.
func TestAzureEvaluator_DenyAssignmentOverridesRoleAssignment(t *testing.T) {
	identity := &CloudIdentity{CanonicalID: "/subscriptions/sub-1/users/alice"}
	resource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}

	edge := &CloudPermission{
		Source:     identity,
		Target:     resource,
		Action:     "Microsoft.Storage/storageAccounts/delete",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":      "/subscriptions/sub-1",
			"role_actions":    "Microsoft.Storage/storageAccounts/delete",
			"deny_assignment": "true",
			"deny_scope":      "/subscriptions/sub-1/resourceGroups/rg-data",
			"deny_actions":    "Microsoft.Storage/storageAccounts/delete",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked (deny assignment overrides role assignment), got %s", result.State)
	}
	if result.BlockedBy != "deny-assignment" {
		t.Errorf("Expected BlockedBy=deny-assignment, got %s", result.BlockedBy)
	}
}

// TestAzureEvaluator_NoMatchingRoleReturnsImplicitDeny verifies default-deny
func TestAzureEvaluator_NoMatchingRoleReturnsImplicitDeny(t *testing.T) {
	identity := &CloudIdentity{CanonicalID: "/subscriptions/sub-1/users/bob"}
	resource := &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"}

	edge := &CloudPermission{
		Source:     identity,
		Target:     resource,
		Action:     "Microsoft.Storage/storageAccounts/delete",
		SourceType: "role-assignment",
		Attributes: map[string]string{
			"role_scope":   "/subscriptions/sub-1",
			"role_actions": "Microsoft.Storage/storageAccounts/read",
		},
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked (no role grants delete), got %s", result.State)
	}
	if result.BlockedBy != "implicit-deny" {
		t.Errorf("Expected BlockedBy=implicit-deny, got %s", result.BlockedBy)
	}
}
