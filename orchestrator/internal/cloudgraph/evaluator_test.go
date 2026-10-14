package cloudgraph

import (
	"testing"
)

// TestAuthorizationEvaluator_AllThreeProvidersSatisfyInterface is the capstone
// proof of the spec's core architectural promise: Layer A (CloudPermission)
// and Layer B (the AuthorizationEvaluator contract) are provider-agnostic, and
// only Layer C (each evaluator's internal logic) differs per provider. This
// test does NOT claim the providers have identical authorization semantics
// (they don't - that's the whole point of Layer C being separate) - it proves
// the CALLING CODE (anything holding an AuthorizationEvaluator) never needs
// to know which provider it's talking to.
func TestAuthorizationEvaluator_AllThreeProvidersSatisfyInterface(t *testing.T) {
	evaluators := []AuthorizationEvaluator{
		&AWSEvaluator{},
		&AzureEvaluator{},
		&GCPEvaluator{},
	}

	if len(evaluators) != 3 {
		t.Fatalf("Expected 3 evaluators satisfying AuthorizationEvaluator, got %d", len(evaluators))
	}

	// Each provider's own "allow" fixture, run through the SAME calling code
	// path (a loop over the interface type) -- the loop itself has no
	// provider-specific branches, proving the interface is sufficient.
	identity := &CloudIdentity{CanonicalID: "generic-identity"}
	resource := &CloudResource{CanonicalID: "generic-resource"}

	fixtures := []*CloudPermission{
		{ // AWS-shaped
			Source: identity, Target: resource, Action: "s3:GetObject", SourceType: "identity-policy",
			Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject"}]}`},
		},
		{ // Azure-shaped
			Source: identity, Target: resource, Action: "Microsoft.Storage/storageAccounts/read", SourceType: "role-assignment",
			Attributes: map[string]string{"role_scope": "generic-resource", "role_actions": "Microsoft.Storage/storageAccounts/read"},
		},
		{ // GCP-shaped
			Source: identity, Target: resource, Action: "storage.objects.get", SourceType: "iam-binding",
			Attributes: map[string]string{"binding_scope": "generic-resource", "binding_actions": "storage.objects.get"},
		},
	}

	for i, evaluator := range evaluators {
		result := evaluator.EvaluatePermission(fixtures[i], &RequestContext{})
		if result.State != PolicySupported {
			t.Errorf("Evaluator %d: expected PolicySupported on its own allow fixture, got %s", i, result.State)
		}
	}
}

// TestAuthorizationEvaluator_GenericCallerNeedsNoProviderBranch proves a
// caller written against the interface alone (no type switch, no provider
// field inspection) correctly dispatches to whichever evaluator it holds.
func TestAuthorizationEvaluator_GenericCallerNeedsNoProviderBranch(t *testing.T) {
	runGeneric := func(evaluator AuthorizationEvaluator, edge *CloudPermission) *EvaluationResult {
		// This function has zero knowledge of AWS/Azure/GCP -- it only calls
		// the interface method. If this compiles and works for all three
		// evaluators, the interface is doing its job.
		return evaluator.EvaluatePermission(edge, &RequestContext{})
	}

	identity := &CloudIdentity{CanonicalID: "generic-identity"}
	resource := &CloudResource{CanonicalID: "generic-resource"}
	awsEdge := &CloudPermission{
		Source: identity, Target: resource, Action: "s3:DeleteObject", SourceType: "identity-policy",
		Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Deny","Action":"s3:DeleteObject"}]}`},
	}

	result := runGeneric(&AWSEvaluator{}, awsEdge)
	if result.State != Blocked {
		t.Errorf("Expected Blocked via generic caller, got %s", result.State)
	}
}
