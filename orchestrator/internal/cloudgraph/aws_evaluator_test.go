package cloudgraph

import (
	"testing"
)

// TestAWSEvaluator_AllowedByIdentityPolicy verifies user has permission via inline policy
func TestAWSEvaluator_AllowedByIdentityPolicy(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::test-bucket",
		Kind:        "s3-bucket",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	// User has s3:GetObject via inline policy
	edge := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::test-bucket/*"}]}`,
		},
	}

	evaluator := &AWSEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != PolicySupported {
		t.Errorf("Expected PolicySupported, got %s", result.State)
	}
	if result.AllowedBy != "identity-policy" {
		t.Errorf("Expected AllowedBy=identity-policy, got %s", result.AllowedBy)
	}
}

// TestAWSEvaluator_BlockedByExplicitDeny verifies explicit Deny takes precedence
func TestAWSEvaluator_BlockedByExplicitDeny(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/restricted-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::protected-bucket",
		Kind:        "s3-bucket",
	}

	// Explicit Deny in user policy
	edge := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:DeleteObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`,
		},
	}

	evaluator := &AWSEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked, got %s", result.State)
	}
	if result.BlockedBy != "explicit-deny" {
		t.Errorf("Expected BlockedBy=explicit-deny, got %s", result.BlockedBy)
	}
}

// TestAWSEvaluator_ImplicitDenyWhenNoMatchingStatement verifies default deny
func TestAWSEvaluator_ImplicitDenyWhenNoMatchingStatement(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/no-permissions-user",
		Kind:        "iam-user",
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::other-bucket",
		Kind:        "s3-bucket",
	}

	edge := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:PutObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		},
	}

	evaluator := &AWSEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != Blocked {
		t.Errorf("Expected Blocked (implicit deny), got %s", result.State)
	}
	if result.BlockedBy != "implicit-deny" {
		t.Errorf("Expected BlockedBy=implicit-deny, got %s", result.BlockedBy)
	}
}

// TestAWSEvaluator_RoleTrustAllowsAssumeRole verifies role-trust policy evaluation
func TestAWSEvaluator_RoleTrustAllowsAssumeRole(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/test-role",
		Kind:        "iam-role",
	}

	edge := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/test-user"},"Action":"sts:AssumeRole"}]}`,
		},
	}

	evaluator := &AWSEvaluator{}
	result := evaluator.EvaluatePermission(edge, &RequestContext{})

	if result.State != PolicySupported {
		t.Errorf("Expected PolicySupported for role trust, got %s", result.State)
	}
	if result.AllowedBy != "role-trust" {
		t.Errorf("Expected AllowedBy=role-trust, got %s", result.AllowedBy)
	}
}

func TestAWSEvaluator_ActionNameIsMatchedWholeNotAsSubstring(t *testing.T) {
	edge := &CloudPermission{
		Source: &CloudIdentity{CanonicalID: "arn:aws:iam::1:user/u"},
		Target: &CloudResource{CanonicalID: "arn:aws:s3:::b/k"},
		Action: "s3:GetObject", SourceType: "identity-policy",
		Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObjectAcl","Resource":"*"}]}`},
	}
	if got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{}); got.State == PolicySupported {
		t.Error("an Allow for s3:GetObjectAcl must not satisfy s3:GetObject")
	}
}

func TestAWSEvaluator_ServiceWildcardSatisfiesConcreteAction(t *testing.T) {
	edge := &CloudPermission{
		Source: &CloudIdentity{CanonicalID: "arn:aws:iam::1:user/u"},
		Target: &CloudResource{CanonicalID: "arn:aws:s3:::b/k"},
		Action: "s3:GetObject", SourceType: "identity-policy",
		Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`},
	}
	if got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{}); got.State != PolicySupported {
		t.Errorf("s3:* should satisfy s3:GetObject, got %s", got.State)
	}
}
