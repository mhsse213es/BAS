package cloudgraph

import (
	"testing"
	"time"
)

// TestE2E_UserAssumeRoleThenAccessBucket verifies full attack path detection and control assessment:
// attacker user -> assumes role (sts:AssumeRole) -> role reads sensitive bucket (s3:GetObject).
// Each hop is evaluated (Layer C), executed, and correlated against audit evidence.
func TestE2E_UserAssumeRoleThenAccessBucket(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/attacker",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/data-processor",
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::sensitive-data",
		Kind:        "s3-bucket",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	evaluator := &AWSEvaluator{}
	correlator := &SyntheticEventCorrelator{}
	actionTime := time.Now().UTC()

	// HOP 1: user -> role (sts:AssumeRole)
	edge1 := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/attacker"},"Action":"sts:AssumeRole"}]}`,
		},
	}

	result1 := evaluator.EvaluatePermission(edge1, &RequestContext{})
	if result1.State != PolicySupported {
		t.Fatalf("Expected user can assume role, got %s", result1.State)
	}

	correlator.addSyntheticEvent(&CloudEvent{
		Principal: user.CanonicalID,
		Action:    "sts:AssumeRole",
		Resource:  role.CanonicalID,
		Timestamp: actionTime.Add(1 * time.Second),
		Result:    "Success",
		Source:    "cloudtrail",
	})

	correlation1 := correlator.FindEvents(user.CanonicalID, "sts:AssumeRole", role.CanonicalID, actionTime, 30*time.Second)
	if correlation1.MatchQuality != "perfect" {
		t.Errorf("Expected perfect match for assume-role, got %s", correlation1.MatchQuality)
	}

	outcome1 := NewCloudControlOutcome(result1, correlation1, "S3RoleAssumeControl")
	if !outcome1.GraphVsExecutionMatch {
		t.Error("Expected prediction and execution to match for assume-role")
	}

	// HOP 2: assumed role -> bucket (s3:GetObject). Once assumed, the role acts as an identity.
	roleAsAssumedIdentity := &CloudIdentity{
		CanonicalID:  role.CanonicalID,
		Kind:         "iam-role",
		AccountScope: role.AccountScope,
	}

	edge2 := &CloudPermission{
		Source:     roleAsAssumedIdentity,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
		},
	}

	result2 := evaluator.EvaluatePermission(edge2, &RequestContext{})
	if result2.State != PolicySupported {
		t.Fatalf("Expected role can read bucket, got %s", result2.State)
	}

	correlator.addSyntheticEvent(&CloudEvent{
		Principal: roleAsAssumedIdentity.CanonicalID,
		Action:    "s3:GetObject",
		Resource:  bucket.CanonicalID,
		Timestamp: actionTime.Add(2 * time.Second),
		Result:    "Success",
		Source:    "cloudtrail",
	})

	correlation2 := correlator.FindEvents(roleAsAssumedIdentity.CanonicalID, "s3:GetObject", bucket.CanonicalID, actionTime, 30*time.Second)
	outcome2 := NewCloudControlOutcome(result2, correlation2, "S3ReadControl")
	if !outcome2.GraphVsExecutionMatch {
		t.Error("Expected prediction and execution to match for bucket read")
	}

	// VERIFY: full attack path detected (user can reach sensitive data), evidence corroborates each hop
	if result1.State != PolicySupported || result2.State != PolicySupported {
		t.Error("Attack path not detected (should show user->role->bucket is open)")
	}
	if outcome1.EventCorrelation != "perfect" || outcome2.EventCorrelation != "perfect" {
		t.Error("Evidence correlation failed for one or both hops")
	}
}

// TestE2E_BlockedHopStopsAttackPath verifies that a denied permission correctly
// breaks the chain — the graph must not report a path as open when one hop is Blocked.
func TestE2E_BlockedHopStopsAttackPath(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/limited-user",
		Kind:        "iam-user",
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/admin-role",
		Kind:        "iam-role",
	}

	evaluator := &AWSEvaluator{}

	// No trust policy granting this user AssumeRole -> implicit deny
	edge := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/someone-else"},"Action":"sts:AssumeRole"}]}`,
		},
	}

	result := evaluator.EvaluatePermission(edge, &RequestContext{})
	if result.State != Blocked {
		t.Fatalf("Expected Blocked (user not in trust policy), got %s", result.State)
	}

	// Evidence: CloudTrail shows a Failure (AWS denied the AssumeRole call)
	correlator := &SyntheticEventCorrelator{}
	actionTime := time.Now().UTC()
	correlator.addSyntheticEvent(&CloudEvent{
		Principal: user.CanonicalID,
		Action:    "sts:AssumeRole",
		Resource:  role.CanonicalID,
		Timestamp: actionTime.Add(1 * time.Second),
		Result:    "Failure",
	})

	correlation := correlator.FindEvents(user.CanonicalID, "sts:AssumeRole", role.CanonicalID, actionTime, 30*time.Second)
	outcome := NewCloudControlOutcome(result, correlation, "RoleAssumeControl")

	if !outcome.GraphVsExecutionMatch {
		t.Error("Expected Blocked prediction to match observed Failure")
	}
	if outcome.ExecutionOutcome != "Blocked" {
		t.Errorf("Expected Blocked outcome, got %s", outcome.ExecutionOutcome)
	}
}
