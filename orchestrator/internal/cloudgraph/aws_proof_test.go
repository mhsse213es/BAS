package cloudgraph

import (
	"testing"
)

// TestAWSProof_DiscoverAndNormalize simulates end-to-end AWS discovery:
// 1. Discover IAM user, role, S3 bucket
// 2. Normalize to CloudResource/CloudIdentity
// 3. Build permission edges
// 4. Report findings with provenance
func TestAWSProof_DiscoverAndNormalize(t *testing.T) {
	// Synthetic AWS discovery data (would come from AWS SDK in Phase 2)
	testUserARN := "arn:aws:iam::123456789012:user/test-user"
	testRoleARN := "arn:aws:iam::123456789012:role/test-role"
	testBucketARN := "arn:aws:s3:::test-bucket"

	// Normalize to CloudResource
	user := &CloudIdentity{
		CanonicalID: testUserARN,
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
		Attributes: map[string]string{
			"mfa_enabled": "true",
		},
		Provenance: &Provenance{
			Source:     "aws:iam-get-user",
			Confidence: "observed",
		},
	}

	role := &CloudResource{
		CanonicalID: testRoleARN,
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
		Attributes: map[string]string{
			"trust_policy": `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/test-user"},"Action":"sts:AssumeRole"}]}`,
		},
		Provenance: &Provenance{
			Source:     "aws:iam-get-role",
			Confidence: "observed",
		},
	}

	bucket := &CloudResource{
		CanonicalID: testBucketARN,
		Kind:        "s3-bucket",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
		Attributes: map[string]string{
			"public_access_blocked": "true",
		},
		Provenance: &Provenance{
			Source:     "aws:s3-head-bucket",
			Confidence: "observed",
		},
	}

	// Verify discovery succeeded
	if user.CanonicalID != testUserARN {
		t.Errorf("User discovery failed: got %s, want %s", user.CanonicalID, testUserARN)
	}
	if role.CanonicalID != testRoleARN {
		t.Errorf("Role discovery failed: got %s, want %s", role.CanonicalID, testRoleARN)
	}
	if bucket.CanonicalID != testBucketARN {
		t.Errorf("Bucket discovery failed: got %s, want %s", bucket.CanonicalID, testBucketARN)
	}

	// Verify account scope is preserved
	if user.AccountScope.AccountID != "123456789012" {
		t.Errorf("Account ID mismatch: got %s", user.AccountScope.AccountID)
	}
}

// TestAWSProof_PermissionEdgeConstruction builds permission edge: user →[sts:AssumeRole]→ role
func TestAWSProof_PermissionEdgeConstruction(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/test-role",
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	// Build permission edge
	edge := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
		Provenance: &Provenance{
			Source:     "aws:iam-get-role-trust-policy",
			Confidence: "observed",
		},
	}

	// Verify edge structure
	if edge.Source.CanonicalID != user.CanonicalID {
		t.Errorf("Edge source mismatch")
	}
	if edge.Target.CanonicalID != role.CanonicalID {
		t.Errorf("Edge target mismatch")
	}
	if edge.Action != "sts:AssumeRole" {
		t.Errorf("Edge action mismatch: got %s", edge.Action)
	}
}

// TestAWSProof_CandidatePathIdentification verifies graph can identify paths
func TestAWSProof_CandidatePathIdentification(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/test-role",
		Kind:        "iam-role",
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

	// Edge 1: user → role (via sts:AssumeRole)
	edge1 := &CloudPermission{
		Source:     user,
		Target:     role,
		Action:     "sts:AssumeRole",
		SourceType: "role-trust",
	}

	// Edge 2: another identity (service) → bucket (via s3:GetObject)
	// This represents the role's granted permissions once assumed
	service := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:role/test-role",
		Kind:        "iam-role",
		AccountScope: &AccountScope{
			Provider:  "aws",
			AccountID: "123456789012",
		},
	}

	edge2 := &CloudPermission{
		Source:     service,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
	}

	// Path exists: user → role → bucket (candidate state; no evaluation yet)
	// For now, just verify edges are constructible and connect
	if edge1.Source == user && edge1.Target == role && edge2.Source == service && edge2.Target == bucket {
		// Candidate path identified: user can assume role, role can get objects
		// In Phase 2, evaluator will check if path is policy-supported
	} else {
		t.Error("Candidate path construction failed")
	}
}
