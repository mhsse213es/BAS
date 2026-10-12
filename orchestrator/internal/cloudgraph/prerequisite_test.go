package cloudgraph

import (
	"testing"
)

// TestPrerequisiteResolver_ResourceFoundReturnsOK verifies a discovered resource satisfies its prerequisite
func TestPrerequisiteResolver_ResourceFoundReturnsOK(t *testing.T) {
	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::test-bucket",
		Kind:        "s3-bucket",
	}

	graph := &DiscoveredGraph{
		Resources: []*CloudResource{bucket},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_resource",
		Target: "arn:aws:s3:::test-bucket",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}
	if results[0].Status != "OK" {
		t.Errorf("Expected OK, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_ResourceMissingReturnsMissing verifies absent resource is reported
func TestPrerequisiteResolver_ResourceMissingReturnsMissing(t *testing.T) {
	graph := &DiscoveredGraph{
		Resources: []*CloudResource{},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_resource",
		Target: "arn:aws:s3:::nonexistent-bucket",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "MISSING" {
		t.Errorf("Expected MISSING, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_IdentityFoundReturnsOK verifies identity prerequisite satisfaction
func TestPrerequisiteResolver_IdentityFoundReturnsOK(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/test-user",
		Kind:        "iam-user",
	}

	graph := &DiscoveredGraph{
		Identities: []*CloudIdentity{user},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_identity",
		Target: "arn:aws:iam::123456789012:user/test-user",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "OK" {
		t.Errorf("Expected OK, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_PermissionFoundButBlockedReturnsDegraded verifies DEGRADED
// when the permission edge exists but evaluates to Blocked (scenario could still run,
// but the attack path it validates is known-closed — operator should know before dispatch).
func TestPrerequisiteResolver_PermissionFoundButBlockedReturnsDegraded(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/test-user"}
	role := &CloudResource{CanonicalID: "arn:aws:iam::123456789012:role/test-role"}

	edge := &CloudPermission{
		Source: user,
		Target: role,
		Action: "sts:AssumeRole",
	}

	graph := &DiscoveredGraph{
		Identities:  []*CloudIdentity{user},
		Resources:   []*CloudResource{role},
		Permissions: []*CloudPermission{edge},
		Evaluations: map[string]PathState{
			"arn:aws:iam::123456789012:user/test-user->sts:AssumeRole->arn:aws:iam::123456789012:role/test-role": Blocked,
		},
	}

	prereq := &CloudPrerequisite{
		Kind:   "cloud_permission",
		Target: "arn:aws:iam::123456789012:user/test-user->sts:AssumeRole->arn:aws:iam::123456789012:role/test-role",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "DEGRADED" {
		t.Errorf("Expected DEGRADED, got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_AuditUnavailableReturnsUnknown verifies UNKNOWN is distinct from MISSING
func TestPrerequisiteResolver_AuditUnavailableReturnsUnknown(t *testing.T) {
	graph := &DiscoveredGraph{
		AuditAvailability: map[string]string{
			"cloudtrail": "unavailable",
		},
	}

	prereq := &CloudPrerequisite{
		Kind:   "audit_availability",
		Target: "cloudtrail",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "UNKNOWN" {
		t.Errorf("Expected UNKNOWN (not MISSING), got %s", results[0].Status)
	}
}

// TestPrerequisiteResolver_UnrecognizedKindReturnsUnknown verifies the resolver never
// silently treats an unrecognized prerequisite kind as satisfied.
func TestPrerequisiteResolver_UnrecognizedKindReturnsUnknown(t *testing.T) {
	graph := &DiscoveredGraph{}

	prereq := &CloudPrerequisite{
		Kind:   "some_future_kind",
		Target: "whatever",
	}

	resolver := &PrerequisiteResolver{}
	results := resolver.Resolve([]*CloudPrerequisite{prereq}, graph)

	if results[0].Status != "UNKNOWN" {
		t.Errorf("Expected UNKNOWN for unrecognized kind, got %s", results[0].Status)
	}
}
