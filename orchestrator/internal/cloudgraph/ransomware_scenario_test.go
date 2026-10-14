package cloudgraph

import (
	"testing"
)

// buildRansomwareKillChain is shared fixture setup for the 3-step cloud
// storage ransomware kill chain: compromised user -> assumes privileged role
// -> deletes bucket objects (the encrypt/destroy stage).
func buildRansomwareKillChain(t *testing.T, roleAssumeAllowed, deleteAllowed bool) *CloudRansomwareScenario {
	t.Helper()

	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/compromised-user"}
	role := &CloudResource{CanonicalID: "arn:aws:iam::123456789012:role/backup-admin"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::critical-backups"}

	roleTrustPolicy := `{"Statement":[{"Effect":"Deny","Principal":{"AWS":"arn:aws:iam::123456789012:user/compromised-user"},"Action":"sts:AssumeRole"}]}`
	if roleAssumeAllowed {
		roleTrustPolicy = `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/compromised-user"},"Action":"sts:AssumeRole"}]}`
	}

	deletePolicy := `{"Statement":[{"Effect":"Deny","Action":"s3:DeleteObject"}]}`
	if deleteAllowed {
		deletePolicy = `{"Statement":[{"Effect":"Allow","Action":"s3:DeleteObject"}]}`
	}

	roleIdentity := &CloudIdentity{CanonicalID: role.CanonicalID}

	return &CloudRansomwareScenario{
		Steps: []*RansomwareStep{
			{
				Name:         "assume-privileged-role",
				TechniqueTag: "T1548",
				Edge: &CloudPermission{
					Source: user, Target: role, Action: "sts:AssumeRole", SourceType: "role-trust",
					Attributes: map[string]string{"policy_document": roleTrustPolicy},
				},
			},
			{
				Name:         "discover-storage-resource",
				TechniqueTag: "T1619",
				Edge: &CloudPermission{
					Source: roleIdentity, Target: bucket, Action: "s3:ListBucket", SourceType: "identity-policy",
					Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:ListBucket"}]}`},
				},
			},
			{
				Name:         "encrypt-delete-objects",
				TechniqueTag: "T1486",
				Edge: &CloudPermission{
					Source: roleIdentity, Target: bucket, Action: "s3:DeleteObject", SourceType: "identity-policy",
					Attributes: map[string]string{"policy_document": deletePolicy},
				},
			},
		},
		Evaluator: &AWSEvaluator{},
	}
}

// TestExecuteCloudRansomwareScenario_FullyBlocked verifies that when the
// FIRST step (role assumption) is blocked, the chain stops there -- later
// steps are never evaluated, and the verdict reflects the block at the right
// point, not a generic failure.
func TestExecuteCloudRansomwareScenario_FullyBlocked(t *testing.T) {
	scenario := buildRansomwareKillChain(t, false, true) // role assume denied

	graph := &DiscoveredGraph{Evaluations: map[string]PathState{}}
	result := ExecuteCloudRansomwareScenario(scenario, graph)

	if result.OverallVerdict != "fully-blocked" {
		t.Errorf("Expected fully-blocked, got %s", result.OverallVerdict)
	}
	if len(result.StepOutcomes) != 1 {
		t.Errorf("Expected exactly 1 step outcome (chain stops at first block), got %d", len(result.StepOutcomes))
	}
}

// TestExecuteCloudRansomwareScenario_FullyOpen verifies all steps succeeding
// produces fully-open, with every step represented in the outcome list.
func TestExecuteCloudRansomwareScenario_FullyOpen(t *testing.T) {
	scenario := buildRansomwareKillChain(t, true, true)

	graph := &DiscoveredGraph{Evaluations: map[string]PathState{}}
	result := ExecuteCloudRansomwareScenario(scenario, graph)

	if result.OverallVerdict != "fully-open" {
		t.Errorf("Expected fully-open, got %s", result.OverallVerdict)
	}
	if len(result.StepOutcomes) != 3 {
		t.Errorf("Expected 3 step outcomes (all steps run), got %d", len(result.StepOutcomes))
	}
}

// TestExecuteCloudRansomwareScenario_PartiallyBlocked verifies the middle
// case: role assumption AND discovery succeed, but the final destructive step
// is blocked -- this must report partially-blocked, identifying which step
// succeeded and which was stopped, never rounding to fully-blocked or fully-open.
func TestExecuteCloudRansomwareScenario_PartiallyBlocked(t *testing.T) {
	scenario := buildRansomwareKillChain(t, true, false) // assume+discover OK, delete denied

	graph := &DiscoveredGraph{Evaluations: map[string]PathState{}}
	result := ExecuteCloudRansomwareScenario(scenario, graph)

	if result.OverallVerdict != "partially-blocked" {
		t.Errorf("Expected partially-blocked, got %s", result.OverallVerdict)
	}
	if len(result.StepOutcomes) != 3 {
		t.Errorf("Expected 3 step outcomes (chain runs until the blocking step, inclusive), got %d", len(result.StepOutcomes))
	}
	if result.StepOutcomes[0].PrerequisiteState != PolicySupported {
		t.Error("Expected step 1 (assume-role) to be PolicySupported")
	}
	if result.StepOutcomes[2].PrerequisiteState != Blocked {
		t.Error("Expected step 3 (delete) to be Blocked")
	}
}

// TestExecuteCloudRansomwareScenario_StepGateUsesOwnEdgeNotPriorStep verifies
// each step's gate check evaluates THAT step's edge, not a cached result from
// an earlier step -- guards against the gate accidentally reusing state.
func TestExecuteCloudRansomwareScenario_StepGateUsesOwnEdgeNotPriorStep(t *testing.T) {
	scenario := buildRansomwareKillChain(t, true, false)

	// Pre-populate graph.Evaluations with a state keyed to step 1's edge only.
	// If the executor incorrectly checked a shared/stale key, step 2 (a
	// different edge) would be wrongly affected too.
	graph := &DiscoveredGraph{
		Evaluations: map[string]PathState{
			edgeKey(scenario.Steps[0].Edge): PolicySupported,
		},
	}

	result := ExecuteCloudRansomwareScenario(scenario, graph)

	if len(result.StepOutcomes) < 2 {
		t.Fatal("Expected at least 2 step outcomes")
	}
	if result.StepOutcomes[1].PrerequisiteState != PolicySupported {
		t.Errorf("Expected step 2 (discover) to be independently PolicySupported, got %s", result.StepOutcomes[1].PrerequisiteState)
	}
}
