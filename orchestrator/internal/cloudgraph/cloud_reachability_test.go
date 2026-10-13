package cloudgraph

import "testing"

func TestWorstState_AllPolicySupported(t *testing.T) {
	got := worstState([]PathState{PolicySupported, PolicySupported})
	if got != PolicySupported {
		t.Errorf("Expected PolicySupported, got %s", got)
	}
}

func TestWorstState_AnyBlockedWins(t *testing.T) {
	got := worstState([]PathState{PolicySupported, Blocked, Observed})
	if got != Blocked {
		t.Errorf("Expected Blocked, got %s", got)
	}
}

func TestWorstState_UnknownWithoutBlocked(t *testing.T) {
	got := worstState([]PathState{PolicySupported, Unknown})
	if got != Unknown {
		t.Errorf("Expected Unknown, got %s", got)
	}
}

func TestWorstState_BlockedBeatsUnknownWhenBothPresent(t *testing.T) {
	got := worstState([]PathState{Unknown, Blocked})
	if got != Blocked {
		t.Errorf("Expected Blocked to beat Unknown, got %s", got)
	}
}

func TestWorstState_AllObserved(t *testing.T) {
	got := worstState([]PathState{Observed, Observed})
	if got != Observed {
		t.Errorf("Expected Observed, got %s", got)
	}
}

func TestWorstState_EmptySliceDefaultsToPolicySupported(t *testing.T) {
	got := worstState(nil)
	if got != PolicySupported {
		t.Errorf("Expected PolicySupported for empty input, got %s", got)
	}
}

func TestCloudPlan_TwoHopHappyPath(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/attacker",
		Kind:        "iam-user",
	}
	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/data-processor",
		Kind:        "iam-role",
	}
	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::sensitive-data",
		Kind:        "s3-bucket",
	}
	roleAsIdentity := &CloudIdentity{
		CanonicalID: role.CanonicalID,
		Kind:        "iam-role",
	}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     role,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/attacker"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     roleAsIdentity,
			Target:     bucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found")
	}
	if len(path.Hops) != 2 {
		t.Fatalf("Expected 2 hops, got %d", len(path.Hops))
	}
	if path.Hops[0].Edge.Target.CanonicalID != role.CanonicalID {
		t.Errorf("Expected first hop to reach role, got %s", path.Hops[0].Edge.Target.CanonicalID)
	}
	if path.Hops[1].Edge.Target.CanonicalID != bucket.CanonicalID {
		t.Errorf("Expected second hop to reach bucket, got %s", path.Hops[1].Edge.Target.CanonicalID)
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected OverallState PolicySupported, got %s", path.OverallState)
	}
}

func TestCloudPlan_BlockedHopStopsChain(t *testing.T) {
	user := &CloudIdentity{
		CanonicalID: "arn:aws:iam::123456789012:user/limited-user",
		Kind:        "iam-user",
	}
	role := &CloudResource{
		CanonicalID: "arn:aws:iam::123456789012:role/admin-role",
		Kind:        "iam-role",
	}
	bucket := &CloudResource{
		CanonicalID: "arn:aws:s3:::sensitive-data",
		Kind:        "s3-bucket",
	}
	roleAsIdentity := &CloudIdentity{CanonicalID: role.CanonicalID, Kind: "iam-role"}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     role,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/someone-else"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     roleAsIdentity,
			Target:     bucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if ok {
		t.Fatal("Expected no path to be found (first hop is Blocked)")
	}
	if path != nil {
		t.Errorf("Expected nil path on failure, got %+v", path)
	}
}

func TestCloudPlan_TargetAlreadyHeld(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	evaluator := &AWSEvaluator{}

	path, ok := CloudPlan(nil, []string{user.CanonicalID}, user.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected ok=true when target is already held")
	}
	if len(path.Hops) != 0 {
		t.Errorf("Expected zero hops, got %d", len(path.Hops))
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected OverallState PolicySupported, got %s", path.OverallState)
	}
}

func TestCloudPlan_DeadEndEdgeDoesNotLeakIntoSuccessfulPath(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	goodBucket := &CloudResource{CanonicalID: "arn:aws:s3:::good-bucket", Kind: "s3-bucket"}
	deadEndRole := &CloudResource{CanonicalID: "arn:aws:iam::123456789012:role/unreachable-role", Kind: "iam-role"}

	// The dead-end edge is listed FIRST deliberately. CloudPlan returns the
	// instant it finds the target, so if the successful edge were first,
	// the dead-end edge would never even be evaluated -- proving nothing
	// about leakage, only short-circuiting. Listing the dead end first
	// forces it to actually be evaluated (and correctly skipped) within
	// the same pass, before the successful hop is found second.
	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     deadEndRole,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/someone-else"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     user,
			Target:     goodBucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::good-bucket/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, goodBucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found via the viable edge")
	}
	if len(path.Hops) != 1 {
		t.Fatalf("Expected exactly 1 hop (the viable edge only), got %d", len(path.Hops))
	}
	if path.Hops[0].Edge.Target.CanonicalID != goodBucket.CanonicalID {
		t.Errorf("Expected the single hop to be the good-bucket edge, got %s", path.Hops[0].Edge.Target.CanonicalID)
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected OverallState PolicySupported (dead-end Blocked edge must not affect it), got %s", path.OverallState)
	}
}

// fakeMixedStrengthEvaluator is a test-only AuthorizationEvaluator that
// returns a fixed, per-target canned State. Used to construct a path with a
// mix of Observed and PolicySupported strength -- something no real
// evaluator (AWSEvaluator/AzureEvaluator/GCPEvaluator) currently produces,
// since none of them ever set State: Observed (confirmed by inspection --
// that value is reserved for a future evidence-correlation-aware
// evaluator; see spec amendment point 2). An unrecognized target is a test
// bug, not a silent default, so it panics rather than guessing.
type fakeMixedStrengthEvaluator struct {
	stateByTarget map[string]PathState
}

func (f *fakeMixedStrengthEvaluator) EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult {
	state, ok := f.stateByTarget[edge.Target.CanonicalID]
	if !ok {
		panic("fakeMixedStrengthEvaluator: no canned state for target " + edge.Target.CanonicalID)
	}
	return &EvaluationResult{State: state}
}

func TestCloudPlan_MixedStrengthHopsComputeWeakestOverallState(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "test:user", Kind: "iam-user"}
	role := &CloudResource{CanonicalID: "test:role", Kind: "iam-role"}
	bucket := &CloudResource{CanonicalID: "test:bucket", Kind: "s3-bucket"}
	roleAsIdentity := &CloudIdentity{CanonicalID: role.CanonicalID, Kind: "iam-role"}

	edges := []*CloudPermission{
		{Source: user, Target: role, Action: "sts:AssumeRole"},
		{Source: roleAsIdentity, Target: bucket, Action: "s3:GetObject"},
	}

	evaluator := &fakeMixedStrengthEvaluator{
		stateByTarget: map[string]PathState{
			role.CanonicalID:   Observed,
			bucket.CanonicalID: PolicySupported,
		},
	}

	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found")
	}
	if len(path.Hops) != 2 {
		t.Fatalf("Expected 2 hops, got %d", len(path.Hops))
	}
	if path.OverallState != PolicySupported {
		t.Errorf("Expected weakest-link OverallState PolicySupported (weaker than Observed), got %s", path.OverallState)
	}
}

func TestCloudPlan_DuplicateViableEdgesDeterministic(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::sensitive-data", Kind: "s3-bucket"}

	edgeA := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "identity-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
		},
	}
	edgeB := &CloudPermission{
		Source:     user,
		Target:     bucket,
		Action:     "s3:GetObject",
		SourceType: "resource-policy",
		Attributes: map[string]string{
			"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-data/*"}]}`,
		},
	}
	edges := []*CloudPermission{edgeA, edgeB}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, bucket.CanonicalID, evaluator, &RequestContext{}, 10)

	if !ok {
		t.Fatal("Expected path to be found")
	}
	if len(path.Hops) != 1 {
		t.Fatalf("Expected exactly 1 hop (target reached once, even with 2 viable edges), got %d", len(path.Hops))
	}
	// Documents deterministic-for-this-fixed-input-order behavior, per the
	// spec's explicit acceptance of iteration-order dependency when ties
	// exist -- this is NOT a claim that identity-policy "should" win in
	// general over resource-policy.
	if path.Hops[0].Edge.SourceType != "identity-policy" {
		t.Errorf("Expected the first edge in input order (identity-policy) to be recorded, got %s", path.Hops[0].Edge.SourceType)
	}
}

func TestCloudPlan_StructurallyUnreachableTarget(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	unrelatedBucket := &CloudResource{CanonicalID: "arn:aws:s3:::unrelated-bucket", Kind: "s3-bucket"}
	isolatedTarget := &CloudResource{CanonicalID: "arn:aws:s3:::isolated-bucket", Kind: "s3-bucket"}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     unrelatedBucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::unrelated-bucket/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, isolatedTarget.CanonicalID, evaluator, &RequestContext{}, 10)

	if ok {
		t.Fatal("Expected no path to be found -- isolatedTarget has no edge pointing to it at all")
	}
	if path != nil {
		t.Errorf("Expected nil path, got %+v", path)
	}
}
