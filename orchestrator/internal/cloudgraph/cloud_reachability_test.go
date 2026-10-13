package cloudgraph

import "testing"

// TestIsViable_AllSixStates gives isViable direct coverage of every
// PathState, matching its own doc comment's claim: only PolicySupported and
// Observed are viable; Blocked, Unknown, Candidate, and
// ConditionallyReachable are all treated identically (none let a hop
// continue). Previously this was only exercised indirectly through
// AWSEvaluator fixtures, which never produce Candidate/ConditionallyReachable
// at all.
func TestIsViable_AllSixStates(t *testing.T) {
	cases := []struct {
		state PathState
		want  bool
	}{
		{Candidate, false},
		{ConditionallyReachable, false},
		{PolicySupported, true},
		{Observed, true},
		{Blocked, false},
		{Unknown, false},
	}
	for _, c := range cases {
		got := isViable(c.state)
		if got != c.want {
			t.Errorf("isViable(%s) = %v, want %v", c.state, got, c.want)
		}
	}
}

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

// TestWorstState_OnlyUnconfirmedStatesDefaultsToUnknown pins a fix: neither
// CloudPlan nor CloudReachable ever feeds worstState a state that isViable
// didn't already approve (only PolicySupported/Observed), so this input
// shape is unreachable through either public function today. But
// worstState is tested directly, and a direct caller could pass it. Before
// this fix, an input containing only Candidate/ConditionallyReachable (no
// Blocked/Unknown/PolicySupported/Observed at all) fell through to the
// final `return Observed` -- the STRONGEST possible verdict for an input
// that contains no confirmed evidence at all, directly contradicting the
// function's own "never report stronger evidence than the weakest hop
// actually has" contract.
func TestWorstState_OnlyUnconfirmedStatesDefaultsToUnknown(t *testing.T) {
	got := worstState([]PathState{Candidate, ConditionallyReachable})
	if got != Unknown {
		t.Errorf("Expected Unknown (never claim stronger evidence than the weakest hop), got %s", got)
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

func TestCloudReachable_MutualTrustCycleTerminates(t *testing.T) {
	roleA := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:role/role-a", Kind: "iam-role"}
	roleAAsResource := &CloudResource{CanonicalID: roleA.CanonicalID, Kind: "iam-role"}
	roleB := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:role/role-b", Kind: "iam-role"}
	roleBAsResource := &CloudResource{CanonicalID: roleB.CanonicalID, Kind: "iam-role"}

	edges := []*CloudPermission{
		{
			Source:     roleA,
			Target:     roleBAsResource,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/role-a"},"Action":"sts:AssumeRole"}]}`,
			},
		},
		{
			Source:     roleB,
			Target:     roleAAsResource,
			Action:     "sts:AssumeRole",
			SourceType: "role-trust",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/role-b"},"Action":"sts:AssumeRole"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	reached := CloudReachable(edges, []string{roleA.CanonicalID}, evaluator, &RequestContext{}, 10)

	if len(reached) != 2 {
		t.Fatalf("Expected 2 reached nodes (role A and role B), got %d: %v", len(reached), reached)
	}
	foundA, foundB := false, false
	for _, id := range reached {
		if id == roleA.CanonicalID {
			foundA = true
		}
		if id == roleB.CanonicalID {
			foundB = true
		}
	}
	if !foundA || !foundB {
		t.Errorf("Expected both role A and role B reached, got %v", reached)
	}
}

func TestCloudReachable_MaxHopsCapCutsOffLongChain(t *testing.T) {
	start := &CloudIdentity{CanonicalID: "test:n0", Kind: "iam-user"}
	n1 := &CloudResource{CanonicalID: "test:n1", Kind: "iam-role"}
	n1AsIdentity := &CloudIdentity{CanonicalID: n1.CanonicalID, Kind: "iam-role"}
	n2 := &CloudResource{CanonicalID: "test:n2", Kind: "iam-role"}
	n2AsIdentity := &CloudIdentity{CanonicalID: n2.CanonicalID, Kind: "iam-role"}
	n3 := &CloudResource{CanonicalID: "test:n3", Kind: "iam-role"}
	n3AsIdentity := &CloudIdentity{CanonicalID: n3.CanonicalID, Kind: "iam-role"}
	n4 := &CloudResource{CanonicalID: "test:n4", Kind: "iam-role"}
	n4AsIdentity := &CloudIdentity{CanonicalID: n4.CanonicalID, Kind: "iam-role"}
	n5 := &CloudResource{CanonicalID: "test:n5", Kind: "iam-role"}

	allow := map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`}
	// Edges are listed in REVERSED dependency order deliberately. Both
	// CloudReachable and adchain.Reachable (the pattern it mirrors) mutate
	// the reached set while iterating a single pass, so if these were
	// listed in forward order (start->n1, n1->n2, ...), all 5 hops would
	// cascade through in pass 0 alone -- n1 would be marked reached, and
	// the very next edge in the same pass would already see it. Listing
	// them backwards means each edge's enabling predecessor is later in
	// the slice, so it isn't satisfied until the NEXT pass, giving exactly
	// one new hop per pass -- the only way this test can exercise maxHops
	// meaningfully instead of finishing in one pass regardless of the cap.
	edges := []*CloudPermission{
		{Source: n4AsIdentity, Target: n5, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: n3AsIdentity, Target: n4, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: n2AsIdentity, Target: n3, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: n1AsIdentity, Target: n2, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
		{Source: start, Target: n1, Action: "sts:AssumeRole", SourceType: "identity-policy", Attributes: allow},
	}

	evaluator := &AWSEvaluator{}

	// With maxHops=2 (passes 0 and 1), this reversed ordering advances the
	// frontier by exactly one new node per pass: pass 0 reaches only n1
	// (the start->n1 edge is last in the slice but is the only one whose
	// Source is already reached); pass 1 reaches only n2 (n1->n2 is now
	// satisfied, but n2->n3 still isn't, since it comes before n1->n2 in
	// the slice and n2 wasn't reached until partway through pass 1). So 2
	// passes reach n1 and n2 but never n3/n4/n5.
	reached := CloudReachable(edges, []string{start.CanonicalID}, evaluator, &RequestContext{}, 2)
	if len(reached) != 3 { // start, n1, n2
		t.Fatalf("Expected 3 reached nodes (start, n1, n2) with maxHops=2, got %d: %v", len(reached), reached)
	}

	path, ok := CloudPlan(edges, []string{start.CanonicalID}, n5.CanonicalID, evaluator, &RequestContext{}, 2)
	if ok {
		t.Fatalf("Expected CloudPlan to fail to confirm n5 within maxHops=2, got path %+v", path)
	}
}

func TestCloudReachable_MaxHopsZeroReturnsHeldUnchanged(t *testing.T) {
	start := &CloudIdentity{CanonicalID: "test:n0", Kind: "iam-user"}
	n1 := &CloudResource{CanonicalID: "test:n1", Kind: "iam-role"}
	edges := []*CloudPermission{
		{
			Source:     start,
			Target:     n1,
			Action:     "sts:AssumeRole",
			SourceType: "identity-policy",
			Attributes: map[string]string{"policy_document": `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole"}]}`},
		},
	}
	evaluator := &AWSEvaluator{}

	reached := CloudReachable(edges, []string{start.CanonicalID}, evaluator, &RequestContext{}, 0)
	if len(reached) != 1 || reached[0] != start.CanonicalID {
		t.Fatalf("Expected held unchanged with maxHops=0, got %v", reached)
	}

	_, ok := CloudPlan(edges, []string{start.CanonicalID}, n1.CanonicalID, evaluator, &RequestContext{}, 0)
	if ok {
		t.Fatal("Expected CloudPlan to return ok=false with maxHops=0 and target not already held")
	}
}

func TestCloudReachable_NonAssumableResourceNeverUnlocksMismatchedEdge(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::reused-id-bucket", Kind: "s3-bucket"}

	// mismatchedSource deliberately reuses the bucket's CanonicalID as an
	// *identity* -- a nonsensical construction (buckets cannot act as
	// principals), simulating a data bug or adversarial edge. Reaching the
	// bucket must never make this edge traversable.
	mismatchedSource := &CloudIdentity{CanonicalID: bucket.CanonicalID, Kind: "iam-role"}
	otherTarget := &CloudResource{CanonicalID: "arn:aws:s3:::other-bucket", Kind: "s3-bucket"}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     bucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reused-id-bucket/*"}]}`,
			},
		},
		{
			Source:     mismatchedSource,
			Target:     otherTarget,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	reached := CloudReachable(edges, []string{user.CanonicalID}, evaluator, &RequestContext{}, 10)

	for _, id := range reached {
		if id == otherTarget.CanonicalID {
			t.Fatalf("otherTarget must NOT be reachable -- the bucket's CanonicalID must never be treated as a valid Source just because it was reached as a Target, got reached=%v", reached)
		}
	}
	foundBucket := false
	for _, id := range reached {
		if id == bucket.CanonicalID {
			foundBucket = true
		}
	}
	if !foundBucket {
		t.Error("Expected the bucket itself to still be reachable (it's a legitimate dead-end target)")
	}
}

// TestCloudPlan_NonAssumableResourceNeverUnlocksMismatchedEdge mirrors
// TestCloudReachable_NonAssumableResourceNeverUnlocksMismatchedEdge, but
// through CloudPlan. Review finding (Minor 2): the reachedAsSource/
// reachedAsTarget Kind-gating logic is duplicated between CloudPlan and
// CloudReachable; only CloudReachable's copy had a dedicated test. This
// closes that gap -- CloudPlan's copy of the same logic is independently
// verified here, not just assumed identical by inspection.
func TestCloudPlan_NonAssumableResourceNeverUnlocksMismatchedEdge(t *testing.T) {
	user := &CloudIdentity{CanonicalID: "arn:aws:iam::123456789012:user/attacker", Kind: "iam-user"}
	bucket := &CloudResource{CanonicalID: "arn:aws:s3:::reused-id-bucket", Kind: "s3-bucket"}
	mismatchedSource := &CloudIdentity{CanonicalID: bucket.CanonicalID, Kind: "iam-role"}
	otherTarget := &CloudResource{CanonicalID: "arn:aws:s3:::other-bucket", Kind: "s3-bucket"}

	edges := []*CloudPermission{
		{
			Source:     user,
			Target:     bucket,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reused-id-bucket/*"}]}`,
			},
		},
		{
			Source:     mismatchedSource,
			Target:     otherTarget,
			Action:     "s3:GetObject",
			SourceType: "identity-policy",
			Attributes: map[string]string{
				"policy_document": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}]}`,
			},
		},
	}

	evaluator := &AWSEvaluator{}
	path, ok := CloudPlan(edges, []string{user.CanonicalID}, otherTarget.CanonicalID, evaluator, &RequestContext{}, 10)

	if ok {
		t.Fatalf("otherTarget must NOT be confirmed reachable -- the bucket's CanonicalID must never be treated as a valid Source just because it was reached as a Target, got path=%+v", path)
	}
}
