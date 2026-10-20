package cloudgraph

import (
	"strings"
	"testing"
)

const s3OtherBucketARN = "arn:aws:s3:::other-bucket"

// sessionEdge returns alice's ListBucket edge from discovery, carrying a session
// policy document.
func sessionEdge(t *testing.T, doc string) *CloudPermission {
	t.Helper()
	g, _ := discoverWithOrg(t, baseSnapshot(t), fullOrg())
	perm := findPerm(g, testUserARN, "s3:ListBucket", testBucket)
	if perm == nil {
		t.Fatal("no alice ListBucket edge")
	}
	perm.Attributes["session_policy_document"] = doc
	return perm
}

func TestSessionPolicy_LimitsGrantToItsActions(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`)
	got := (&AWSEvaluator{}).EvaluatePermission(sessionEdge(t, doc), &RequestContext{})
	if got.State != Blocked || got.BlockedBy != "session-policy:implicit-deny" {
		t.Errorf("ListBucket under a GetObject-only session = %+v, want blocked by the session policy", got)
	}
}

func TestSessionPolicy_AllowingActionKeepsGrant(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}`)
	got := (&AWSEvaluator{}).EvaluatePermission(sessionEdge(t, doc), &RequestContext{})
	if got.State != PolicySupported {
		t.Errorf("ListBucket under a covering session = %+v, want the grant to stand", got)
	}
}

// The session allows ListBucket, but only on another bucket. The grant on
// corp-backups must not survive.
func TestSessionPolicy_AllowOnOtherResourceDoesNotCover(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"` + s3OtherBucketARN + `"}`)
	got := (&AWSEvaluator{}).EvaluatePermission(sessionEdge(t, doc), &RequestContext{})
	if got.State != Blocked {
		t.Errorf("ListBucket with a session allow on another bucket = %+v, want blocked", got)
	}
}

// Boundaries are resource-aware too: a boundary that allows the action only on
// another bucket must not keep corp-backups reachable.
func TestPermissionsBoundary_AllowOnOtherResourceDoesNotCover(t *testing.T) {
	snap := baseSnapshot(t)
	withBoundary(snap, enfDoc(`{"Effect":"Allow","Action":"s3:ListBucket","Resource":"`+s3OtherBucketARN+`"}`))
	g, _ := discoverWithOrg(t, snap, fullOrg())
	if got := evalAlice(t, g, "s3:ListBucket"); got.State != Blocked {
		t.Errorf("ListBucket under a boundary covering only another bucket = %+v, want blocked", got)
	}
}

func TestNormalizeAWSSessionPolicy(t *testing.T) {
	good := enfDoc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`)
	if doc, err := NormalizeAWSSessionPolicy(good); err != nil || doc == "" {
		t.Errorf("valid session policy refused: %v", err)
	}
	cases := map[string]string{
		"no statements": enfDoc(`[]`),
		"bad effect":    enfDoc(`{"Effect":"Maybe","Action":"s3:GetObject","Resource":"*"}`),
		"unreadable":    "not json",
		"too long":      enfDoc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"` + strings.Repeat("a", 2100) + `"}`),
	}
	for name, raw := range cases {
		if _, err := NormalizeAWSSessionPolicy(raw); err == nil {
			t.Errorf("%s: session policy accepted, want refused", name)
		}
	}
}

// End to end: a scenario run as a role session. The role grants ListBucket on
// the bucket; the session policy allows only GetObject, so the step is blocked.
func TestExecuteCloudScenarioInSession_SessionPolicyBlocksStep(t *testing.T) {
	g, _ := discoverWithOrg(t, baseSnapshot(t), fullOrg())
	scenario := &CloudScenario{
		ID: "session-list", Provider: "aws",
		Steps: []*CloudScenarioStep{{Name: "list", TechniqueTag: "T1619", Action: "s3:ListBucket"}},
	}

	open := ExecuteCloudScenario(scenario, g, &AWSEvaluator{}, testUserARN, testBucket)
	if open.Steps[0].ExecutionOutcome != "Allowed" {
		t.Fatalf("without a session, step = %s, want Allowed", open.Steps[0].ExecutionOutcome)
	}

	doc := enfDoc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`)
	sessioned := ExecuteCloudScenarioInSession(scenario, g, &AWSEvaluator{}, testUserARN, testBucket, doc)
	if sessioned.Steps[0].ExecutionOutcome != "Blocked" {
		t.Errorf("with a GetObject-only session, step = %s, want Blocked", sessioned.Steps[0].ExecutionOutcome)
	}
}
