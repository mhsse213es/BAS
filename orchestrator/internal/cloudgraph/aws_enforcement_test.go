package cloudgraph

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

const (
	orgOU        = "ou-test-1"
	orgRoot      = "r-test"
	boundaryARN  = "arn:aws:iam::111122223333:policy/alice-boundary"
	fullAccessID = "p-fullaccess"
)

// fakeOrg is an in-memory Organizations source. parent maps each child to its
// parent. An account absent from parent is not in an organization.
type fakeOrg struct {
	parent   map[string]orgtypes.Parent
	policies map[string][]string // target -> policy IDs attached directly
	content  map[string]string   // policy ID -> document
	err      error               // returned by every call when set
}

func (f *fakeOrg) ListParents(_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	p, ok := f.parent[aws.ToString(in.ChildId)]
	if !ok {
		return nil, &orgtypes.AWSOrganizationsNotInUseException{}
	}
	return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{p}}, nil
}

func (f *fakeOrg) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := &organizations.ListPoliciesForTargetOutput{}
	for _, id := range f.policies[aws.ToString(in.TargetId)] {
		out.Policies = append(out.Policies, orgtypes.PolicySummary{Id: aws.String(id)})
	}
	return out, nil
}

func (f *fakeOrg) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{Content: aws.String(f.content[aws.ToString(in.PolicyId)])}}, nil
}

// fullOrg is an account under OU -> root. Each level carries FullAWSAccess
// unless a test overrides the policies map.
func fullOrg() *fakeOrg {
	allowAll := enfDoc(`{"Effect":"Allow","Action":"*","Resource":"*"}`)
	return &fakeOrg{
		parent: map[string]orgtypes.Parent{
			testAcct: {Id: aws.String(orgOU), Type: orgtypes.ParentTypeOrganizationalUnit},
			orgOU:    {Id: aws.String(orgRoot), Type: orgtypes.ParentTypeRoot},
		},
		policies: map[string][]string{
			testAcct: {fullAccessID},
			orgOU:    {fullAccessID},
			orgRoot:  {fullAccessID},
		},
		content: map[string]string{fullAccessID: allowAll},
	}
}

// withBoundary sets alice's permissions boundary to a managed policy holding
// doc, so discovery has to resolve it the same way it resolves attached policies.
func withBoundary(snap *iam.GetAccountAuthorizationDetailsOutput, doc string) {
	snap.UserDetailList[0].PermissionsBoundary = &types.AttachedPermissionsBoundary{
		PermissionsBoundaryArn:  aws.String(boundaryARN),
		PermissionsBoundaryType: types.PermissionsBoundaryAttachmentTypePolicy,
	}
	snap.Policies = append(snap.Policies, types.ManagedPolicyDetail{
		Arn:               aws.String(boundaryARN),
		PolicyVersionList: []types.PolicyVersion{{IsDefaultVersion: true, Document: aws.String(doc)}},
	})
}

func discoverWithOrg(t *testing.T, snap *iam.GetAccountAuthorizationDetailsOutput, org AWSOrgAPI) (*DiscoveredGraph, *AWSDiscoveryStats) {
	t.Helper()
	c := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}}).WithOrganizations(org)
	g, stats, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return g, stats
}

func evalAlice(t *testing.T, g *DiscoveredGraph, action string) *EvaluationResult {
	t.Helper()
	perm := findPerm(g, testUserARN, action, testBucket)
	if perm == nil {
		t.Fatalf("no alice edge for %s on %s", action, testBucket)
	}
	return (&AWSEvaluator{}).EvaluatePermission(perm, &RequestContext{})
}

func TestAWSGate_ActionNotActionAndConditions(t *testing.T) {
	allowAll := enfDoc(`{"Effect":"Allow","Action":"*","Resource":"*"}`)
	allowGetOnly := enfDoc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`)
	denyAllButGet := enfDoc(`{"Effect":"Deny","NotAction":"s3:GetObject","Resource":"*"}`)
	allowConditional := enfDoc(`{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}`)
	cases := []struct {
		name   string
		docs   []string
		action string
		want   PathState
		reason string
	}{
		{"wildcard allow covers", []string{allowAll}, "s3:GetObject", PolicySupported, ""},
		{"whole-action match only", []string{allowGetOnly}, "s3:GetObjectAcl", Blocked, "implicit-deny"},
		{"NotAction deny blocks the unnamed action", []string{allowAll, denyAllButGet}, "s3:PutObject", Blocked, "explicit-deny"},
		{"NotAction deny spares the named action", []string{allowAll, denyAllButGet}, "s3:GetObject", PolicySupported, ""},
		{"conditional allow is conditional", []string{allowConditional}, "s3:GetObject", ConditionallyReachable, awsGateCondition},
		{"unreadable document is unknown", []string{"not json"}, "s3:GetObject", Unknown, "unparseable-enforcement-document"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, reason := awsGate(c.docs, c.action, testBucket)
			if state != c.want || reason != c.reason {
				t.Errorf("awsGate = (%s, %q), want (%s, %q)", state, reason, c.want, c.reason)
			}
		})
	}
}

func TestAWSEnforcement_PermissionsBoundaryBlocksActionOutsideIt(t *testing.T) {
	snap := baseSnapshot(t)
	withBoundary(snap, policyDoc(t, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`))
	g, stats := discoverWithOrg(t, snap, fullOrg())

	if stats.BoundaryAttached != 1 {
		t.Errorf("BoundaryAttached = %d, want 1", stats.BoundaryAttached)
	}
	got := evalAlice(t, g, "s3:ListBucket")
	if got.State != Blocked || got.BlockedBy != "permissions-boundary:implicit-deny" {
		t.Errorf("ListBucket under a GetObject-only boundary = %+v, want blocked by the boundary", got)
	}
}

func TestAWSEnforcement_PermissionsBoundaryAllowingActionKeepsGrant(t *testing.T) {
	snap := baseSnapshot(t)
	withBoundary(snap, policyDoc(t, `{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}`))
	g, _ := discoverWithOrg(t, snap, fullOrg())
	if got := evalAlice(t, g, "s3:ListBucket"); got.State != PolicySupported {
		t.Errorf("ListBucket under a covering boundary = %+v, want the grant to stand", got)
	}
}

func TestAWSEnforcement_UnresolvedBoundaryIsUnknownNotGranted(t *testing.T) {
	snap := baseSnapshot(t)
	snap.UserDetailList[0].PermissionsBoundary = &types.AttachedPermissionsBoundary{
		PermissionsBoundaryArn:  aws.String("arn:aws:iam::111122223333:policy/missing"),
		PermissionsBoundaryType: types.PermissionsBoundaryAttachmentTypePolicy,
	}
	g, stats := discoverWithOrg(t, snap, fullOrg())
	if stats.BoundaryUnresolved != 1 {
		t.Errorf("BoundaryUnresolved = %d, want 1", stats.BoundaryUnresolved)
	}
	if got := evalAlice(t, g, "s3:ListBucket"); got.State != Unknown {
		t.Errorf("ListBucket with an unreadable boundary = %+v, want Unknown", got)
	}
}

func TestAWSEnforcement_SCPDenyAtOUBlocksEveryAccount(t *testing.T) {
	org := fullOrg()
	org.policies[orgOU] = []string{"p-deny-list"}
	org.content["p-deny-list"] = enfDoc(`{"Effect":"Deny","Action":"s3:ListBucket","Resource":"*"}`)

	g, stats := discoverWithOrg(t, baseSnapshot(t), org)
	if stats.SCPLevels != 3 || stats.SCPNotInUse {
		t.Errorf("stats = %+v, want 3 SCP levels (account, OU, root)", stats)
	}
	got := evalAlice(t, g, "s3:ListBucket")
	if got.State != Blocked || got.BlockedBy != "scp-deny" {
		t.Errorf("ListBucket under an OU deny = %+v, want blocked by scp-deny", got)
	}
}

func TestAWSEnforcement_SCPLevelWithoutAllowBlocks(t *testing.T) {
	org := fullOrg()
	// The OU attaches nothing, so no level there allows the action (IAM requires
	// an Allow at every level). ListBucket is blocked even though the account
	// and root both allow it.
	org.policies[orgOU] = nil
	g, _ := discoverWithOrg(t, baseSnapshot(t), org)
	got := evalAlice(t, g, "s3:ListBucket")
	if got.State != Blocked || got.BlockedBy != "scp:implicit-deny" {
		t.Errorf("ListBucket with an empty OU level = %+v, want blocked by scp:implicit-deny", got)
	}
}

func TestAWSEnforcement_ConditionalSCPDenyIsConditional(t *testing.T) {
	org := fullOrg()
	org.policies[orgOU] = []string{"p-cond-deny"}
	org.content["p-cond-deny"] = enfDoc(`{"Effect":"Deny","Action":"s3:ListBucket","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}`)
	g, _ := discoverWithOrg(t, baseSnapshot(t), org)
	got := evalAlice(t, g, "s3:ListBucket")
	if got.State != ConditionallyReachable {
		t.Errorf("ListBucket under a conditional OU deny = %+v, want ConditionallyReachable (not a clean allow)", got)
	}
}

func TestAWSEnforcement_NotInOrganizationSkipsSCPsVisibly(t *testing.T) {
	g, stats := discoverWithOrg(t, baseSnapshot(t), &fakeOrg{})
	if !stats.SCPNotInUse || stats.SCPLevels != 0 {
		t.Errorf("stats = %+v, want SCPNotInUse and no levels", stats)
	}
	perm := findPerm(g, testUserARN, "s3:ListBucket", testBucket)
	if _, ok := perm.Attributes["scp_levels"]; ok {
		t.Error("an account outside an organization must carry no SCP attribute")
	}
	if got := evalAlice(t, g, "s3:ListBucket"); got.State != PolicySupported {
		t.Errorf("ListBucket outside an organization = %+v, want the identity grant", got)
	}
}

func TestAWSEnforcement_OrganizationsAccessDeniedFailsPass(t *testing.T) {
	c := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}).
		WithOrganizations(&fakeOrg{err: errors.New("AccessDenied: organizations:ListParents")})
	if _, _, err := c.Discover(context.Background()); err == nil {
		t.Fatal("Discover must fail when SCPs cannot be read; a partial result would over-report")
	}
}

func TestAWSEnforcement_LevelsRoundTripThroughEdgeAttribute(t *testing.T) {
	levels := [][]string{{`{"Statement":[]}`}, {}}
	raw, err := awsLevelsJSON(levels)
	if err != nil {
		t.Fatalf("awsLevelsJSON: %v", err)
	}
	var back [][]string
	if err := json.Unmarshal([]byte(raw), &back); err != nil || len(back) != 2 {
		t.Errorf("round trip = %v (%v), want 2 levels", back, err)
	}
}

// enfDoc wraps a statement list in a policy document, for fixtures that are
// built outside a test body.
func enfDoc(statements string) string {
	return `{"Version":"2012-10-17","Statement":` + statements + `}`
}
