package cloudgraph

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	testAcct    = "111122223333"
	testUserARN = "arn:aws:iam::111122223333:user/alice"
	testRoleARN = "arn:aws:iam::111122223333:role/backup-operator"
	testBucket  = "arn:aws:s3:::corp-backups"
)

type fakeIAM struct {
	pages []*iam.GetAccountAuthorizationDetailsOutput
	err   error
	calls int
}

func (f *fakeIAM) GetAccountAuthorizationDetails(_ context.Context, in *iam.GetAccountAuthorizationDetailsInput, _ ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	idx := 0
	if in.Marker != nil {
		idx = int((*in.Marker)[0] - '0')
	}
	f.calls++
	return f.pages[idx], nil
}

type fakeSTS struct{ account string }

func (f *fakeSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account)}, nil
}

type fakeS3 struct {
	names []string
	err   error
}

func (f *fakeS3) ListBuckets(_ context.Context, _ *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := &s3.ListBucketsOutput{}
	for _, n := range f.names {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: aws.String(n)})
	}
	return out, nil
}

func policyDoc(t *testing.T, statements string) string {
	t.Helper()
	return `{"Version":"2012-10-17","Statement":` + statements + `}`
}

// baseSnapshot: alice (user, inherits group "ops" policy), backup-operator
// role trusting alice, and a managed policy granting the role S3 access.
func baseSnapshot(t *testing.T) *iam.GetAccountAuthorizationDetailsOutput {
	t.Helper()
	trust := policyDoc(t, `{"Effect":"Allow","Principal":{"AWS":"`+testUserARN+`"},"Action":"sts:AssumeRole"}`)
	userInline := policyDoc(t, `{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"`+testRoleARN+`"}`)
	groupInline := policyDoc(t, `{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":"`+testBucket+`"}`)
	roleManaged := policyDoc(t, `{"Effect":"Allow","Action":"s3:GetObject","Resource":"`+testBucket+`/*"}`)
	return &iam.GetAccountAuthorizationDetailsOutput{
		UserDetailList: []types.UserDetail{{
			Arn:       aws.String(testUserARN),
			UserName:  aws.String("alice"),
			GroupList: []string{"ops"},
			UserPolicyList: []types.PolicyDetail{{
				PolicyName:     aws.String("assume"),
				PolicyDocument: aws.String(userInline),
			}},
		}},
		GroupDetailList: []types.GroupDetail{{
			GroupName: aws.String("ops"),
			GroupPolicyList: []types.PolicyDetail{{
				PolicyName:     aws.String("list"),
				PolicyDocument: aws.String(groupInline),
			}},
		}},
		RoleDetailList: []types.RoleDetail{{
			Arn:                      aws.String(testRoleARN),
			RoleName:                 aws.String("backup-operator"),
			AssumeRolePolicyDocument: aws.String(trust),
			AttachedManagedPolicies: []types.AttachedPolicy{{
				PolicyArn: aws.String("arn:aws:iam::111122223333:policy/backup-read"),
			}},
		}},
		Policies: []types.ManagedPolicyDetail{{
			Arn: aws.String("arn:aws:iam::111122223333:policy/backup-read"),
			PolicyVersionList: []types.PolicyVersion{{
				IsDefaultVersion: true,
				Document:         aws.String(roleManaged),
			}},
		}},
		IsTruncated: false,
	}
}

func newTestAWSClient(iamAPI AWSIAMAPI, buckets ...string) *AWSDiscoveryClient {
	return NewAWSDiscoveryClientWith(iamAPI, &fakeSTS{account: testAcct}, &fakeS3{names: buckets}, "us-east-1").
		WithOrganizations(&fakeOrg{})
}

func findPerm(g *DiscoveredGraph, source, action, target string) *CloudPermission {
	for _, p := range g.Permissions {
		if p.Source.CanonicalID == source && p.Action == action && p.Target.CanonicalID == target {
			return p
		}
	}
	return nil
}

func TestAWSDiscover_IdentitiesAndResources(t *testing.T) {
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}, "corp-backups")
	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	kinds := map[string]string{}
	for _, id := range graph.Identities {
		kinds[id.CanonicalID] = id.Kind
		if id.AccountScope == nil || id.AccountScope.AccountID != testAcct {
			t.Errorf("identity %s missing account scope", id.CanonicalID)
		}
	}
	if kinds[testUserARN] != "iam-user" || kinds[testRoleARN] != "iam-role" {
		t.Errorf("identity kinds = %v", kinds)
	}
	resKinds := map[string]string{}
	for _, r := range graph.Resources {
		resKinds[r.CanonicalID] = r.Kind
	}
	if resKinds[testBucket] != "s3-bucket" {
		t.Errorf("bucket resource kind = %q, want s3-bucket", resKinds[testBucket])
	}
	if resKinds[testRoleARN] != "iam-role" {
		t.Errorf("role must be a resource so it can be assumed, got %q", resKinds[testRoleARN])
	}
	if stats.ItemsFound == 0 {
		t.Error("stats.ItemsFound should count discovered items")
	}
}

func TestAWSDiscover_GroupPolicyInheritedByUser(t *testing.T) {
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}, "corp-backups")
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if findPerm(graph, testUserARN, "s3:ListBucket", testBucket) == nil {
		t.Error("alice should inherit s3:ListBucket from group ops")
	}
}

func TestAWSDiscover_EdgesAreEvaluableByAWSEvaluator(t *testing.T) {
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}, "corp-backups")
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	eval := &AWSEvaluator{}
	edge := findPerm(graph, testRoleARN, "s3:GetObject", testBucket+"/*")
	if edge == nil {
		t.Fatal("expected role identity-policy edge for s3:GetObject")
	}
	if got := eval.EvaluatePermission(edge, &RequestContext{}).State; got != PolicySupported {
		t.Errorf("role s3:GetObject state = %s, want policy_supported", got)
	}
}

func TestAWSDiscover_ExplicitDenyBlocksAllow(t *testing.T) {
	snap := baseSnapshot(t)
	deny := policyDoc(t, `[{"Effect":"Allow","Action":"s3:GetObject","Resource":"`+testBucket+`/*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"`+testBucket+`/*"}]`)
	snap.Policies[0].PolicyVersionList[0].Document = aws.String(deny)
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}}, "corp-backups")
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	edge := findPerm(graph, testRoleARN, "s3:GetObject", testBucket+"/*")
	if edge == nil {
		t.Fatal("expected edge even when a deny exists; the evaluator decides the verdict")
	}
	if got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{}).State; got != Blocked {
		t.Errorf("state = %s, want blocked by explicit deny", got)
	}
}

func TestAWSDiscover_RoleTrustRequiresIdentityPolicyAllowingAssume(t *testing.T) {
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}, "corp-backups")
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	var trustEdge *CloudPermission
	for _, p := range graph.Permissions {
		if p.SourceType == "role-trust" && p.Source.CanonicalID == testUserARN && p.Target.CanonicalID == testRoleARN {
			trustEdge = p
		}
	}
	if trustEdge == nil {
		t.Fatal("expected role-trust edge alice->role")
	}
	if got := (&AWSEvaluator{}).EvaluatePermission(trustEdge, &RequestContext{}).State; got != PolicySupported {
		t.Errorf("trust edge state = %s, want policy_supported", got)
	}

	// Same trust, but alice's own policy does not allow AssumeRole: no edge.
	snap := baseSnapshot(t)
	snap.UserDetailList[0].UserPolicyList = nil
	client = newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}}, "corp-backups")
	graph, _, err = client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, p := range graph.Permissions {
		if p.SourceType == "role-trust" {
			t.Error("trust without identity-policy permission must not produce an assumable edge")
		}
	}
}

func TestAWSDiscover_MultiHopReachesBucketThroughRole(t *testing.T) {
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}, "corp-backups")
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	path, ok := CloudPlan(graph.Permissions, []string{testUserARN}, testBucket+"/*", &AWSEvaluator{}, &RequestContext{}, 3)
	if !ok {
		t.Fatal("expected alice to reach the bucket object via assume-role then s3:GetObject")
	}
	if len(path.Hops) != 2 {
		t.Fatalf("hops = %d, want 2 (assume role, then read); sibling ListBucket must not appear", len(path.Hops))
	}
	if path.Hops[0].Edge.Action != "sts:AssumeRole" || path.Hops[1].Edge.Action != "s3:GetObject" {
		t.Errorf("chain = [%s, %s], want [sts:AssumeRole, s3:GetObject]", path.Hops[0].Edge.Action, path.Hops[1].Edge.Action)
	}
}

func TestAWSDiscover_UnresolvableTrustPrincipalsCounted(t *testing.T) {
	snap := baseSnapshot(t)
	rootTrust := policyDoc(t, `[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]`)
	snap.RoleDetailList[0].AssumeRolePolicyDocument = aws.String(rootTrust)
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}}, "corp-backups")
	_, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if stats.UnresolvedTrust != 1 {
		t.Errorf("UnresolvedTrust = %d, want 1 (account root)", stats.UnresolvedTrust)
	}
	if stats.WildcardTrustSkipped != 1 {
		t.Errorf("WildcardTrustSkipped = %d, want 1", stats.WildcardTrustSkipped)
	}
}

func TestAWSDiscover_URLEncodedDocumentDecoded(t *testing.T) {
	snap := baseSnapshot(t)
	raw := policyDoc(t, `{"Effect":"Allow","Action":"s3:HeadBucket","Resource":"`+testBucket+`"}`)
	snap.UserDetailList[0].UserPolicyList[0].PolicyDocument = aws.String(url.QueryEscape(raw))
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}}, "corp-backups")
	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if stats.SkippedDocuments != 0 {
		t.Errorf("encoded document was skipped (%d)", stats.SkippedDocuments)
	}
	if findPerm(graph, testUserARN, "s3:HeadBucket", testBucket) == nil {
		t.Error("URL-encoded policy document should yield its edge")
	}
}

func TestAWSDiscover_PaginatesAuthorizationDetails(t *testing.T) {
	full := baseSnapshot(t)
	first := &iam.GetAccountAuthorizationDetailsOutput{
		UserDetailList: full.UserDetailList,
		IsTruncated:    true,
		Marker:         aws.String("1"),
	}
	second := &iam.GetAccountAuthorizationDetailsOutput{
		RoleDetailList:  full.RoleDetailList,
		GroupDetailList: full.GroupDetailList,
		Policies:        full.Policies,
	}
	fake := &fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{first, second}}
	client := newTestAWSClient(fake, "corp-backups")
	graph, _, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if fake.calls != 2 {
		t.Errorf("IAM calls = %d, want 2", fake.calls)
	}
	if findPerm(graph, testRoleARN, "s3:GetObject", testBucket+"/*") == nil {
		t.Error("role from the second page should be discovered")
	}
}

func TestAWSDiscover_FailsFastOnIAMError(t *testing.T) {
	client := newTestAWSClient(&fakeIAM{err: errors.New("AccessDenied")}, "corp-backups")
	graph, _, err := client.Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("err = %v, want AccessDenied surfaced", err)
	}
	if graph != nil {
		t.Error("a failed pass must not return a partial graph")
	}
}

func TestAWSDiscover_FailsFastOnBucketListError(t *testing.T) {
	client := NewAWSDiscoveryClientWith(
		&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}},
		&fakeSTS{account: testAcct},
		&fakeS3{err: errors.New("throttled")},
		"us-east-1",
	)
	if _, _, err := client.Discover(context.Background()); err == nil {
		t.Fatal("bucket listing failure must abort the pass")
	}
}

func TestAWSDiscover_NotResourceStatementEmitsNoWildcardEdge(t *testing.T) {
	snap := baseSnapshot(t)
	doc := policyDoc(t, `{"Effect":"Allow","Action":"s3:DeleteObject","NotResource":"`+testBucket+`/keep/*"}`)
	snap.UserDetailList[0].UserPolicyList = []types.PolicyDetail{{PolicyDocument: aws.String(doc)}}
	client := newTestAWSClient(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}}, "corp-backups")
	graph, stats, err := client.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, p := range graph.Permissions {
		if p.Action == "s3:DeleteObject" {
			t.Fatalf("NotResource allow produced an edge to %s", p.Target.CanonicalID)
		}
	}
	if stats.NotActionStatements != 1 {
		t.Errorf("NotActionStatements = %d, want 1 (NotResource counted)", stats.NotActionStatements)
	}
}

func TestAWSDecodePolicy_CompactsAndRejectsGarbage(t *testing.T) {
	got, err := awsDecodePolicy("{\n  \"Effect\": \"Allow\"\n}")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != `{"Effect":"Allow"}` {
		t.Errorf("compact = %q", got)
	}
	if _, err := awsDecodePolicy("{not json"); err == nil {
		t.Error("invalid JSON must be rejected")
	}
	var v any
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Errorf("result must stay valid JSON: %v", err)
	}
}
