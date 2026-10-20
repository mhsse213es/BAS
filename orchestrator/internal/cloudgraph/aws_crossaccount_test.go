package cloudgraph

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

const (
	xPartnerARN = "arn:aws:iam::999988887777:user/partner"
	xPublicObj  = "arn:aws:s3:::corp-backups/*"
)

// xDiscover runs discovery over the base snapshot with a bucket policy.
func xDiscover(t *testing.T, doc string) (*DiscoveredGraph, *AWSDiscoveryStats) {
	t.Helper()
	s3api := &fakeS3{names: []string{s3TestBucket}, policies: map[string]string{s3TestBucket: doc}}
	c := NewAWSDiscoveryClientWith(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}},
		&fakeSTS{account: testAcct}, s3api, "us-east-1").WithOrganizations(&fakeOrg{})
	g, stats, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return g, stats
}

// xEdge finds an edge by source, action, target, and source type.
func xEdge(g *DiscoveredGraph, source, action, target, sourceType string) *CloudPermission {
	for _, p := range g.Permissions {
		if p.Source.CanonicalID == source && p.Action == action && p.Target.CanonicalID == target && p.SourceType == sourceType {
			return p
		}
	}
	return nil
}

func TestCrossAccount_PartnerGrantIsConditional(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","Principal":{"AWS":"` + xPartnerARN + `"},"Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `"}`)
	g, stats := xDiscover(t, doc)

	if stats.CrossAccountIdentities != 1 {
		t.Errorf("CrossAccountIdentities = %d, want 1", stats.CrossAccountIdentities)
	}
	edge := xEdge(g, xPartnerARN, "s3:ListBucket", s3TestBucketARN, "resource-policy")
	if edge == nil {
		t.Fatal("the partner account's bucket-policy grant produced no edge")
	}
	got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{})
	if got.State != ConditionallyReachable || len(got.UnresolvedConds) != 1 || got.UnresolvedConds[0] != crossAccountCondition {
		t.Errorf("partner grant = %+v, want ConditionallyReachable on %s", got, crossAccountCondition)
	}
}

func TestCrossAccount_PublicGrantIsMarkedPublic(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"` + xPublicObj + `"}`)
	g, stats := xDiscover(t, doc)

	if stats.PublicGrants != 1 {
		t.Errorf("PublicGrants = %d, want 1", stats.PublicGrants)
	}
	edge := xEdge(g, publicIdentityID, "s3:GetObject", xPublicObj, "resource-policy")
	if edge == nil {
		t.Fatal("public bucket-policy grant produced no edge")
	}
	got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{})
	if got.State != ConditionallyReachable || got.UnresolvedConds[0] != publicAccessCondition {
		t.Errorf("public grant = %+v, want ConditionallyReachable on %s", got, publicAccessCondition)
	}
}

// Same-account access can come from the bucket policy alone. The identity has
// no PutObject policy here, so only the resource policy grants it.
func TestCrossAccount_SameAccountGrantFromBucketPolicyAlone(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","Principal":{"AWS":"` + testUserARN + `"},"Action":"s3:PutObject","Resource":"` + s3TestBucketARN + `/*"}`)
	g, _ := xDiscover(t, doc)

	edge := xEdge(g, testUserARN, "s3:PutObject", s3TestBucketARN+"/*", "resource-policy")
	if edge == nil {
		t.Fatal("same-account bucket-policy grant produced no edge")
	}
	got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{})
	if got.State != PolicySupported || got.AllowedBy != "resource-policy" {
		t.Errorf("same-account bucket grant = %+v, want PolicySupported allowed by the resource policy", got)
	}
}

// The account root in an Allow names every principal in this account.
func TestCrossAccount_OwnAccountRootReachesEveryIdentity(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::` + testAcct + `:root"},"Action":"s3:PutObject","Resource":"` + s3TestBucketARN + `/*"}`)
	g, _ := xDiscover(t, doc)

	if xEdge(g, testUserARN, "s3:PutObject", s3TestBucketARN+"/*", "resource-policy") == nil {
		t.Error("the account root grant did not reach alice")
	}
}

// A Deny for the partner in the same policy overrides its Allow.
func TestCrossAccount_DenyInSamePolicyBlocksPartner(t *testing.T) {
	allow := `{"Effect":"Allow","Principal":{"AWS":"` + xPartnerARN + `"},"Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `"}`
	deny := `{"Effect":"Deny","Principal":{"AWS":"` + xPartnerARN + `"},"Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `"}`
	g, _ := xDiscover(t, enfDoc("["+allow+","+deny+"]"))

	edge := xEdge(g, xPartnerARN, "s3:ListBucket", s3TestBucketARN, "resource-policy")
	if edge == nil {
		t.Fatal("expected the allow to produce an edge that the deny then blocks")
	}
	got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{})
	if got.State != Blocked || got.BlockedBy != "resource-policy:explicit-deny" {
		t.Errorf("partner under a same-policy deny = %+v, want blocked", got)
	}
}

// NotPrincipal Allows are counted, not expanded: "everyone except X" cannot be
// turned into a finite set of identities.
func TestCrossAccount_NotPrincipalAllowCountedNotExpanded(t *testing.T) {
	doc := enfDoc(`{"Effect":"Allow","NotPrincipal":{"AWS":"` + testUserARN + `"},"Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `"}`)
	g, stats := xDiscover(t, doc)

	if stats.NotPrincipalAllows != 1 {
		t.Errorf("NotPrincipalAllows = %d, want 1", stats.NotPrincipalAllows)
	}
	for _, p := range g.Permissions {
		if p.SourceType == "resource-policy" {
			t.Errorf("NotPrincipal allow expanded to an edge: %+v", p.Source.CanonicalID)
		}
	}
}
