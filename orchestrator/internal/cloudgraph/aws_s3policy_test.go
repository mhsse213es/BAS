package cloudgraph

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
)

const (
	s3TestBucket    = "corp-backups"
	s3TestBucketARN = "arn:aws:s3:::corp-backups"
	s3TestAccount   = "arn:aws:iam::111122223333:root"
	s3BobARN        = "arn:aws:iam::111122223333:user/bob"
)

// s3Discover runs discovery over the base snapshot with a bucket that has the
// given policy, and returns the graph and stats.
func s3Discover(t *testing.T, s3api *fakeS3) (*DiscoveredGraph, *AWSDiscoveryStats) {
	t.Helper()
	snap := baseSnapshot(t)
	c := NewAWSDiscoveryClientWith(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}},
		&fakeSTS{account: testAcct}, s3api, "us-east-1").WithOrganizations(&fakeOrg{})
	g, stats, err := c.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return g, stats
}

func bucketPolicyFake(doc string) *fakeS3 {
	return &fakeS3{names: []string{s3TestBucket}, policies: map[string]string{s3TestBucket: doc}}
}

func TestS3Policy_DenyForPrincipalBlocksGrant(t *testing.T) {
	doc := enfDoc(`{"Effect":"Deny","Principal":{"AWS":"` + testUserARN + `"},"Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `"}`)
	g, stats := s3Discover(t, bucketPolicyFake(doc))

	if stats.BucketPolicies != 1 {
		t.Errorf("BucketPolicies = %d, want 1", stats.BucketPolicies)
	}
	got := evalAlice(t, g, "s3:ListBucket")
	if got.State != Blocked || got.BlockedBy != "resource-policy:explicit-deny" {
		t.Errorf("ListBucket under a bucket deny = %+v, want blocked by the resource policy", got)
	}
}

func TestS3Policy_DenyOnOtherActionOrPrincipalDoesNotBlock(t *testing.T) {
	cases := map[string]string{
		"other action":    enfDoc(`{"Effect":"Deny","Principal":{"AWS":"` + testUserARN + `"},"Action":"s3:PutObject","Resource":"` + s3TestBucketARN + `"}`),
		"other principal": enfDoc(`{"Effect":"Deny","Principal":{"AWS":"` + s3BobARN + `"},"Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `"}`),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			g, _ := s3Discover(t, bucketPolicyFake(doc))
			if got := evalAlice(t, g, "s3:ListBucket"); got.State != PolicySupported {
				t.Errorf("ListBucket = %+v, want the grant to stand", got)
			}
		})
	}
}

func TestS3Policy_WildcardAndAccountRootPrincipalsBlock(t *testing.T) {
	cases := map[string]string{
		"wildcard principal": enfDoc(`{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"` + s3TestBucketARN + `"}`),
		"account root":       enfDoc(`{"Effect":"Deny","Principal":{"AWS":"` + s3TestAccount + `"},"Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `"}`),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			g, _ := s3Discover(t, bucketPolicyFake(doc))
			if got := evalAlice(t, g, "s3:ListBucket"); got.State != Blocked {
				t.Errorf("ListBucket = %+v, want blocked", got)
			}
		})
	}
}

func TestS3Policy_ConditionalDenyIsConditional(t *testing.T) {
	doc := enfDoc(`{"Effect":"Deny","Principal":"*","Action":"s3:ListBucket","Resource":"` + s3TestBucketARN + `","Condition":{"Bool":{"aws:SecureTransport":"false"}}}`)
	g, _ := s3Discover(t, bucketPolicyFake(doc))
	if got := evalAlice(t, g, "s3:ListBucket"); got.State != ConditionallyReachable {
		t.Errorf("ListBucket under a conditional bucket deny = %+v, want ConditionallyReachable", got)
	}
}

func TestS3Policy_UnparseablePolicyIsUnknown(t *testing.T) {
	g, stats := s3Discover(t, bucketPolicyFake("not a policy"))
	if stats.BucketPoliciesUnreadable != 1 {
		t.Errorf("BucketPoliciesUnreadable = %d, want 1", stats.BucketPoliciesUnreadable)
	}
	if got := evalAlice(t, g, "s3:ListBucket"); got.State != Unknown {
		t.Errorf("ListBucket with an unreadable bucket policy = %+v, want Unknown, not a clean grant", got)
	}
}

func TestS3Policy_NoPolicyIsNormal(t *testing.T) {
	g, stats := s3Discover(t, &fakeS3{names: []string{s3TestBucket}})
	if stats.BucketPolicies != 0 || stats.BucketPoliciesUnreadable != 0 {
		t.Errorf("stats = %+v, want no policies and no unreadable policies", stats)
	}
	if got := evalAlice(t, g, "s3:ListBucket"); got.State != PolicySupported {
		t.Errorf("ListBucket with no bucket policy = %+v, want the grant to stand", got)
	}
}

func TestS3Policy_DeniedReadFailsPassNamingPermission(t *testing.T) {
	snap := baseSnapshot(t)
	s3api := &fakeS3{names: []string{s3TestBucket}, policyErr: &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}}
	c := NewAWSDiscoveryClientWith(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{snap}},
		&fakeSTS{account: testAcct}, s3api, "us-east-1").WithOrganizations(&fakeOrg{})
	_, _, err := c.Discover(context.Background())
	if err == nil {
		t.Fatal("Discover must fail when a bucket policy cannot be read; its denies would be invisible")
	}
	if !strings.Contains(err.Error(), "s3:GetBucketPolicy") {
		t.Errorf("err = %v, want the missing s3:GetBucketPolicy permission named", err)
	}
}

func TestAWSResourcePolicyGate_ResourceAndNotClauses(t *testing.T) {
	src := testUserARN
	edge := func(target, action string) *CloudPermission {
		return &CloudPermission{
			Source: &CloudIdentity{CanonicalID: src},
			Target: &CloudResource{CanonicalID: target},
			Action: action,
		}
	}
	cases := []struct {
		name   string
		doc    string
		target string
		action string
		want   PathState
	}{
		{
			name:   "object resource pattern covers object, not bucket",
			doc:    enfDoc(`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::corp-backups/*"}`),
			target: "arn:aws:s3:::corp-backups/key.txt", action: "s3:GetObject", want: Blocked,
		},
		{
			name:   "same statement does not cover the bucket itself",
			doc:    enfDoc(`{"Effect":"Deny","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::corp-backups/*"}`),
			target: "arn:aws:s3:::corp-backups", action: "s3:GetObject", want: PolicySupported,
		},
		{
			name:   "NotPrincipal naming the source exempts it",
			doc:    enfDoc(`{"Effect":"Deny","NotPrincipal":{"AWS":"` + src + `"},"Action":"s3:*","Resource":"*"}`),
			target: s3TestBucketARN, action: "s3:ListBucket", want: PolicySupported,
		},
		{
			name:   "NotPrincipal not naming the source denies it",
			doc:    enfDoc(`{"Effect":"Deny","NotPrincipal":{"AWS":"` + s3BobARN + `"},"Action":"s3:*","Resource":"*"}`),
			target: s3TestBucketARN, action: "s3:ListBucket", want: Blocked,
		},
		{
			name:   "NotAction deny spares the named action",
			doc:    enfDoc(`{"Effect":"Deny","Principal":"*","NotAction":"s3:ListBucket","Resource":"*"}`),
			target: s3TestBucketARN, action: "s3:ListBucket", want: PolicySupported,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			state, _ := awsResourcePolicyGate(c.doc, edge(c.target, c.action))
			if state != c.want {
				t.Errorf("awsResourcePolicyGate = %s, want %s", state, c.want)
			}
		})
	}
}

func TestAWSBucketARN(t *testing.T) {
	cases := map[string]string{
		"arn:aws:s3:::corp-backups":           "arn:aws:s3:::corp-backups",
		"arn:aws:s3:::corp-backups/key/a.txt": "arn:aws:s3:::corp-backups",
		"arn:aws:s3:::*":                      "",
		"arn:aws:iam::111122223333:role/x":    "",
	}
	for in, want := range cases {
		if got := awsBucketARN(in); got != want {
			t.Errorf("awsBucketARN(%q) = %q, want %q", in, got, want)
		}
	}
}
