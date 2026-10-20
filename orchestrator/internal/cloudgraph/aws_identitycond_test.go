package cloudgraph

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const idCond = `{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`

// withAliceDoc adds an inline policy to alice, beside the group policy she already
// inherits, and discovers the account.
func withAliceDoc(t *testing.T, statements string) (*DiscoveredGraph, *AWSDiscoveryStats) {
	t.Helper()
	snap := baseSnapshot(t)
	snap.UserDetailList[0].UserPolicyList = append(snap.UserDetailList[0].UserPolicyList, types.PolicyDetail{
		PolicyName:     aws.String("extra"),
		PolicyDocument: aws.String(enfDoc(statements)),
	})
	return discoverWithOrg(t, snap, fullOrg())
}

// identityEdge returns alice's identity-policy edge for an action on a target,
// conditional or not.
func identityEdge(g *DiscoveredGraph, action, target string, conditional bool) *CloudPermission {
	for _, p := range g.Permissions {
		if p.Source.CanonicalID != testUserARN || p.Action != action || p.Target.CanonicalID != target || p.SourceType != "identity-policy" {
			continue
		}
		if (p.Attributes["identity_condition"] == "true") == conditional {
			return p
		}
	}
	return nil
}

func TestIdentityCondition_ConditionalAllowIsConditional(t *testing.T) {
	g, stats := withAliceDoc(t, `{"Effect":"Allow","Action":"s3:PutObject","Resource":"`+testBucket+`/*","Condition":`+idCond+`}`)
	if stats.ConditionalAllows < 1 {
		t.Errorf("ConditionalAllows = %d, want at least 1", stats.ConditionalAllows)
	}
	edge := identityEdge(g, "s3:PutObject", testBucket+"/*", true)
	if edge == nil {
		t.Fatal("conditional allow produced no edge")
	}
	got := (&AWSEvaluator{}).EvaluatePermission(edge, &RequestContext{})
	if got.State != ConditionallyReachable || got.UnresolvedConds[0] != awsGateCondition {
		t.Errorf("conditional allow = %+v, want ConditionallyReachable", got)
	}
}

// The group grants ListBucket unconditionally. A conditional statement for the same
// action must not turn that unconditional grant conditional.
func TestIdentityCondition_UnconditionalGrantStaysClean(t *testing.T) {
	g, _ := withAliceDoc(t, `{"Effect":"Allow","Action":"s3:ListBucket","Resource":"`+testBucket+`","Condition":`+idCond+`}`)

	clean := identityEdge(g, "s3:ListBucket", testBucket, false)
	if clean == nil {
		t.Fatal("the unconditional group grant produced no edge")
	}
	if got := (&AWSEvaluator{}).EvaluatePermission(clean, &RequestContext{}); got.State != PolicySupported {
		t.Errorf("unconditional grant = %+v, want PolicySupported", got)
	}
	conditional := identityEdge(g, "s3:ListBucket", testBucket, true)
	if conditional == nil {
		t.Fatal("the conditional statement produced no separate edge")
	}
	if got := (&AWSEvaluator{}).EvaluatePermission(conditional, &RequestContext{}); got.State != ConditionallyReachable {
		t.Errorf("conditional statement = %+v, want ConditionallyReachable", got)
	}
}

func TestIdentityCondition_ConditionalDenyDoesNotBlockOutright(t *testing.T) {
	g, _ := withAliceDoc(t, `{"Effect":"Deny","Action":"s3:ListBucket","Resource":"`+testBucket+`","Condition":`+idCond+`}`)
	clean := identityEdge(g, "s3:ListBucket", testBucket, false)
	if got := (&AWSEvaluator{}).EvaluatePermission(clean, &RequestContext{}); got.State != ConditionallyReachable {
		t.Errorf("grant under a conditional deny = %+v, want ConditionallyReachable (not Blocked)", got)
	}
}

// A Deny in one document overrides the group's Allow in another. Before this fix
// each edge only saw its own document, so this over-reported.
func TestIdentityCondition_DenyInAnotherDocumentBlocks(t *testing.T) {
	g, _ := withAliceDoc(t, `{"Effect":"Deny","Action":"s3:ListBucket","Resource":"`+testBucket+`"}`)
	clean := identityEdge(g, "s3:ListBucket", testBucket, false)
	got := (&AWSEvaluator{}).EvaluatePermission(clean, &RequestContext{})
	if got.State != Blocked || got.BlockedBy != "explicit-deny" {
		t.Errorf("group grant under the user's own deny = %+v, want Blocked by explicit-deny", got)
	}
}

func TestIdentityCondition_DenyOnOtherBucketDoesNotBlock(t *testing.T) {
	g, _ := withAliceDoc(t, `{"Effect":"Deny","Action":"s3:ListBucket","Resource":"arn:aws:s3:::other-bucket"}`)
	clean := identityEdge(g, "s3:ListBucket", testBucket, false)
	if got := (&AWSEvaluator{}).EvaluatePermission(clean, &RequestContext{}); got.State != PolicySupported {
		t.Errorf("grant under a deny on another bucket = %+v, want PolicySupported", got)
	}
}
