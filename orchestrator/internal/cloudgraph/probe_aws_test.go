package cloudgraph

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

type fakeProbeSTS struct{ account string }

func (f fakeProbeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{Account: aws.String(f.account)}, nil
}

// fakeProbeS3 counts every call, so a test can prove that nothing ran after a
// failed gate.
type fakeProbeS3 struct {
	buckets   []string
	listErr   error
	objectErr error
	calls     int
}

func (f *fakeProbeS3) ListBuckets(context.Context, *s3.ListBucketsInput, ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	f.calls++
	out := &s3.ListBucketsOutput{}
	for _, b := range f.buckets {
		out.Buckets = append(out.Buckets, s3types.Bucket{Name: aws.String(b)})
	}
	return out, f.listErr
}

func (f *fakeProbeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.calls++
	if aws.ToInt32(in.MaxKeys) != 1 {
		panic("probe must list at most one key")
	}
	return &s3.ListObjectsV2Output{}, f.objectErr
}

type fakeProbeIAM struct {
	decision iamtypes.PolicyEvaluationDecisionType
	err      error
	calls    int
}

func (f *fakeProbeIAM) SimulatePrincipalPolicy(context.Context, *iam.SimulatePrincipalPolicyInput, ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []iamtypes.EvaluationResult{{EvalDecision: f.decision}}}, nil
}

func awsProbe(account string, s3api *fakeProbeS3, iamapi *fakeProbeIAM) *AWSProber {
	return NewAWSProber(fakeProbeSTS{account: account}, s3api, iamapi)
}

// The credentials must belong to the named account. If they do not, nothing runs.
func TestAWSProber_IdentityMismatchStopsBeforeAnyCall(t *testing.T) {
	s3api := &fakeProbeS3{buckets: []string{"corp-bucket"}}
	p := awsProbe("999999999999", s3api, &fakeProbeIAM{})
	_, err := p.Probe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"))
	if err == nil || !strings.Contains(err.Error(), "resolve to account 999999999999") {
		t.Fatalf("err = %v, want an identity mismatch", err)
	}
	if s3api.calls != 0 {
		t.Fatal("S3 was called although the identity check failed")
	}
}

// A bucket the account does not own is refused before any object read.
func TestAWSProber_BucketNotOwnedIsRefused(t *testing.T) {
	s3api := &fakeProbeS3{buckets: []string{"other-bucket"}}
	p := awsProbe(probeAcct, s3api, &fakeProbeIAM{})
	_, err := p.Probe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"))
	if err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("err = %v, want a not-owned refusal", err)
	}
	if s3api.calls != 1 {
		t.Errorf("S3 calls = %d, want only the bucket listing", s3api.calls)
	}
}

func TestAWSProber_ListBucketAllowed(t *testing.T) {
	s3api := &fakeProbeS3{buckets: []string{"corp-bucket"}}
	out, err := awsProbe(probeAcct, s3api, &fakeProbeIAM{}).Probe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if out.Outcome != "allowed" || out.Evidence != EvidenceObserved {
		t.Errorf("outcome = %+v, want allowed with observed evidence", out)
	}
}

func TestAWSProber_ListBucketAccessDeniedIsDenied(t *testing.T) {
	s3api := &fakeProbeS3{buckets: []string{"corp-bucket"}, objectErr: &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}}
	out, err := awsProbe(probeAcct, s3api, &fakeProbeIAM{}).Probe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if out.Outcome != "denied" || out.Evidence != EvidenceObserved {
		t.Errorf("outcome = %+v, want denied with observed evidence", out)
	}
}

// Any other S3 error is an error, not a denial. It must not be read as a control
// that blocked the probe.
func TestAWSProber_OtherS3ErrorIsNotADenial(t *testing.T) {
	s3api := &fakeProbeS3{buckets: []string{"corp-bucket"}, objectErr: errors.New("connection reset")}
	_, err := awsProbe(probeAcct, s3api, &fakeProbeIAM{}).Probe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"))
	if err == nil {
		t.Fatal("a transport error must not be reported as an outcome")
	}
}

// The simulator's answer is labelled as simulated, never as observed.
func TestAWSProber_SimulatedDecisions(t *testing.T) {
	target := "arn:aws:iam::" + probeAcct + ":role/app"
	cases := map[iamtypes.PolicyEvaluationDecisionType]string{
		iamtypes.PolicyEvaluationDecisionTypeAllowed:      "simulated-allowed",
		iamtypes.PolicyEvaluationDecisionTypeImplicitDeny: "simulated-denied",
		iamtypes.PolicyEvaluationDecisionTypeExplicitDeny: "simulated-denied",
	}
	for decision, want := range cases {
		out, err := awsProbe(probeAcct, &fakeProbeS3{}, &fakeProbeIAM{decision: decision}).
			Probe(context.Background(), simReq(ProbeLiveReadOnly, target, "s3:GetObject"))
		if err != nil {
			t.Fatalf("%s: Probe: %v", decision, err)
		}
		if out.Outcome != want || out.Evidence != EvidenceSimulated {
			t.Errorf("%s: outcome = %+v, want %s with simulated evidence", decision, out, want)
		}
		if !strings.Contains(out.Detail, "not an observed call") {
			t.Errorf("%s: detail must say the answer is simulated, got %q", decision, out.Detail)
		}
	}
}

// A probe that goes through RunProbe keeps the evidence kind the registry expects.
func TestAWSProber_ThroughRunProbeKeepsEvidenceKind(t *testing.T) {
	p := awsProbe(probeAcct, &fakeProbeS3{buckets: []string{"corp-bucket"}}, &fakeProbeIAM{decision: iamtypes.PolicyEvaluationDecisionTypeAllowed})
	res, err := RunProbe(context.Background(), s3Req(ProbeLiveReadOnly, "arn:aws:s3:::corp-bucket"), probeAllow(t), p)
	if err != nil {
		t.Fatalf("RunProbe: %v", err)
	}
	if res.Evidence != EvidenceObserved || res.Simulated {
		t.Errorf("S3 result = %+v, want observed, not simulated", res)
	}
}
