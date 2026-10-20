package cloudgraph

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// AWSProbeSTSAPI is the identity read a probe makes before it touches anything.
type AWSProbeSTSAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// AWSProbeS3API is the two S3 reads a probe makes. Both only read.
type AWSProbeS3API interface {
	ListBuckets(ctx context.Context, params *s3.ListBucketsInput, optFns ...func(*s3.Options)) (*s3.ListBucketsOutput, error)
	ListObjectsV2(ctx context.Context, params *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// AWSProbeIAMAPI is the policy simulator. It evaluates a principal's policies
// for one action. It changes nothing.
type AWSProbeIAMAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// AWSProber runs the AWS probes in the registry. The clients come from server
// configuration. A request never supplies them.
type AWSProber struct {
	sts AWSProbeSTSAPI
	s3  AWSProbeS3API
	iam AWSProbeIAMAPI
}

// NewAWSProber builds a prober from already-configured clients.
func NewAWSProber(stsAPI AWSProbeSTSAPI, s3API AWSProbeS3API, iamAPI AWSProbeIAMAPI) *AWSProber {
	return &AWSProber{sts: stsAPI, s3: s3API, iam: iamAPI}
}

// Probe confirms the credentials belong to the named account, then runs the
// operation. Any failure before the operation runs returns an error, and the
// operation is not attempted.
func (p *AWSProber) Probe(ctx context.Context, req ProbeRequest) (ProbeOutcome, error) {
	id, err := p.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return ProbeOutcome{}, fmt.Errorf("aws probe: caller identity: %w", err)
	}
	if got := aws.ToString(id.Account); got != req.AccountID {
		return ProbeOutcome{}, fmt.Errorf("aws probe: credentials resolve to account %s, probe names %s", got, req.AccountID)
	}

	switch req.Operation {
	case "s3:ListBucket":
		return p.probeListBucket(ctx, req)
	case "iam:SimulatePrincipalPolicy":
		return p.probeSimulate(ctx, req)
	default:
		return ProbeOutcome{}, fmt.Errorf("aws probe: no implementation for %q", req.Operation)
	}
}

// probeListBucket lists at most one object key in a bucket this account owns.
// The bucket must appear in the account's own bucket listing. A probe will not
// reach into a bucket the account does not own.
func (p *AWSProber) probeListBucket(ctx context.Context, req ProbeRequest) (ProbeOutcome, error) {
	bucket := strings.TrimPrefix(req.Target, "arn:aws:s3:::")

	owned, err := p.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return ProbeOutcome{}, fmt.Errorf("aws probe: listing buckets: %w", err)
	}
	found := false
	for _, b := range owned.Buckets {
		if aws.ToString(b.Name) == bucket {
			found = true
			break
		}
	}
	if !found {
		return ProbeOutcome{}, fmt.Errorf("aws probe: bucket %s is not owned by account %s", bucket, req.AccountID)
	}

	_, err = p.s3.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), MaxKeys: aws.Int32(1)})
	if err == nil {
		return ProbeOutcome{Outcome: "allowed", Evidence: EvidenceObserved, Detail: "ListObjectsV2 succeeded; one key listing only"}, nil
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "AccessDenied" {
		return ProbeOutcome{Outcome: "denied", Evidence: EvidenceObserved, Detail: "ListObjectsV2 returned AccessDenied"}, nil
	}
	return ProbeOutcome{}, fmt.Errorf("aws probe: ListObjectsV2: %w", err)
}

// probeSimulate asks the policy simulator whether the target principal's policies
// would allow the action. The answer is a simulated decision and is labelled as one.
func (p *AWSProber) probeSimulate(ctx context.Context, req ProbeRequest) (ProbeOutcome, error) {
	out, err := p.iam.SimulatePrincipalPolicy(ctx, &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(req.Target),
		ActionNames:     []string{req.Action},
	})
	if err != nil {
		return ProbeOutcome{}, fmt.Errorf("aws probe: SimulatePrincipalPolicy: %w", err)
	}
	if len(out.EvaluationResults) != 1 {
		return ProbeOutcome{}, fmt.Errorf("aws probe: simulator returned %d results, expected 1", len(out.EvaluationResults))
	}
	switch decision := out.EvaluationResults[0].EvalDecision; decision {
	case iamtypes.PolicyEvaluationDecisionTypeAllowed:
		return ProbeOutcome{Outcome: "simulated-allowed", Evidence: EvidenceSimulated, Detail: "policy simulator allows " + req.Action + "; a simulated decision, not an observed call"}, nil
	case iamtypes.PolicyEvaluationDecisionTypeExplicitDeny, iamtypes.PolicyEvaluationDecisionTypeImplicitDeny:
		return ProbeOutcome{Outcome: "simulated-denied", Evidence: EvidenceSimulated, Detail: "policy simulator returns " + string(decision) + "; a simulated decision, not an observed call"}, nil
	default:
		return ProbeOutcome{}, fmt.Errorf("aws probe: unexpected simulator decision %q", decision)
	}
}
