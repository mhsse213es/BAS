package cloudgraph

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// Preflight probes each AWS read that discovery depends on, one call per check,
// and names the one that fails. It reads only and never writes to the account.
// A later check still runs when an earlier one fails, so one run shows every gap.
//
// Organizations and Backup are optional clients: when one is not configured its
// check is SKIPPED, not failed, since discovery runs without it in that case.
func (c *AWSDiscoveryClient) Preflight(ctx context.Context) []PreflightCheck {
	var checks []PreflightCheck

	checks = append(checks, awsPreflight("sts-identity",
		"caller identity is readable",
		"caller identity not readable (needs a valid session; sts:GetCallerIdentity)",
		func() error {
			_, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			return err
		}))

	checks = append(checks, awsPreflight("iam-authorization-details",
		"account authorization details are readable",
		"authorization details not readable (needs iam:GetAccountAuthorizationDetails)",
		func() error {
			_, err := c.iam.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
				Filter:   []iamtypes.EntityType{iamtypes.EntityTypeUser},
				MaxItems: aws.Int32(1),
			})
			return err
		}))

	bucketCheck, firstBucket := c.preflightListBuckets(ctx)
	checks = append(checks, bucketCheck)
	checks = append(checks, c.preflightBucketPolicy(ctx, firstBucket))

	checks = append(checks, c.preflightOrganization(ctx))

	if c.backup == nil {
		checks = append(checks, PreflightCheck{Name: "backup-vaults-readable", Status: "SKIPPED", Detail: "no Backup client configured"})
	} else {
		checks = append(checks, awsPreflight("backup-vaults-readable",
			"backup vaults are readable",
			"backup vaults not readable (needs backup:ListBackupVaults)",
			func() error {
				_, err := c.backup.ListBackupVaults(ctx, &backup.ListBackupVaultsInput{})
				return err
			}))
	}
	return checks
}

// awsPreflight runs one read. Any error is reported with the supplied gap text
// and the SDK's own message, since AWS error codes differ by service.
func awsPreflight(name, passDetail, gapDetail string, call func() error) PreflightCheck {
	if err := call(); err != nil {
		return PreflightCheck{Name: name, Status: "FAIL", Detail: fmt.Sprintf("%s: %v", gapDetail, err)}
	}
	return PreflightCheck{Name: name, Status: "PASS", Detail: passDetail}
}

// preflightListBuckets lists buckets and returns the first name for the bucket
// policy probe. The listing is the same read discovery uses.
func (c *AWSDiscoveryClient) preflightListBuckets(ctx context.Context) (PreflightCheck, string) {
	var first string
	check := awsPreflight("s3-list-buckets",
		"buckets are listable",
		"buckets not listable (needs s3:ListAllMyBuckets)",
		func() error {
			out, err := c.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
			if err != nil {
				return err
			}
			if len(out.Buckets) > 0 {
				first = aws.ToString(out.Buckets[0].Name)
			}
			return nil
		})
	return check, first
}

// preflightBucketPolicy reads one bucket's policy. A missing policy counts as a
// successful read, because that is how S3 reports a bucket with no policy. With no
// bucket in the account there is nothing to probe, so the check is SKIPPED rather
// than passed: the permission is then unverified, not proven.
func (c *AWSDiscoveryClient) preflightBucketPolicy(ctx context.Context, bucket string) PreflightCheck {
	if bucket == "" {
		return PreflightCheck{Name: "s3-bucket-policy-readable", Status: "SKIPPED", Detail: "no bucket in this account to probe; s3:GetBucketPolicy is unverified"}
	}
	return awsPreflight("s3-bucket-policy-readable",
		"bucket policies are readable",
		fmt.Sprintf("bucket policy not readable for %s (needs s3:GetBucketPolicy)", bucket),
		func() error {
			_, err := c.s3.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket)})
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucketPolicy" {
				return nil
			}
			return err
		})
}

// preflightOrganization reads this account's parent. An account outside any
// organization is a valid state, since no SCPs apply to it, so it passes.
func (c *AWSDiscoveryClient) preflightOrganization(ctx context.Context) PreflightCheck {
	if c.org == nil {
		return PreflightCheck{Name: "organizations-readable", Status: "SKIPPED", Detail: "no Organizations client configured; SCPs will not be read"}
	}
	accountID := c.accountID
	return awsPreflight("organizations-readable",
		"organization hierarchy is readable (or the account is outside an organization)",
		"organization hierarchy not readable (needs organizations:ListParents)",
		func() error {
			_, err := c.org.ListParents(ctx, &organizations.ListParentsInput{ChildId: aws.String(accountID)})
			var notInUse *orgtypes.AWSOrganizationsNotInUseException
			if errors.As(err, &notInUse) {
				return nil
			}
			return err
		})
}
