package cloudgraph

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// pfSTS is a caller-identity stub that can fail.
type pfSTS struct{ err error }

func (f *pfSTS) GetCallerIdentity(_ context.Context, _ *sts.GetCallerIdentityInput, _ ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{}, f.err
}

// pfBackup is a backup-vault stub that can fail.
type pfBackup struct{ err error }

func (f *pfBackup) ListBackupVaults(_ context.Context, _ *backup.ListBackupVaultsInput, _ ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	return &backup.ListBackupVaultsOutput{}, f.err
}

// pfClient builds a client whose every dependency is a working fake unless the
// caller replaces one.
func pfClient(t *testing.T, iamAPI AWSIAMAPI, stsAPI AWSSTSAPI, s3API AWSS3API) *AWSDiscoveryClient {
	t.Helper()
	return NewAWSDiscoveryClientWith(iamAPI, stsAPI, s3API, "us-east-1").
		WithOrganizations(fullOrg()).
		WithBackup(&pfBackup{})
}

func pfOK(t *testing.T) *AWSDiscoveryClient {
	return pfClient(t, &fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}},
		&fakeSTS{account: testAcct}, &fakeS3{names: []string{s3TestBucket}})
}

func awsCheck(t *testing.T, checks []PreflightCheck, name string) PreflightCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, checks)
	return PreflightCheck{}
}

func TestAWSPreflight_AllPass(t *testing.T) {
	checks := pfOK(t).Preflight(context.Background())
	for _, c := range checks {
		if c.Status != "PASS" {
			t.Errorf("%s = %s (%s), want PASS", c.Name, c.Status, c.Detail)
		}
	}
	if len(checks) != 6 {
		t.Errorf("got %d checks, want 6", len(checks))
	}
}

// A failure in one read must not hide the others: every check still runs.
func TestAWSPreflight_IAMFailureDoesNotHideOthers(t *testing.T) {
	c := pfClient(t, &fakeIAM{err: errors.New("AccessDenied: iam:GetAccountAuthorizationDetails")},
		&fakeSTS{account: testAcct}, &fakeS3{names: []string{s3TestBucket}})
	checks := c.Preflight(context.Background())

	iamCheck := awsCheck(t, checks, "iam-authorization-details")
	if iamCheck.Status != "FAIL" || !strings.Contains(iamCheck.Detail, "iam:GetAccountAuthorizationDetails") {
		t.Errorf("iam check = %+v, want FAIL naming the action", iamCheck)
	}
	if got := awsCheck(t, checks, "sts-identity"); got.Status != "PASS" {
		t.Errorf("sts check = %+v, want PASS", got)
	}
	if got := awsCheck(t, checks, "backup-vaults-readable"); got.Status != "PASS" {
		t.Errorf("backup check = %+v, want PASS", got)
	}
}

func TestAWSPreflight_STSFailureIsNamed(t *testing.T) {
	c := pfClient(t, &fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}},
		&pfSTS{err: errors.New("ExpiredToken")}, &fakeS3{names: []string{s3TestBucket}})
	got := awsCheck(t, c.Preflight(context.Background()), "sts-identity")
	if got.Status != "FAIL" || !strings.Contains(got.Detail, "ExpiredToken") {
		t.Errorf("sts check = %+v, want FAIL with the SDK error", got)
	}
}

// A bucket with no policy is a readable state, not a gap.
func TestAWSPreflight_NoBucketPolicyPasses(t *testing.T) {
	checks := pfOK(t).Preflight(context.Background())
	if got := awsCheck(t, checks, "s3-bucket-policy-readable"); got.Status != "PASS" {
		t.Errorf("bucket policy check = %+v, want PASS (no policy is NoSuchBucketPolicy)", got)
	}
}

func TestAWSPreflight_BucketPolicyDeniedIsFail(t *testing.T) {
	s3api := &fakeS3{names: []string{s3TestBucket}, policyErr: &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}}
	c := pfClient(t, &fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}, &fakeSTS{account: testAcct}, s3api)
	got := awsCheck(t, c.Preflight(context.Background()), "s3-bucket-policy-readable")
	if got.Status != "FAIL" || !strings.Contains(got.Detail, "s3:GetBucketPolicy") {
		t.Errorf("bucket policy check = %+v, want FAIL naming s3:GetBucketPolicy", got)
	}
}

// With no bucket there is nothing to probe. The check is SKIPPED, not passed,
// because the permission is unverified rather than proven.
func TestAWSPreflight_NoBucketIsSkippedNotPassed(t *testing.T) {
	c := pfClient(t, &fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}}, &fakeSTS{account: testAcct}, &fakeS3{})
	got := awsCheck(t, c.Preflight(context.Background()), "s3-bucket-policy-readable")
	if got.Status != "SKIPPED" {
		t.Errorf("bucket policy check with no buckets = %+v, want SKIPPED", got)
	}
}

// An account outside any organization is a valid state, since no SCPs apply.
func TestAWSPreflight_NotInOrganizationPasses(t *testing.T) {
	c := pfOK(t).WithOrganizations(&fakeOrg{err: &orgtypes.AWSOrganizationsNotInUseException{}})
	got := awsCheck(t, c.Preflight(context.Background()), "organizations-readable")
	if got.Status != "PASS" {
		t.Errorf("organizations check = %+v, want PASS", got)
	}
}

func TestAWSPreflight_OrganizationDeniedIsFail(t *testing.T) {
	c := pfOK(t).WithOrganizations(&fakeOrg{err: &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "denied"}})
	got := awsCheck(t, c.Preflight(context.Background()), "organizations-readable")
	if got.Status != "FAIL" || !strings.Contains(got.Detail, "organizations:ListParents") {
		t.Errorf("organizations check = %+v, want FAIL naming organizations:ListParents", got)
	}
}

func TestAWSPreflight_OptionalClientsSkipped(t *testing.T) {
	c := NewAWSDiscoveryClientWith(&fakeIAM{pages: []*iam.GetAccountAuthorizationDetailsOutput{baseSnapshot(t)}},
		&fakeSTS{account: testAcct}, &fakeS3{names: []string{s3TestBucket}}, "us-east-1")
	checks := c.Preflight(context.Background())
	if got := awsCheck(t, checks, "organizations-readable"); got.Status != "SKIPPED" {
		t.Errorf("organizations without a client = %+v, want SKIPPED", got)
	}
	if got := awsCheck(t, checks, "backup-vaults-readable"); got.Status != "SKIPPED" {
		t.Errorf("backup without a client = %+v, want SKIPPED", got)
	}
}

func TestAWSPreflight_BackupDeniedIsFail(t *testing.T) {
	c := pfOK(t).WithBackup(&pfBackup{err: errors.New("AccessDeniedException: backup:ListBackupVaults")})
	got := awsCheck(t, c.Preflight(context.Background()), "backup-vaults-readable")
	if got.Status != "FAIL" || !strings.Contains(got.Detail, "backup:ListBackupVaults") {
		t.Errorf("backup check = %+v, want FAIL naming backup:ListBackupVaults", got)
	}
}
