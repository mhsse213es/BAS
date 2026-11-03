package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"google.golang.org/api/option"

	"github.com/audspect/bas/internal/cloudgraph"
)

// errCloudDiscoveryNotConfigured means this server has no credentials for the
// requested provider. It is a server-side condition, not a bad request, so
// callers map it to 503.
var errCloudDiscoveryNotConfigured = errors.New("cloud discovery is not configured on this server")

// cloudDiscovererFor builds the live discoverer for one account from the server's
// validated settings. The account must be on the allow-list before anything else
// happens; a refused account never reaches a provider client.
//
// Credentials come from the AWS SDK default chain, Application Default Credentials
// for GCP, and the Azure secrets file loaded at startup. Nothing secret is taken
// from the request.
//
// The run names an account; the discoverer proves the credentials belong to it
// before any inventory is read. A mismatch fails the run rather than silently
// evaluating one tenant's permissions under another tenant's label.
func cloudDiscovererFor(ctx context.Context, s *CloudSettings, account cloudgraph.AccountScope) (cloudgraph.Discoverer, error) {
	if err := s.permitAccount(account); err != nil {
		return nil, err
	}
	var inner cloudgraph.Discoverer
	var err error
	switch account.Provider {
	case "aws":
		inner, err = awsDiscovererFor(ctx, account)
	case "gcp":
		inner, err = gcpDiscovererFor(ctx, s, account)
	case "azure":
		inner, err = azureDiscovererFor(s, account)
	default:
		return nil, fmt.Errorf("unknown provider %q", account.Provider)
	}
	if err != nil {
		return nil, err
	}
	return observeDiscoverer(inner, account, s.metricsOrNil()), nil
}

// gcpDiscovererFor builds the GCP client and reports its rate-limit waits.
func gcpDiscovererFor(ctx context.Context, s *CloudSettings, account cloudgraph.AccountScope) (cloudgraph.Discoverer, error) {
	client, err := cloudgraph.NewGCPDiscoveryClient(ctx, account.AccountID, option.WithScopes("https://www.googleapis.com/auth/cloud-platform.read-only"))
	if err != nil {
		return nil, fmt.Errorf("%w: gcp: %v", errCloudDiscoveryNotConfigured, err)
	}
	if m := s.metricsOrNil(); m != nil {
		client.SetRateLimitObserver(func(d time.Duration) { m.RateLimitWait.WithLabelValues("gcp").Observe(d.Seconds()) })
	}
	return accountChecked(account.AccountID, nil, cloudgraph.GCPDiscoverer(client), func(context.Context) (string, error) {
		return account.AccountID, nil
	}), nil
}

// awsConfigFor loads the SDK default credential chain for the account's region.
// The AWS SDK applies its own retries, so no rate-limit wait is reported for AWS.
func awsConfigFor(ctx context.Context, account cloudgraph.AccountScope) (aws.Config, error) {
	region := account.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return aws.Config{}, fmt.Errorf("%w: aws: %v", errCloudDiscoveryNotConfigured, err)
	}
	return cfg, nil
}

func awsDiscovererFor(ctx context.Context, account cloudgraph.AccountScope) (cloudgraph.Discoverer, error) {
	cfg, err := awsConfigFor(ctx, account)
	if err != nil {
		return nil, err
	}
	client := cloudgraph.NewAWSDiscoveryClient(cfg)
	return accountChecked(account.AccountID, nil, cloudgraph.AWSDiscoverer(client), func(ctx context.Context) (string, error) {
		scope, err := client.DiscoverAccount(ctx)
		if err != nil {
			return "", err
		}
		return scope.AccountID, nil
	}), nil
}

// azureConfigFor returns the Azure service principal loaded at startup, and checks
// that its subscription is the one the run names. Nothing is read here: the secret
// was loaded once from the secrets file when the settings were built.
func azureConfigFor(s *CloudSettings, account cloudgraph.AccountScope) (cloudgraph.AzureDiscoveryConfig, error) {
	if s == nil || s.azure == nil {
		return cloudgraph.AzureDiscoveryConfig{}, fmt.Errorf("%w: azure: no Azure credentials were loaded at startup", errCloudDiscoveryNotConfigured)
	}
	if account.AccountID != s.azure.SubscriptionID {
		return cloudgraph.AzureDiscoveryConfig{}, fmt.Errorf("azure: server credentials are for subscription %s, run names %s", s.azure.SubscriptionID, account.AccountID)
	}
	return *s.azure, nil
}

func azureDiscovererFor(s *CloudSettings, account cloudgraph.AccountScope) (cloudgraph.Discoverer, error) {
	cfg, err := azureConfigFor(s, account)
	if err != nil {
		return nil, err
	}
	client := cloudgraph.NewAzureDiscoveryClient(cfg)
	if m := s.metricsOrNil(); m != nil {
		client.SetRateLimitObserver(func(d time.Duration) { m.RateLimitWait.WithLabelValues("azure").Observe(d.Seconds()) })
	}
	return accountChecked(account.AccountID, []string{cfg.ClientSecret}, cloudgraph.AzureDiscoverer(client), func(context.Context) (string, error) {
		return cfg.SubscriptionID, nil
	}), nil
}

// accountCheckedDiscoverer confirms the credentials resolve to the expected
// account before running the inner pass, and scrubs secrets from any error it
// returns. Errors from SDKs and HTTP clients can echo request details; they
// must not reach cloud_runs.error or an API response unredacted.
type accountCheckedDiscoverer struct {
	want    string
	secrets []string
	inner   cloudgraph.Discoverer
	account func(context.Context) (string, error)
}

func accountChecked(want string, secrets []string, inner cloudgraph.Discoverer, account func(context.Context) (string, error)) cloudgraph.Discoverer {
	return accountCheckedDiscoverer{want: want, secrets: secrets, inner: inner, account: account}
}

func (d accountCheckedDiscoverer) Discover(ctx context.Context) (*cloudgraph.DiscoveredGraph, cloudgraph.DiscoveryReport, error) {
	got, err := d.account(ctx)
	if err != nil {
		return nil, nil, d.scrub(err)
	}
	if got != d.want {
		return nil, nil, fmt.Errorf("credentials resolve to account %s, run names %s", got, d.want)
	}
	graph, report, err := d.inner.Discover(ctx)
	if err != nil {
		return nil, nil, d.scrub(err)
	}
	return graph, report, nil
}

// Preflight checks that the credentials resolve to the named account, then runs
// the inner source's checks. The account check comes first and is reported
// alongside the inner checks, not instead of them, so one run shows every gap.
// Inner details are scrubbed of secrets just as discovery errors are.
func (d accountCheckedDiscoverer) Preflight(ctx context.Context) []cloudgraph.PreflightCheck {
	var checks []cloudgraph.PreflightCheck
	got, err := d.account(ctx)
	switch {
	case err != nil:
		checks = append(checks, cloudgraph.PreflightCheck{Name: "account-match", Status: "FAIL",
			Detail: "account could not be resolved: " + cloudgraph.Redact(err.Error(), d.secrets...)})
	case got != d.want:
		checks = append(checks, cloudgraph.PreflightCheck{Name: "account-match", Status: "FAIL",
			Detail: fmt.Sprintf("credentials resolve to account %s, run names %s", got, d.want)})
	default:
		checks = append(checks, cloudgraph.PreflightCheck{Name: "account-match", Status: "PASS",
			Detail: "credentials resolve to the named account"})
	}

	inner, ok := d.inner.(cloudgraph.Preflighter)
	if !ok {
		return append(checks, cloudgraph.PreflightCheck{Name: "discovery-source", Status: "FAIL",
			Detail: "this discovery source cannot be preflighted"})
	}
	for _, c := range inner.Preflight(ctx) {
		c.Detail = cloudgraph.Redact(c.Detail, d.secrets...)
		checks = append(checks, c)
	}
	return checks
}

func (d accountCheckedDiscoverer) scrub(err error) error {
	return errors.New(cloudgraph.Redact(err.Error(), d.secrets...))
}

// discoveryStatusCode maps a construction or gate error to an HTTP status:
//   - an unlisted account is 403;
//   - a busy account is 409;
//   - a saturated server is 503 (retry later);
//   - missing server credentials are 503;
//   - anything else names an account the server cannot serve, which is 400.
func discoveryStatusCode(err error) int {
	switch {
	case errors.Is(err, errCloudAccountNotAllowed):
		return http.StatusForbidden
	case errors.Is(err, errCloudAccountBusy):
		return http.StatusConflict
	case errors.Is(err, errCloudServerSaturated):
		return http.StatusServiceUnavailable
	case errors.Is(err, errCloudDiscoveryNotConfigured):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// cloudEventSourceFor returns the provider's live audit-log source for the
// account, using the same server-side credentials as discovery. It applies the
// same allow-list, so an unlisted account is never read here either.
func cloudEventSourceFor(ctx context.Context, s *CloudSettings, account cloudgraph.AccountScope) (cloudgraph.EventSource, error) {
	if err := s.permitAccount(account); err != nil {
		return nil, err
	}
	switch account.Provider {
	case "aws":
		cfg, err := awsConfigFor(ctx, account)
		if err != nil {
			return nil, err
		}
		return &cloudgraph.CloudTrailSource{API: cloudtrail.NewFromConfig(cfg)}, nil
	case "azure":
		cfg, err := azureConfigFor(s, account)
		if err != nil {
			return nil, err
		}
		return cloudgraph.NewActivityLogSource(cloudgraph.NewAzureDiscoveryClient(cfg)), nil
	case "gcp":
		src, err := cloudgraph.NewGCPAuditLogSource(ctx, account.AccountID,
			option.WithScopes("https://www.googleapis.com/auth/cloud-platform.read-only"))
		if err != nil {
			return nil, fmt.Errorf("%w: gcp: %v", errCloudDiscoveryNotConfigured, err)
		}
		return src, nil
	default:
		return nil, fmt.Errorf("unknown provider %q", account.Provider)
	}
}
