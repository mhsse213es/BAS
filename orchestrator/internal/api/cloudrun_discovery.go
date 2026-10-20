package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"google.golang.org/api/option"

	"github.com/audspect/bas/internal/cloudgraph"
)

// errCloudDiscoveryNotConfigured means this server has no credentials for the
// requested provider. It is a server-side condition, not a bad request, so
// callers map it to 503.
var errCloudDiscoveryNotConfigured = errors.New("cloud discovery is not configured on this server")

// cloudDiscovererFor builds the live discoverer for one account from server
// configuration. Credentials are read from the environment only -- the AWS
// SDK default chain, Application Default Credentials for GCP, and service
// principal variables for Azure. Nothing secret is taken from the request.
//
// The run names an account; the discoverer proves the credentials belong to
// it before any inventory is read. A mismatch fails the run rather than
// silently evaluating one tenant's permissions under another tenant's label.
func cloudDiscovererFor(ctx context.Context, account cloudgraph.AccountScope) (cloudgraph.Discoverer, error) {
	switch account.Provider {
	case "aws":
		return awsDiscovererFor(ctx, account)
	case "gcp":
		client, err := cloudgraph.NewGCPDiscoveryClient(ctx, account.AccountID, option.WithScopes("https://www.googleapis.com/auth/cloud-platform.read-only"))
		if err != nil {
			return nil, fmt.Errorf("%w: gcp: %v", errCloudDiscoveryNotConfigured, err)
		}
		return accountChecked(account.AccountID, nil, cloudgraph.GCPDiscoverer(client), func(context.Context) (string, error) {
			return account.AccountID, nil
		}), nil
	case "azure":
		return azureDiscovererFor(account)
	default:
		return nil, fmt.Errorf("unknown provider %q", account.Provider)
	}
}

func awsDiscovererFor(ctx context.Context, account cloudgraph.AccountScope) (cloudgraph.Discoverer, error) {
	region := account.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("%w: aws: %v", errCloudDiscoveryNotConfigured, err)
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

// azureDiscovererFor reads the service principal from the environment. The
// subscription in the environment must be the one the run names.
func azureDiscovererFor(account cloudgraph.AccountScope) (cloudgraph.Discoverer, error) {
	cfg := cloudgraph.AzureDiscoveryConfig{
		TenantID:       os.Getenv("AZURE_TENANT_ID"),
		ClientID:       os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret:   os.Getenv("AZURE_CLIENT_SECRET"),
		SubscriptionID: os.Getenv("AZURE_SUBSCRIPTION_ID"),
	}
	for name, v := range map[string]string{
		"AZURE_TENANT_ID": cfg.TenantID, "AZURE_CLIENT_ID": cfg.ClientID,
		"AZURE_CLIENT_SECRET": cfg.ClientSecret, "AZURE_SUBSCRIPTION_ID": cfg.SubscriptionID,
	} {
		if v == "" {
			// Names the variable, never its value.
			return nil, fmt.Errorf("%w: azure: %s is not set", errCloudDiscoveryNotConfigured, name)
		}
	}
	if account.AccountID != cfg.SubscriptionID {
		return nil, fmt.Errorf("azure: server credentials are for subscription %s, run names %s", cfg.SubscriptionID, account.AccountID)
	}
	client := cloudgraph.NewAzureDiscoveryClient(cfg)
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

func (d accountCheckedDiscoverer) scrub(err error) error {
	return errors.New(cloudgraph.Redact(err.Error(), d.secrets...))
}

// discoveryStatusCode maps a discoverer-construction error to an HTTP status:
// a server that lacks credentials for the provider is 503, anything else is a
// request that names an account the server cannot serve, which is 400.
func discoveryStatusCode(err error) int {
	if errors.Is(err, errCloudDiscoveryNotConfigured) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadRequest
}
