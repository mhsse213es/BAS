//go:build integration

package cloudgraph

import (
	"context"
	"os"
	"testing"
)

// TestAzureDiscovery_Integration is the only place "verified against the
// real tenant" can honestly be claimed for this milestone. It is excluded
// from normal test runs by the integration build tag and is skipped at
// runtime if credentials aren't set -- run explicitly once a service
// principal exists for essen065.onmicrosoft.com:
//
//	go test -tags=integration ./internal/cloudgraph -run TestAzureDiscovery_Integration -v
func TestAzureDiscovery_Integration(t *testing.T) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if tenantID == "" || clientID == "" || clientSecret == "" || subscriptionID == "" {
		t.Skip("AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET/AZURE_SUBSCRIPTION_ID not set")
	}

	c := NewAzureDiscoveryClient(AzureDiscoveryConfig{
		TenantID:       tenantID,
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		SubscriptionID: subscriptionID,
	})
	ctx := context.Background()

	identities, idStats, err := c.DiscoverIdentities(ctx)
	if err != nil {
		t.Fatalf("DiscoverIdentities: %v", err)
	}
	if idStats.ItemsFound == 0 {
		t.Fatalf("DiscoverIdentities: found 0 identities in tenant %s, expected at least 1", tenantID)
	}

	resources, resStats, err := c.DiscoverResources(ctx)
	if err != nil {
		t.Fatalf("DiscoverResources: %v", err)
	}
	if resStats.ItemsFound == 0 {
		t.Fatalf("DiscoverResources: found 0 resources in subscription %s, expected at least 1", subscriptionID)
	}

	permissions, permStats, err := c.DiscoverPermissions(ctx, identities, resources)
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}

	t.Logf("Discovered %d identities, %d resources, %d permissions (%d unresolved principals)",
		idStats.ItemsFound, resStats.ItemsFound, permStats.ItemsFound, permStats.UnresolvedPrincipals)
}
