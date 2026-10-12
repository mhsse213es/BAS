package cloudgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/audspect/bas/internal/platform/msauth"
)

// AzureDiscoveryConfig holds the connection settings for one Azure tenant's
// service principal, used for both Microsoft Graph (identities) and Azure
// Resource Manager (resources, role assignments) calls.
type AzureDiscoveryConfig struct {
	TenantID       string
	ClientID       string
	ClientSecret   string
	SubscriptionID string
}

// AzureDiscoveryClient discovers real identities, resources, and role
// assignments from a live Azure tenant and normalizes them into cloudgraph's
// provider-agnostic CloudIdentity/CloudResource/CloudPermission types.
// BaseURL fields are exported so tests can point them at an httptest.Server,
// matching the pattern internal/vendors/defender.Client already uses.
type AzureDiscoveryClient struct {
	GraphBaseURL string // defaults to https://graph.microsoft.com/v1.0
	ARMBaseURL   string // defaults to https://management.azure.com

	graphTokens *msauth.EntraTokenSource
	armTokens   *msauth.EntraTokenSource
	httpClient  *http.Client

	subscriptionID string
}

func NewAzureDiscoveryClient(cfg AzureDiscoveryConfig) *AzureDiscoveryClient {
	return &AzureDiscoveryClient{
		GraphBaseURL: "https://graph.microsoft.com/v1.0",
		ARMBaseURL:   "https://management.azure.com",
		graphTokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://graph.microsoft.com/.default"),
		armTokens: msauth.NewEntraTokenSource(cfg.TenantID, cfg.ClientID, cfg.ClientSecret,
			"https://management.azure.com/.default"),
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		subscriptionID: cfg.SubscriptionID,
	}
}

// GraphTokenURL exposes the Graph token source's overridable URL for tests.
func (c *AzureDiscoveryClient) GraphTokenURL() *string { return &c.graphTokens.TokenURL }

// ARMTokenURL exposes the ARM token source's overridable URL for tests.
func (c *AzureDiscoveryClient) ARMTokenURL() *string { return &c.armTokens.TokenURL }

// DiscoveryStats reports what happened during one discovery call, including
// anything that couldn't be resolved -- never silently dropped.
type DiscoveryStats struct {
	ItemsFound           int
	UnresolvedPrincipals int
}

// azurePage is the shared shape of a Microsoft Graph or Azure Resource
// Manager list response. Graph uses "@odata.nextLink"; ARM uses "nextLink".
// Only one will ever be populated for a given response, so reading
// whichever is non-empty is unambiguous.
type azurePage struct {
	Value     []json.RawMessage `json:"value"`
	GraphNext string            `json:"@odata.nextLink"`
	ARMNext   string            `json:"nextLink"`
}

// fetchAllPages performs an authenticated GET against startURL and follows
// pagination until the response carries no next link, returning every
// "value" element seen. Fails fast: any transport, status, or decode error
// aborts immediately and returns no partial results. A nextLink that is
// identical to the URL just fetched is treated as a malformed response
// (rather than looped on forever) and returns an error.
func (c *AzureDiscoveryClient) fetchAllPages(ctx context.Context, startURL string, tokens *msauth.EntraTokenSource) ([]json.RawMessage, error) {
	var all []json.RawMessage
	url := startURL
	for url != "" {
		token, err := tokens.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure discovery: acquiring token: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("azure discovery: building request for %s: %w", url, err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("azure discovery: request to %s: %w", url, err)
		}
		var page azurePage
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		statusCode := resp.StatusCode
		resp.Body.Close()

		if statusCode != http.StatusOK {
			return nil, fmt.Errorf("azure discovery: %s returned status %d", url, statusCode)
		}
		if decodeErr != nil {
			return nil, fmt.Errorf("azure discovery: decoding response from %s: %w", url, decodeErr)
		}

		all = append(all, page.Value...)

		next := page.GraphNext
		if next == "" {
			next = page.ARMNext
		}
		if next == url {
			return nil, fmt.Errorf("azure discovery: pagination did not advance (nextLink repeated %s)", url)
		}
		url = next
	}
	return all, nil
}

type graphUser struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
}

type graphServicePrincipal struct {
	ID    string `json:"id"`
	AppID string `json:"appId"`
}

// DiscoverIdentities enumerates Entra users and service principals,
// normalizing each into a CloudIdentity. CanonicalID is prefixed
// "azure:user_"/"azure:sp_" to match the convention Phase 4's hybrid-identity
// tests already established.
func (c *AzureDiscoveryClient) DiscoverIdentities(ctx context.Context) ([]*CloudIdentity, *DiscoveryStats, error) {
	var identities []*CloudIdentity

	userPages, err := c.fetchAllPages(ctx, c.GraphBaseURL+"/users", c.graphTokens)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: listing users: %w", err)
	}
	for _, raw := range userPages {
		var u graphUser
		if err := json.Unmarshal(raw, &u); err != nil {
			return nil, nil, fmt.Errorf("azure discovery: parsing user: %w", err)
		}
		identities = append(identities, &CloudIdentity{
			CanonicalID: "azure:user_" + u.ID,
			Kind:        "entra-user",
			Attributes:  map[string]string{"upn": u.UserPrincipalName},
			Provenance:  &Provenance{Source: "azure:graph-users", Confidence: "observed"},
		})
	}

	spPages, err := c.fetchAllPages(ctx, c.GraphBaseURL+"/servicePrincipals", c.graphTokens)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: listing service principals: %w", err)
	}
	for _, raw := range spPages {
		var sp graphServicePrincipal
		if err := json.Unmarshal(raw, &sp); err != nil {
			return nil, nil, fmt.Errorf("azure discovery: parsing service principal: %w", err)
		}
		identities = append(identities, &CloudIdentity{
			CanonicalID: "azure:sp_" + sp.ID,
			Kind:        "service-principal",
			Attributes:  map[string]string{"app_id": sp.AppID},
			Provenance:  &Provenance{Source: "azure:graph-service-principals", Confidence: "observed"},
		})
	}

	return identities, &DiscoveryStats{ItemsFound: len(identities)}, nil
}
