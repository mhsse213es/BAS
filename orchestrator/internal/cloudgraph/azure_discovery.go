package cloudgraph

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"

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

	// retry and limiter are zero-value safe: a client built as a struct
	// literal makes one attempt with no rate limiting.
	retry   RetryPolicy
	limiter *rate.Limiter

	// secret is held only so error text can be redacted; it is never logged
	// or returned.
	secret string

	subscriptionID string
	tenantID       string // root management group ID for hierarchy reads
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
		retry:          DefaultRetryPolicy,
		limiter:        DefaultRateLimiter(),
		tenantID:       cfg.TenantID,
		secret:         cfg.ClientSecret,
		subscriptionID: cfg.SubscriptionID,
	}
}

// get performs an authenticated GET with throttling and transient-failure
// retry. The bearer token is re-acquired on every attempt so a long backoff
// cannot send an expired token.
func (c *AzureDiscoveryClient) get(ctx context.Context, url string, tokens *msauth.EntraTokenSource) (*http.Response, error) {
	return c.getWith(ctx, url, tokens)
}

// maxDiscoveryPages bounds pagination so a misbehaving endpoint that keeps
// returning fresh nextLinks cannot run a discovery pass indefinitely.
const maxDiscoveryPages = 5000

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
	for pages := 0; url != ""; pages++ {
		if pages >= maxDiscoveryPages {
			return nil, fmt.Errorf("azure discovery: more than %d pages from %s; refusing to continue", maxDiscoveryPages, startURL)
		}
		resp, err := c.get(ctx, url, tokens)
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

type armResource struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// DiscoverResources enumerates Azure resources in the configured
// subscription via Azure Resource Manager. ARM's "id" field is already the
// full hierarchical resource path, so it is used as CanonicalID unchanged --
// no transformation needed, since it is identical in shape to the Phase 4/5
// test fixtures.
func (c *AzureDiscoveryClient) DiscoverResources(ctx context.Context) ([]*CloudResource, *DiscoveryStats, error) {
	url := fmt.Sprintf("%s/subscriptions/%s/resources?api-version=2021-04-01", c.ARMBaseURL, c.subscriptionID)
	pages, err := c.fetchAllPages(ctx, url, c.armTokens)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: listing resources: %w", err)
	}

	var resources []*CloudResource
	for _, raw := range pages {
		var r armResource
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, nil, fmt.Errorf("azure discovery: parsing resource: %w", err)
		}
		resources = append(resources, &CloudResource{
			CanonicalID: r.ID,
			Kind:        r.Type,
			Provenance:  &Provenance{Source: "azure:arm-resources", Confidence: "observed"},
		})
	}

	return resources, &DiscoveryStats{ItemsFound: len(resources)}, nil
}

type armRoleAssignment struct {
	Properties struct {
		PrincipalID      string `json:"principalId"`
		Scope            string `json:"scope"`
		RoleDefinitionID string `json:"roleDefinitionId"`
	} `json:"properties"`
	// InheritedFrom names the management group a grant was made at, when it
	// reaches this subscription from above. Empty for a direct assignment.
	InheritedFrom string `json:"-"`
}

// parseRoleAssignmentPages decodes raw ARM role assignment pages.
func parseRoleAssignmentPages(pages []json.RawMessage) ([]armRoleAssignment, error) {
	out := make([]armRoleAssignment, 0, len(pages))
	for _, raw := range pages {
		var a armRoleAssignment
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, fmt.Errorf("azure discovery: parsing role assignment: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

type armRoleDefinition struct {
	Properties struct {
		RoleName    string `json:"roleName"`
		Permissions []struct {
			Actions        []string `json:"actions"`
			NotActions     []string `json:"notActions"`
			DataActions    []string `json:"dataActions"`
			NotDataActions []string `json:"notDataActions"`
		} `json:"permissions"`
	} `json:"properties"`
}

// azureRoleBlock is one permission block of a role definition. Azure applies
// notActions/notDataActions only within the block that declares them, so the
// exclusions are kept per block rather than merged across the role.
type azureRoleBlock struct {
	granted    []string // actions and dataActions, in declaration order
	notActions []string // notActions and notDataActions
}

func roleBlocks(def *armRoleDefinition) []azureRoleBlock {
	blocks := make([]azureRoleBlock, 0, len(def.Properties.Permissions))
	for _, perm := range def.Properties.Permissions {
		granted := make([]string, 0, len(perm.Actions)+len(perm.DataActions))
		granted = append(granted, perm.Actions...)
		granted = append(granted, perm.DataActions...)
		notActions := make([]string, 0, len(perm.NotActions)+len(perm.NotDataActions))
		notActions = append(notActions, perm.NotActions...)
		notActions = append(notActions, perm.NotDataActions...)
		blocks = append(blocks, azureRoleBlock{granted: granted, notActions: notActions})
	}
	return blocks
}

// azureEdgeSpec is one permission edge a role block yields. A literal action
// is netted against its own block's exclusions. A wildcard pattern (for
// example "*" or "*/read") is kept as the pattern, carrying the block's full
// grant and exclusion lists, so the evaluator can decide each concrete action
// a scenario asks about.
type azureEdgeSpec struct {
	action         string
	roleActions    string
	roleNotActions string
}

func azureRoleEdgeSpecs(def *armRoleDefinition) []azureEdgeSpec {
	var specs []azureEdgeSpec
	seenLiteral := map[string]bool{}
	for _, b := range roleBlocks(def) {
		grantedJoined := strings.Join(b.granted, ",")
		notJoined := strings.Join(b.notActions, ",")

		var netted []string
		for _, g := range b.granted {
			if !strings.Contains(g, "*") && exactIn(g, b.notActions) {
				continue
			}
			netted = append(netted, g)
		}
		nettedJoined := strings.Join(netted, ",")

		for _, g := range b.granted {
			if strings.Contains(g, "*") {
				specs = append(specs, azureEdgeSpec{action: g, roleActions: grantedJoined, roleNotActions: notJoined})
				continue
			}
			if azureAnyPatternMatches(b.notActions, g) || seenLiteral[g] {
				continue
			}
			seenLiteral[g] = true
			specs = append(specs, azureEdgeSpec{action: g, roleActions: nettedJoined})
		}
	}
	return specs
}

func exactIn(v string, list []string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

var (
	subscriptionScopeRe  = regexp.MustCompile(`^/subscriptions/[^/]+$`)
	resourceGroupScopeRe = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/[^/]+$`)
)

// scopeKind classifies a role-assignment scope path by exact shape. A scope
// that matches neither a subscription nor a resource-group path is
// "unknown-scope" -- never guessed as one of the two known kinds.
func scopeKind(scope string) string {
	switch {
	case subscriptionScopeRe.MatchString(scope):
		return "subscription"
	case resourceGroupScopeRe.MatchString(scope):
		return "resource-group"
	default:
		return "unknown-scope"
	}
}

// fetchOne performs an authenticated GET against url and decodes a single
// JSON object into out. Unlike fetchAllPages, this is for single-resource
// ARM GETs (e.g. one role definition), which are not wrapped in a "value"
// array.
func (c *AzureDiscoveryClient) fetchOne(ctx context.Context, url string, tokens *msauth.EntraTokenSource, out any) error {
	resp, err := c.get(ctx, url, tokens)
	if err != nil {
		return fmt.Errorf("azure discovery: request to %s: %w", url, err)
	}
	decodeErr := json.NewDecoder(resp.Body).Decode(out)
	statusCode := resp.StatusCode
	resp.Body.Close()

	if statusCode != http.StatusOK {
		return fmt.Errorf("azure discovery: %s returned status %d", url, statusCode)
	}
	if decodeErr != nil {
		return fmt.Errorf("azure discovery: decoding response from %s: %w", url, decodeErr)
	}
	return nil
}

// DiscoverPermissions correlates already-discovered identities and
// resources against real role assignments, emitting one CloudPermission per
// action the assigned role grants (matching the exact shape AzureEvaluator's
// Phase 4 synthetic fixtures already used -- NOT one edge per assignment
// with a wildcard Action, which AzureEvaluator's exact-match
// actionListContains would reject for any role whose actions aren't
// literally "*").
func (c *AzureDiscoveryClient) DiscoverPermissions(ctx context.Context, identities []*CloudIdentity, resources []*CloudResource) ([]*CloudPermission, *DiscoveryStats, error) {
	return c.discoverPermissionsFrom(ctx, identities, resources, nil)
}

// discoverPermissionsFrom turns subscription role assignments, plus any extra
// assignments (inherited from management groups), into permission edges.
func (c *AzureDiscoveryClient) discoverPermissionsFrom(ctx context.Context, identities []*CloudIdentity, resources []*CloudResource, extra []armRoleAssignment) ([]*CloudPermission, *DiscoveryStats, error) {
	identityByObjectID := make(map[string]*CloudIdentity, len(identities))
	for _, id := range identities {
		switch {
		case strings.HasPrefix(id.CanonicalID, "azure:user_"):
			identityByObjectID[strings.TrimPrefix(id.CanonicalID, "azure:user_")] = id
		case strings.HasPrefix(id.CanonicalID, "azure:sp_"):
			identityByObjectID[strings.TrimPrefix(id.CanonicalID, "azure:sp_")] = id
		}
	}

	resourceByCanonicalID := make(map[string]*CloudResource, len(resources))
	for _, r := range resources {
		resourceByCanonicalID[r.CanonicalID] = r
	}

	assignURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", c.ARMBaseURL, c.subscriptionID)
	assignPages, err := c.fetchAllPages(ctx, assignURL, c.armTokens)
	if err != nil {
		return nil, nil, fmt.Errorf("azure discovery: listing role assignments: %w", err)
	}

	roleDefCache := make(map[string]*armRoleDefinition)
	stats := &DiscoveryStats{}
	var permissions []*CloudPermission

	assignments, err := parseRoleAssignmentPages(assignPages)
	if err != nil {
		return nil, nil, err
	}
	assignments = append(assignments, extra...)
	for _, a := range assignments {

		identity, ok := identityByObjectID[a.Properties.PrincipalID]
		if !ok {
			stats.UnresolvedPrincipals++
			continue
		}

		def, cached := roleDefCache[a.Properties.RoleDefinitionID]
		if !cached {
			def = &armRoleDefinition{}
			defURL := c.ARMBaseURL + a.Properties.RoleDefinitionID + "?api-version=2022-04-01"
			if err := c.fetchOne(ctx, defURL, c.armTokens, def); err != nil {
				return nil, nil, fmt.Errorf("azure discovery: fetching role definition %s: %w", a.Properties.RoleDefinitionID, err)
			}
			roleDefCache[a.Properties.RoleDefinitionID] = def
		}

		specs := azureRoleEdgeSpecs(def)

		target, ok := resourceByCanonicalID[a.Properties.Scope]
		if !ok {
			target = &CloudResource{
				CanonicalID: a.Properties.Scope,
				Kind:        scopeKind(a.Properties.Scope),
				Provenance:  &Provenance{Source: "azure:arm-role-assignments", Confidence: "observed"},
			}
		}

		for _, spec := range specs {
			attrs := map[string]string{
				"role_scope":           a.Properties.Scope,
				"role_actions":         spec.roleActions,
				"role_definition_name": def.Properties.RoleName,
			}
			if spec.roleNotActions != "" {
				attrs["role_not_actions"] = spec.roleNotActions
			}
			if a.InheritedFrom != "" {
				attrs["inherited_from"] = a.InheritedFrom
			}
			permissions = append(permissions, &CloudPermission{
				Source:     identity,
				Target:     target,
				Action:     spec.action,
				SourceType: "role-assignment",
				Attributes: attrs,
				Provenance: &Provenance{Source: "azure:arm-role-assignments", Confidence: "observed"},
			})
		}
	}

	stats.ItemsFound = len(permissions)
	return permissions, stats, nil
}
