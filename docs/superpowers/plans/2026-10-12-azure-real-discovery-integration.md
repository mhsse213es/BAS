# Azure Real Discovery Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a real, read-only Azure discovery client that connects to a real Azure tenant (via a service principal) and normalizes real identities, resources, and role assignments into the existing Phase 1 `CloudIdentity`/`CloudResource`/`CloudPermission` types, proving that real Azure data evaluates correctly through the existing, unmodified Phase 4 `AzureEvaluator`.

**Architecture:** One new client, `AzureDiscoveryClient`, in the existing `cloudgraph` package, with three discovery methods (`DiscoverIdentities`, `DiscoverResources`, `DiscoverPermissions`) backed by hand-rolled REST calls against Microsoft Graph and Azure Resource Manager — no new SDK dependency. Auth is delegated entirely to the already-shipped `msauth.EntraTokenSource` (used today by the Defender vendor client), following `defender.Client`'s exact two-token-source, overridable-base-URL shape so the same `httptest.Server` testing pattern applies unchanged.

**Tech Stack:** Go, `net/http`, `encoding/json`, `internal/platform/msauth` (reused, unmodified), `httptest` for unit tests.

**Spec:** `docs/superpowers/specs/2026-10-12-azure-real-discovery-integration-design.md`

## Deviation From Spec (found during planning, fixed before Task 1)

The spec's `Action = "*"` sentinel for discovered role-assignment edges is incompatible with the real, unmodified `AzureEvaluator.isRoleAssignmentMatch` (`orchestrator/internal/cloudgraph/azure_evaluator.go:52-59`), confirmed by reading that function directly:

```go
func isRoleAssignmentMatch(edge *CloudPermission) bool {
	roleScope, hasScope := edge.Attributes["role_scope"]
	roleActions, hasActions := edge.Attributes["role_actions"]
	if !hasScope || !hasActions {
		return false
	}
	return scopeCovers(roleScope, edge.Target.CanonicalID) && actionListContains(roleActions, edge.Action)
}
```

This takes **one edge** and requires `edge.Action` to be literally present in that same edge's `Attributes["role_actions"]` list (`actionListContains` does an exact string match after splitting on `,`). There is no separate "stored edge" vs. "query edge" — the spec's risk-table mitigation assumed a two-edge model that does not exist in the code. A discovered edge with `Action = "*"` only matches a role whose actions list is literally `["*"]` (e.g., a built-in Owner role) — every other role assignment would incorrectly evaluate as `Blocked` by implicit-deny.

**Resolution (also closes the spec's own "Open Questions" item about one-edge-per-action):** `DiscoverPermissions` emits one `CloudPermission` per action the role grants, each with `Action` set to that specific action string — identical in shape to the synthetic fixtures `AzureEvaluator` was built and tested against in Phase 4. Task 3 below implements this corrected shape and Task 3's Review Focus test proves a discovered edge evaluates to `PolicySupported` through the real, unmodified evaluator.

## Global Constraints

- New files only: `orchestrator/internal/cloudgraph/azure_discovery.go`, `azure_discovery_test.go`, `azure_discovery_integration_test.go`. No modification to any existing `cloudgraph` file (`azure_evaluator.go` stays untouched — that is the point of this milestone).
- Reuse `msauth.NewEntraTokenSource(tenantID, clientID, clientSecret, scope string) *EntraTokenSource` unmodified. Do not add a new auth mechanism.
- No new Go module dependency. Everything is `net/http` + `encoding/json` + the existing `msauth` package.
- Fail-fast error handling: any transport/auth/decode error aborts the in-progress `Discover*` call and returns `(nil, nil, err)`. No partial results on failure.
- Every discovered `CloudIdentity`/`CloudResource`/`CloudPermission` gets a non-nil `Provenance` with `Confidence: "observed"` and a `Source` string naming the exact API call that produced it.
- Unresolved role-assignment principals are counted in `DiscoveryStats.UnresolvedPrincipals`, never a fatal error and never silently dropped.
- The integration test (`azure_discovery_integration_test.go`) is gated by `//go:build integration` and is never run by this plan's own verification steps — no real credentials exist yet in this session. Each task's test-run steps use `go test ./internal/cloudgraph -run <TestName>` (no `-tags=integration`), which the Go build tag mechanism excludes automatically.
- Git: inline execution on `main` (this session's established convention), commit after each task, push after every commit.

## Review Focus

- **Action-sentinel / evaluator-compatibility mismatch** — a discovered permission edge must evaluate correctly through the real, unmodified `AzureEvaluator`, not just construct without a panic. Covered by Task 3, Step 9 (`TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator`) — calls the real `AzureEvaluator.EvaluatePermission` on a `DiscoverPermissions` output edge and asserts `PolicySupported`.
- **Pagination never terminates on a malformed `nextLink`** (e.g., a server that echoes the same link forever) — must return an error, not hang. Covered by Task 1, Step 7 (`TestDiscoverIdentities_RepeatedNextLinkReturnsErrorNotInfiniteLoop`).
- **Unresolved-principal counting is exact across multiple unresolved assignments in one call** — not off-by-one when several assignments in the same page fail to resolve. Covered by Task 3, Step 5 (`TestDiscoverPermissions_MultipleUnresolvedPrincipalsAllCounted`, two unresolved assignments, asserts `UnresolvedPrincipals == 2` exactly).
- **A role definition shared by multiple role assignments is fetched once, not once per assignment** — otherwise a real tenant with many assignments against a common role (e.g. "Reader") makes redundant ARM calls on every discovery run. Covered by Task 3, Step 7 (`TestDiscoverPermissions_RoleDefinitionFetchedOnceAndCached`, asserts the role-definition endpoint's call counter is exactly 1 after two assignments share the same `roleDefinitionId`).
- **A transport failure partway through `DiscoverPermissions` must not return a partially-built permissions slice** — fail-fast means `(nil, nil, err)`, not "here's what we got before it broke." Covered by Task 3, Step 11 (`TestDiscoverPermissions_RoleDefinitionFetchError_FailsFastNoPartialResults`).

---

### Task 1: Client Scaffold + DiscoverIdentities

**Files:**
- Create: `orchestrator/internal/cloudgraph/azure_discovery.go`
- Create: `orchestrator/internal/cloudgraph/azure_discovery_test.go`

**Interfaces:**
- Consumes: `msauth.NewEntraTokenSource(tenantID, clientID, clientSecret, scope string) *EntraTokenSource` and its `(e *EntraTokenSource) Token(ctx context.Context) (string, error)` method (from `orchestrator/internal/platform/msauth`, unmodified); `CloudIdentity{CanonicalID, Kind, AccountScope, Attributes, Provenance}` and `Provenance{Source, ObservedAt, CollectionAge, Confidence, ErrorDetail}` (from `orchestrator/internal/cloudgraph/types.go`, unmodified).
- Produces: `AzureDiscoveryConfig{TenantID, ClientID, ClientSecret, SubscriptionID string}`; `AzureDiscoveryClient` with exported fields `GraphBaseURL string` and `ARMBaseURL string`; `NewAzureDiscoveryClient(cfg AzureDiscoveryConfig) *AzureDiscoveryClient`; `(c *AzureDiscoveryClient) GraphTokenURL() *string` and `(c *AzureDiscoveryClient) ARMTokenURL() *string` (test-override accessors, same pattern as `defender.Client.TokenURL()`); `DiscoveryStats{ItemsFound, UnresolvedPrincipals int}`; `(c *AzureDiscoveryClient) fetchAllPages(ctx context.Context, startURL string, tokens *msauth.EntraTokenSource) ([]json.RawMessage, error)` (package-private, used by Tasks 2 and 3); `(c *AzureDiscoveryClient) DiscoverIdentities(ctx context.Context) ([]*CloudIdentity, *DiscoveryStats, error)`.

- [ ] **Step 1: Write the failing test for client construction and identity normalization**

Create `orchestrator/internal/cloudgraph/azure_discovery_test.go`:

```go
package cloudgraph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func azureTokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func newTestAzureDiscoveryClient(t *testing.T, tokenURL, graphURL, armURL string) *AzureDiscoveryClient {
	t.Helper()
	c := NewAzureDiscoveryClient(AzureDiscoveryConfig{
		TenantID: "t1", ClientID: "c1", ClientSecret: "s1", SubscriptionID: "sub-1",
	})
	*c.GraphTokenURL() = tokenURL
	*c.ARMTokenURL() = tokenURL
	c.GraphBaseURL = graphURL
	c.ARMBaseURL = armURL
	return c
}

func TestDiscoverIdentities_NormalizesUsersAndServicePrincipals(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "user-1", "userPrincipalName": "alice@essen065.onmicrosoft.com"},
				},
			})
		case "/servicePrincipals":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "sp-1", "appId": "app-1"},
				},
			})
		default:
			t.Fatalf("unexpected graph path %s", r.URL.Path)
		}
	}))
	defer graphSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, graphSrv.URL, "")
	identities, stats, err := c.DiscoverIdentities(context.Background())
	if err != nil {
		t.Fatalf("DiscoverIdentities: %v", err)
	}
	if stats.ItemsFound != 2 {
		t.Fatalf("stats.ItemsFound = %d, want 2", stats.ItemsFound)
	}
	if len(identities) != 2 {
		t.Fatalf("identities = %+v, want 2 entries", identities)
	}

	var user, sp *CloudIdentity
	for _, id := range identities {
		switch id.Kind {
		case "entra-user":
			user = id
		case "service-principal":
			sp = id
		}
	}
	if user == nil || user.CanonicalID != "azure:user_user-1" || user.Attributes["upn"] != "alice@essen065.onmicrosoft.com" {
		t.Fatalf("user identity = %+v, want CanonicalID azure:user_user-1 with upn set", user)
	}
	if user.Provenance == nil || user.Provenance.Source != "azure:graph-users" || user.Provenance.Confidence != "observed" {
		t.Fatalf("user provenance = %+v, want Source azure:graph-users, Confidence observed", user.Provenance)
	}
	if sp == nil || sp.CanonicalID != "azure:sp_sp-1" || sp.Attributes["app_id"] != "app-1" {
		t.Fatalf("sp identity = %+v, want CanonicalID azure:sp_sp-1 with app_id set", sp)
	}
	if sp.Provenance == nil || sp.Provenance.Source != "azure:graph-service-principals" {
		t.Fatalf("sp provenance = %+v, want Source azure:graph-service-principals", sp.Provenance)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cloudgraph -run TestDiscoverIdentities_NormalizesUsersAndServicePrincipals -v`
Expected: FAIL — compile error, `NewAzureDiscoveryClient`/`AzureDiscoveryConfig`/`DiscoverIdentities` undefined.

- [ ] **Step 3: Write minimal implementation — scaffold + fetchAllPages + DiscoverIdentities**

Create `orchestrator/internal/cloudgraph/azure_discovery.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cloudgraph -run TestDiscoverIdentities_NormalizesUsersAndServicePrincipals -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/cloudgraph/azure_discovery.go orchestrator/internal/cloudgraph/azure_discovery_test.go
git commit -m "feat(cloudgraph): Azure discovery client scaffold + identity discovery"
git push
```

- [ ] **Step 6: Write the failing test for pagination following (the malformed-nextLink Review Focus case)**

Add to `azure_discovery_test.go`:

```go
func TestDiscoverIdentities_FollowsGraphPagination(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	var graphSrv *httptest.Server
	page := 0
	graphSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users" && r.URL.Path != "/usersPage2" {
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
			return
		}
		page++
		if r.URL.Path == "/users" {
			json.NewEncoder(w).Encode(map[string]any{
				"value":           []map[string]any{{"id": "user-1", "userPrincipalName": "a@x.com"}},
				"@odata.nextLink": graphSrv.URL + "/usersPage2",
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": "user-2", "userPrincipalName": "b@x.com"}},
		})
	}))
	defer graphSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, graphSrv.URL, "")
	identities, stats, err := c.DiscoverIdentities(context.Background())
	if err != nil {
		t.Fatalf("DiscoverIdentities: %v", err)
	}
	userCount := 0
	for _, id := range identities {
		if id.Kind == "entra-user" {
			userCount++
		}
	}
	if userCount != 2 {
		t.Fatalf("got %d users across pages, want 2 (stats=%+v)", userCount, stats)
	}
}

func TestDiscoverIdentities_RepeatedNextLinkReturnsErrorNotInfiniteLoop(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	var graphSrv *httptest.Server
	graphSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users" {
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value":           []map[string]any{{"id": "user-1", "userPrincipalName": "a@x.com"}},
			"@odata.nextLink": graphSrv.URL + "/users", // malformed: points back at itself
		})
	}))
	defer graphSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, graphSrv.URL, "")
	_, _, err := c.DiscoverIdentities(context.Background())
	if err == nil {
		t.Fatal("DiscoverIdentities: want error on repeated nextLink, got nil (would have looped forever without the guard)")
	}
}

func TestDiscoverIdentities_GraphHTTPError_FailsFastNoPartialResults(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer graphSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, graphSrv.URL, "")
	identities, stats, err := c.DiscoverIdentities(context.Background())
	if err == nil {
		t.Fatal("DiscoverIdentities: want error on HTTP 500, got nil")
	}
	if identities != nil || stats != nil {
		t.Fatalf("DiscoverIdentities: want (nil, nil, err), got (%+v, %+v, %v)", identities, stats, err)
	}
}
```

- [ ] **Step 7: Run tests to verify they fail or pass correctly**

Run: `go test ./internal/cloudgraph -run TestDiscoverIdentities -v`
Expected: `TestDiscoverIdentities_NormalizesUsersAndServicePrincipals` PASS (already implemented); `TestDiscoverIdentities_FollowsGraphPagination`, `TestDiscoverIdentities_RepeatedNextLinkReturnsErrorNotInfiniteLoop`, and `TestDiscoverIdentities_GraphHTTPError_FailsFastNoPartialResults` should already PASS too, since `fetchAllPages`'s pagination-following, repeated-nextLink guard, and fail-fast behavior were all written in Step 3. If any of the three new tests FAIL, that is real evidence of a bug in Step 3's `fetchAllPages` — use systematic-debugging rather than patching the test.

- [ ] **Step 8: Commit**

```bash
git add orchestrator/internal/cloudgraph/azure_discovery_test.go
git commit -m "test(cloudgraph): pin pagination-following, malformed-nextLink guard, and fail-fast behavior for Azure discovery"
git push
```

---

### Task 2: DiscoverResources

**Files:**
- Modify: `orchestrator/internal/cloudgraph/azure_discovery.go`
- Modify: `orchestrator/internal/cloudgraph/azure_discovery_test.go`

**Interfaces:**
- Consumes: `(c *AzureDiscoveryClient) fetchAllPages(ctx, startURL string, tokens *msauth.EntraTokenSource) ([]json.RawMessage, error)` (Task 1); `CloudResource{CanonicalID, Kind, AccountScope, DisplayName, Attributes, Provenance}` (from `types.go`, unmodified); `c.ARMBaseURL`, `c.armTokens`, `c.subscriptionID` (Task 1 fields).
- Produces: `(c *AzureDiscoveryClient) DiscoverResources(ctx context.Context) ([]*CloudResource, *DiscoveryStats, error)`.

- [ ] **Step 1: Write the failing test**

Add to `azure_discovery_test.go`:

```go
func TestDiscoverResources_NormalizesARMResources(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subscriptions/sub-1/resources" {
			t.Fatalf("unexpected ARM path %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id":   "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo",
					"type": "Microsoft.Storage/storageAccounts",
				},
			},
		})
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)
	resources, stats, err := c.DiscoverResources(context.Background())
	if err != nil {
		t.Fatalf("DiscoverResources: %v", err)
	}
	if stats.ItemsFound != 1 || len(resources) != 1 {
		t.Fatalf("resources = %+v, stats = %+v, want 1 resource", resources, stats)
	}
	r := resources[0]
	wantID := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo"
	if r.CanonicalID != wantID || r.Kind != "Microsoft.Storage/storageAccounts" {
		t.Fatalf("resource = %+v, want CanonicalID %s, Kind Microsoft.Storage/storageAccounts", r, wantID)
	}
	if r.Provenance == nil || r.Provenance.Source != "azure:arm-resources" || r.Provenance.Confidence != "observed" {
		t.Fatalf("resource provenance = %+v, want Source azure:arm-resources, Confidence observed", r.Provenance)
	}
}

func TestDiscoverResources_FollowsARMPagination(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	var armSrv *httptest.Server
	armSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/resources":
			json.NewEncoder(w).Encode(map[string]any{
				"value":    []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-1/res-a", "type": "t1"}},
				"nextLink": armSrv.URL + "/resourcesPage2",
			})
		case "/resourcesPage2":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{"id": "/subscriptions/sub-1/resourceGroups/rg-1/res-b", "type": "t1"}},
			})
		default:
			t.Fatalf("unexpected ARM path %s", r.URL.Path)
		}
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)
	resources, stats, err := c.DiscoverResources(context.Background())
	if err != nil {
		t.Fatalf("DiscoverResources: %v", err)
	}
	if stats.ItemsFound != 2 || len(resources) != 2 {
		t.Fatalf("resources = %+v, stats = %+v, want 2 resources across both pages", resources, stats)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cloudgraph -run TestDiscoverResources -v`
Expected: FAIL — compile error, `DiscoverResources` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `azure_discovery.go`:

```go
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
```

The `?api-version=2021-04-01` query string matches the real ARM API; the test's mock server checks only `r.URL.Path`, which excludes the query string, so the test above still matches this URL unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cloudgraph -run TestDiscoverResources -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add orchestrator/internal/cloudgraph/azure_discovery.go orchestrator/internal/cloudgraph/azure_discovery_test.go
git commit -m "feat(cloudgraph): Azure ARM resource discovery"
git push
```

---

### Task 3: DiscoverPermissions (corrected one-edge-per-action design)

**Files:**
- Modify: `orchestrator/internal/cloudgraph/azure_discovery.go`
- Modify: `orchestrator/internal/cloudgraph/azure_discovery_test.go`

**Interfaces:**
- Consumes: `(c *AzureDiscoveryClient) fetchAllPages(...)` (Task 1); `[]*CloudIdentity` with `CanonicalID` prefixed `"azure:user_"`/`"azure:sp_"` (Task 1 output shape); `[]*CloudResource` with `CanonicalID` set to the ARM resource path (Task 2 output shape); `CloudPermission{Source, Target, Action, Conditions, SourceType, Attributes, Provenance}` (from `types.go`, unmodified); `AzureEvaluator.EvaluatePermission(edge *CloudPermission, ctx *RequestContext) *EvaluationResult` and the `PolicySupported` constant (from `azure_evaluator.go`, read-only, unmodified — used only in this task's Review Focus test to prove compatibility).
- Produces: `(c *AzureDiscoveryClient) DiscoverPermissions(ctx context.Context, identities []*CloudIdentity, resources []*CloudResource) ([]*CloudPermission, *DiscoveryStats, error)`; package-private `scopeKind(scope string) string`.

- [ ] **Step 1: Write the failing test for the core mapping (one edge per granted action)**

Add to `azure_discovery_test.go` (add `"strings"` to the existing import block if not already present — it is not needed by Tasks 1-2, so add it now):

```go
func TestDiscoverPermissions_MapsRoleAssignmentToOneEdgePerAction(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	roleDefID := "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-1"
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"properties": map[string]any{
						"principalId":      "user-1",
						"scope":            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo",
						"roleDefinitionId": roleDefID,
					}},
				},
			})
		case roleDefID:
			json.NewEncoder(w).Encode(map[string]any{
				"properties": map[string]any{
					"roleName": "Storage Blob Data Reader",
					"permissions": []map[string]any{
						{"actions": []string{
							"Microsoft.Storage/storageAccounts/read",
							"Microsoft.Storage/storageAccounts/blobServices/containers/read",
						}},
					},
				},
			})
		default:
			t.Fatalf("unexpected ARM path %s", r.URL.Path)
		}
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)

	identities := []*CloudIdentity{
		{CanonicalID: "azure:user_user-1", Kind: "entra-user"},
	}
	resources := []*CloudResource{
		{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo", Kind: "Microsoft.Storage/storageAccounts"},
	}

	permissions, stats, err := c.DiscoverPermissions(context.Background(), identities, resources)
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}
	if len(permissions) != 2 || stats.ItemsFound != 2 {
		t.Fatalf("permissions = %+v, stats = %+v, want 2 edges (one per granted action)", permissions, stats)
	}

	gotActions := map[string]bool{}
	for _, p := range permissions {
		gotActions[p.Action] = true
		if p.Source != identities[0] {
			t.Fatalf("permission.Source = %+v, want the discovered identity", p.Source)
		}
		if p.Target != resources[0] {
			t.Fatalf("permission.Target = %+v, want the discovered resource", p.Target)
		}
		if p.SourceType != "role-assignment" {
			t.Fatalf("permission.SourceType = %q, want role-assignment", p.SourceType)
		}
		wantScope := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo"
		if p.Attributes["role_scope"] != wantScope {
			t.Fatalf("role_scope = %q, want %q", p.Attributes["role_scope"], wantScope)
		}
		wantRoleActions := "Microsoft.Storage/storageAccounts/read,Microsoft.Storage/storageAccounts/blobServices/containers/read"
		if p.Attributes["role_actions"] != wantRoleActions {
			t.Fatalf("role_actions = %q, want %q", p.Attributes["role_actions"], wantRoleActions)
		}
		if p.Attributes["role_definition_name"] != "Storage Blob Data Reader" {
			t.Fatalf("role_definition_name = %q, want Storage Blob Data Reader", p.Attributes["role_definition_name"])
		}
		if p.Provenance == nil || p.Provenance.Source != "azure:arm-role-assignments" {
			t.Fatalf("provenance = %+v, want Source azure:arm-role-assignments", p.Provenance)
		}
	}
	if !gotActions["Microsoft.Storage/storageAccounts/read"] || !gotActions["Microsoft.Storage/storageAccounts/blobServices/containers/read"] {
		t.Fatalf("gotActions = %+v, want both granted actions represented as separate edges", gotActions)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cloudgraph -run TestDiscoverPermissions_MapsRoleAssignmentToOneEdgePerAction -v`
Expected: FAIL — compile error, `DiscoverPermissions` undefined.

- [ ] **Step 3: Write minimal implementation**

Add to `azure_discovery.go` (add `"regexp"` and `"strings"` to its import block):

```go
type armRoleAssignment struct {
	Properties struct {
		PrincipalID      string `json:"principalId"`
		Scope            string `json:"scope"`
		RoleDefinitionID string `json:"roleDefinitionId"`
	} `json:"properties"`
}

type armRoleDefinition struct {
	Properties struct {
		RoleName    string `json:"roleName"`
		Permissions []struct {
			Actions []string `json:"actions"`
		} `json:"permissions"`
	} `json:"properties"`
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
	token, err := tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("azure discovery: acquiring token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("azure discovery: building request for %s: %w", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
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

	for _, raw := range assignPages {
		var a armRoleAssignment
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, nil, fmt.Errorf("azure discovery: parsing role assignment: %w", err)
		}

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

		var actions []string
		for _, perm := range def.Properties.Permissions {
			actions = append(actions, perm.Actions...)
		}
		roleActionsJoined := strings.Join(actions, ",")

		target, ok := resourceByCanonicalID[a.Properties.Scope]
		if !ok {
			target = &CloudResource{
				CanonicalID: a.Properties.Scope,
				Kind:        scopeKind(a.Properties.Scope),
				Provenance:  &Provenance{Source: "azure:arm-role-assignments", Confidence: "observed"},
			}
		}

		for _, action := range actions {
			permissions = append(permissions, &CloudPermission{
				Source:     identity,
				Target:     target,
				Action:     action,
				SourceType: "role-assignment",
				Attributes: map[string]string{
					"role_scope":           a.Properties.Scope,
					"role_actions":         roleActionsJoined,
					"role_definition_name": def.Properties.RoleName,
				},
				Provenance: &Provenance{Source: "azure:arm-role-assignments", Confidence: "observed"},
			})
		}
	}

	stats.ItemsFound = len(permissions)
	return permissions, stats, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cloudgraph -run TestDiscoverPermissions_MapsRoleAssignmentToOneEdgePerAction -v`
Expected: PASS

- [ ] **Step 5: Write the failing test for unresolved-principal counting (Review Focus)**

Add to `azure_discovery_test.go`:

```go
func TestDiscoverPermissions_MultipleUnresolvedPrincipalsAllCounted(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments" {
			t.Fatalf("unexpected ARM path %s (role definitions should never be fetched -- both principals are unresolved)", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"properties": map[string]any{"principalId": "ghost-1", "scope": "/subscriptions/sub-1", "roleDefinitionId": "/role-a"}},
				{"properties": map[string]any{"principalId": "ghost-2", "scope": "/subscriptions/sub-1", "roleDefinitionId": "/role-b"}},
			},
		})
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)
	permissions, stats, err := c.DiscoverPermissions(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}
	if stats.UnresolvedPrincipals != 2 {
		t.Fatalf("stats.UnresolvedPrincipals = %d, want 2", stats.UnresolvedPrincipals)
	}
	if len(permissions) != 0 {
		t.Fatalf("permissions = %+v, want none (both principals unresolved)", permissions)
	}
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/cloudgraph -run TestDiscoverPermissions_MultipleUnresolvedPrincipalsAllCounted -v`
Expected: PASS (the `continue` in Step 3's implementation already handles this correctly; this step is pinning the behavior with a test, not adding new code). If it fails, that's real evidence of an off-by-one — debug via systematic-debugging, don't adjust the assertion to match.

- [ ] **Step 7: Write the failing test for role-definition caching (Review Focus)**

Add to `azure_discovery_test.go`:

```go
func TestDiscoverPermissions_RoleDefinitionFetchedOnceAndCached(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	roleDefID := "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/shared-role"
	roleDefFetchCount := 0
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"properties": map[string]any{"principalId": "user-1", "scope": "/subscriptions/sub-1", "roleDefinitionId": roleDefID}},
					{"properties": map[string]any{"principalId": "user-2", "scope": "/subscriptions/sub-1", "roleDefinitionId": roleDefID}},
				},
			})
		case roleDefID:
			roleDefFetchCount++
			json.NewEncoder(w).Encode(map[string]any{
				"properties": map[string]any{
					"roleName":    "Reader",
					"permissions": []map[string]any{{"actions": []string{"*/read"}}},
				},
			})
		default:
			t.Fatalf("unexpected ARM path %s", r.URL.Path)
		}
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)
	identities := []*CloudIdentity{
		{CanonicalID: "azure:user_user-1", Kind: "entra-user"},
		{CanonicalID: "azure:user_user-2", Kind: "entra-user"},
	}
	_, _, err := c.DiscoverPermissions(context.Background(), identities, nil)
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}
	if roleDefFetchCount != 1 {
		t.Fatalf("roleDefFetchCount = %d, want exactly 1 (role definition shared by 2 assignments must be cached)", roleDefFetchCount)
	}
}
```

- [ ] **Step 8: Run test to verify it passes**

Run: `go test ./internal/cloudgraph -run TestDiscoverPermissions_RoleDefinitionFetchedOnceAndCached -v`
Expected: PASS (Step 3's `roleDefCache` map already implements this; pinning the behavior).

- [ ] **Step 9: Write the failing test for the scope-fallback cases and the critical evaluator-compatibility Review Focus test**

Add to `azure_discovery_test.go`:

```go
func TestDiscoverPermissions_ScopeFallbackSynthesizesResourceGroupResource(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	roleDefID := "/role-x"
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"properties": map[string]any{
						"principalId":      "user-1",
						"scope":            "/subscriptions/sub-1/resourceGroups/rg-not-discovered",
						"roleDefinitionId": roleDefID,
					}},
				},
			})
		case roleDefID:
			json.NewEncoder(w).Encode(map[string]any{
				"properties": map[string]any{
					"roleName":    "Contributor",
					"permissions": []map[string]any{{"actions": []string{"*/write"}}},
				},
			})
		default:
			t.Fatalf("unexpected ARM path %s", r.URL.Path)
		}
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)
	identities := []*CloudIdentity{{CanonicalID: "azure:user_user-1", Kind: "entra-user"}}
	permissions, _, err := c.DiscoverPermissions(context.Background(), identities, nil) // no discovered resources
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}
	if len(permissions) != 1 {
		t.Fatalf("permissions = %+v, want 1", permissions)
	}
	target := permissions[0].Target
	if target.CanonicalID != "/subscriptions/sub-1/resourceGroups/rg-not-discovered" || target.Kind != "resource-group" {
		t.Fatalf("synthesized target = %+v, want CanonicalID /subscriptions/sub-1/resourceGroups/rg-not-discovered, Kind resource-group", target)
	}
}

func TestScopeKind_ClassifiesByExactShape(t *testing.T) {
	cases := map[string]string{
		"/subscriptions/sub-1":                              "subscription",
		"/subscriptions/sub-1/resourceGroups/rg-1":           "resource-group",
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo": "unknown-scope",
		"":                                                    "unknown-scope",
	}
	for scope, want := range cases {
		if got := scopeKind(scope); got != want {
			t.Errorf("scopeKind(%q) = %q, want %q", scope, got, want)
		}
	}
}

// TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator
// is the Review Focus test for the Action-sentinel/evaluator-compatibility
// risk identified during planning: a discovered permission edge must
// evaluate to PolicySupported through the real, unmodified AzureEvaluator
// (azure_evaluator.go), not just construct without error. This is the
// concrete proof that the one-edge-per-granted-action design (rather than
// the spec's original Action="*" sentinel) actually works end to end.
func TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	roleDefID := "/role-reader"
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"properties": map[string]any{
						"principalId":      "user-1",
						"scope":            "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo",
						"roleDefinitionId": roleDefID,
					}},
				},
			})
		case roleDefID:
			json.NewEncoder(w).Encode(map[string]any{
				"properties": map[string]any{
					"roleName":    "Storage Blob Data Reader",
					"permissions": []map[string]any{{"actions": []string{"Microsoft.Storage/storageAccounts/read"}}},
				},
			})
		default:
			t.Fatalf("unexpected ARM path %s", r.URL.Path)
		}
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)
	identities := []*CloudIdentity{{CanonicalID: "azure:user_user-1", Kind: "entra-user"}}
	resources := []*CloudResource{{
		CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo",
		Kind:        "Microsoft.Storage/storageAccounts",
	}}

	permissions, _, err := c.DiscoverPermissions(context.Background(), identities, resources)
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}
	if len(permissions) != 1 {
		t.Fatalf("permissions = %+v, want exactly 1 discovered edge", permissions)
	}

	evaluator := &AzureEvaluator{}
	result := evaluator.EvaluatePermission(permissions[0], &RequestContext{})
	if result.State != PolicySupported {
		t.Fatalf("EvaluatePermission(discovered edge) = %+v, want State PolicySupported -- the discovered edge's Action (%q) must be found in its own Attributes[\"role_actions\"] (%q)",
			result, permissions[0].Action, permissions[0].Attributes["role_actions"])
	}
}
```

- [ ] **Step 10: Run tests to verify they pass**

Run: `go test ./internal/cloudgraph -run "TestDiscoverPermissions_ScopeFallbackSynthesizesResourceGroupResource|TestScopeKind_ClassifiesByExactShape|TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator" -v`
Expected: PASS (all three). `TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator` passing is the concrete proof the corrected design (one edge per granted action) is compatible with the real `AzureEvaluator` — this is the test the plan's "Deviation From Spec" section promised.

- [ ] **Step 11: Write the failing test for fail-fast on a role-definition fetch error (Review Focus)**

Add to `azure_discovery_test.go`:

```go
func TestDiscoverPermissions_RoleDefinitionFetchError_FailsFastNoPartialResults(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	roleDefID := "/role-broken"
	armSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"properties": map[string]any{"principalId": "user-1", "scope": "/subscriptions/sub-1", "roleDefinitionId": roleDefID}},
				},
			})
		case roleDefID:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected ARM path %s", r.URL.Path)
		}
	}))
	defer armSrv.Close()

	c := newTestAzureDiscoveryClient(t, tokenSrv.URL, "", armSrv.URL)
	identities := []*CloudIdentity{{CanonicalID: "azure:user_user-1", Kind: "entra-user"}}
	permissions, stats, err := c.DiscoverPermissions(context.Background(), identities, nil)
	if err == nil {
		t.Fatal("DiscoverPermissions: want error when role definition fetch fails, got nil")
	}
	if permissions != nil || stats != nil {
		t.Fatalf("DiscoverPermissions: want (nil, nil, err) on failure, got (%+v, %+v, %v)", permissions, stats, err)
	}
}
```

- [ ] **Step 12: Run test to verify it passes**

Run: `go test ./internal/cloudgraph -run TestDiscoverPermissions_RoleDefinitionFetchError_FailsFastNoPartialResults -v`
Expected: PASS (Step 3's implementation already returns `(nil, nil, err)` immediately on `fetchOne` failure; pinning the behavior).

- [ ] **Step 13: Run the full package test suite**

Run: `go test ./internal/cloudgraph -v`
Expected: All tests PASS, including every pre-existing Phase 1-5 test (66+ subtests) plus every test added in Tasks 1-3 of this plan. Zero regressions.

- [ ] **Step 14: Commit**

```bash
git add orchestrator/internal/cloudgraph/azure_discovery.go orchestrator/internal/cloudgraph/azure_discovery_test.go
git commit -m "feat(cloudgraph): Azure role-assignment discovery, one CloudPermission per granted action

Corrects the written spec's Action=\"*\" sentinel design, found broken during
planning: AzureEvaluator.isRoleAssignmentMatch requires an edge's own Action
to literally appear in that same edge's role_actions, so a wildcard sentinel
only matches Owner-like roles. Emitting one edge per granted action matches
the shape AzureEvaluator was built and tested against, proven by
TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator."
git push
```

---

### Task 4: Integration Test Stub + Final Regression

**Files:**
- Create: `orchestrator/internal/cloudgraph/azure_discovery_integration_test.go`

**Interfaces:**
- Consumes: `AzureDiscoveryConfig`, `NewAzureDiscoveryClient`, `DiscoverIdentities`, `DiscoverResources`, `DiscoverPermissions` (Tasks 1-3, unmodified).
- Produces: nothing consumed by later work — this is the plan's final task.

- [ ] **Step 1: Write the integration test (build-tag gated, not run by this plan)**

Create `orchestrator/internal/cloudgraph/azure_discovery_integration_test.go`:

```go
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
```

- [ ] **Step 2: Verify the integration test is excluded from a normal test run**

Run: `go test ./internal/cloudgraph -v 2>&1 | grep -i "TestAzureDiscovery_Integration"`
Expected: no output — the build tag excludes the file entirely from a tag-less `go test`, so the test name never appears.

- [ ] **Step 3: Run go vet on the package**

Run: `go vet ./internal/cloudgraph`
Expected: clean, no output.

- [ ] **Step 4: Run the full package regression one more time**

Run: `go test ./internal/cloudgraph -v`
Expected: All tests PASS (Phase 1-5's 66+ subtests plus this plan's new tests). Zero regressions.

- [ ] **Step 5: Run the cross-package regression check (AD/scenario/controlval/campaign untouched)**

Run: `go test ./internal/ad... ./internal/scenario... ./internal/controlval... ./internal/campaign...`
Expected: All PASS — this plan never modified any file outside `internal/cloudgraph`, so this is a confirmation, not a risk.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/cloudgraph/azure_discovery_integration_test.go
git commit -m "test(cloudgraph): gated Azure discovery integration test (requires real AZURE_* env vars)"
git push
```

---

## Plan Completion Criteria

- `AzureDiscoveryClient` exists with `DiscoverIdentities`, `DiscoverResources`, `DiscoverPermissions`, all reusing `msauth.EntraTokenSource` unmodified.
- Every discovered object carries a non-nil `Provenance` with `Confidence: "observed"`.
- `DiscoverPermissions` emits one `CloudPermission` per granted action (corrected from the spec's `Action="*"` sentinel), proven compatible with the real, unmodified `AzureEvaluator` by `TestDiscoverPermissions_DiscoveredEdgeEvaluatesViaUnmodifiedAzureEvaluator`.
- All 5 Review Focus items have a passing, named test.
- Zero modifications to any pre-existing `cloudgraph` file.
- Zero regressions in `internal/ad...`, `internal/scenario...`, `internal/controlval...`, `internal/campaign...`.
- The integration test exists, is excluded from normal runs by its build tag, and has never been executed against the real tenant in this plan (no credentials exist yet) — honestly reported as such, not claimed as verified.
