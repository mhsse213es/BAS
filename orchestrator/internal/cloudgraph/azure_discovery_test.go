package cloudgraph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDiscoverIdentities_FollowsGraphPagination(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	var graphSrv *httptest.Server
	graphSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users" && r.URL.Path != "/usersPage2" {
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
			return
		}
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
		"/subscriptions/sub-1":                     "subscription",
		"/subscriptions/sub-1/resourceGroups/rg-1": "resource-group",
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/foo": "unknown-scope",
		"": "unknown-scope",
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

// TestDiscoverPermissions_ExcludesNotActionsAndIncludesDataActions is the
// fix-pass test for the final review's Important finding: the role
// definition mapping ignored notActions/dataActions/notDataActions,
// which would under-report data-plane permissions (most PaaS services
// grant access almost entirely via dataActions) and over-report
// control-plane permissions for roles that carve out exclusions via
// notActions.
func TestDiscoverPermissions_ExcludesNotActionsAndIncludesDataActions(t *testing.T) {
	tokenSrv := azureTokenMock(t)
	defer tokenSrv.Close()

	roleDefID := "/role-mixed"
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
					"roleName": "Custom Mixed Role",
					"permissions": []map[string]any{
						{
							"actions":        []string{"Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/write"},
							"notActions":     []string{"Microsoft.Storage/storageAccounts/write"},
							"dataActions":    []string{"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"},
							"notDataActions": []string{},
						},
					},
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

	permissions, stats, err := c.DiscoverPermissions(context.Background(), identities, resources)
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}

	gotActions := map[string]bool{}
	for _, p := range permissions {
		gotActions[p.Action] = true
	}

	if gotActions["Microsoft.Storage/storageAccounts/write"] {
		t.Fatalf("gotActions = %+v, want write excluded (it is in notActions)", gotActions)
	}
	if !gotActions["Microsoft.Storage/storageAccounts/read"] {
		t.Fatalf("gotActions = %+v, want read present (in actions, not excluded)", gotActions)
	}
	if !gotActions["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"] {
		t.Fatalf("gotActions = %+v, want the dataAction present (data-plane grants must be included)", gotActions)
	}
	if len(permissions) != 2 || stats.ItemsFound != 2 {
		t.Fatalf("permissions = %+v, stats = %+v, want exactly 2 edges (read + dataAction, write excluded)", permissions, stats)
	}
	for _, p := range permissions {
		if strings.Contains(p.Attributes["role_actions"], "write") {
			t.Fatalf("role_actions = %q, must not contain the excluded write action", p.Attributes["role_actions"])
		}
	}
}
