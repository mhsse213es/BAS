package cloudgraph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	wcUser    = "user-wc"
	wcSub     = "/subscriptions/sub-1"
	wcRG      = "/subscriptions/sub-1/resourceGroups/rg-data"
	wcAccount = "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"
)

// wildcardARM serves one role assignment for wcUser at assignScope, a role
// definition with the given permission blocks, and the denial list.
func wildcardARM(t *testing.T, assignScope string, perms []map[string]any, denials []map[string]any) *httptest.Server {
	t.Helper()
	roleDef := "/role-wc"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments":
			json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"properties": map[string]any{
				"principalId": wcUser, "scope": assignScope, "roleDefinitionId": roleDef}}}})
		case roleDef:
			json.NewEncoder(w).Encode(map[string]any{"properties": map[string]any{"roleName": "wc", "permissions": perms}})
		case "/subscriptions/sub-1/providers/Microsoft.Authorization/denyAssignments":
			json.NewEncoder(w).Encode(map[string]any{"value": denials})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// discoverWildcard runs the real permission and deny passes for one role and
// returns a graph built the way the Azure discoverer builds it.
func discoverWildcard(t *testing.T, assignScope string, perms []map[string]any, denials []map[string]any) *DiscoveredGraph {
	t.Helper()
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := wildcardARM(t, assignScope, perms, denials)
	defer arm.Close()
	client := newTestAzureDiscoveryClient(t, tok.URL, arm.URL, arm.URL)
	identities := []*CloudIdentity{{CanonicalID: "azure:user_" + wcUser, Kind: "entra-user"}}
	resources := []*CloudResource{{CanonicalID: wcAccount, Kind: "Microsoft.Storage/storageAccounts"}}
	permissions, _, err := client.DiscoverPermissions(context.Background(), identities, resources)
	if err != nil {
		t.Fatalf("DiscoverPermissions: %v", err)
	}
	denialList, _, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}
	attachAzureDenies(permissions, denialList)
	return &DiscoveredGraph{Identities: identities, Resources: resources, Permissions: permissions,
		Denials: denialList, Evaluations: map[string]PathState{}}
}

func wildcardPerm(actions, notActions []string) map[string]any {
	return map[string]any{"actions": actions, "notActions": notActions, "dataActions": []string{}, "notDataActions": []string{}}
}

// An Owner-style grant at subscription scope must reach a concrete listKeys on a
// storage account below it. Before this fix the literal "*" edge never matched.
func TestAzureWildcardOwner_CoversConcreteStepsBelowSubscription(t *testing.T) {
	g := discoverWildcard(t, wcSub, []map[string]any{wildcardPerm([]string{"*"}, []string{})}, nil)
	ev := &AzureEvaluator{}
	edge := scenarioStepEdge(g, &CloudIdentity{CanonicalID: "azure:user_" + wcUser}, &CloudResource{CanonicalID: wcAccount}, listKeys)
	if got := ev.EvaluatePermission(edge, &RequestContext{}); got.State != PolicySupported {
		t.Errorf("listKeys under subscription Owner = %+v, want the grant to stand", got)
	}
}

// Contributor-style: "*" minus an authorization write carve-out. Ordinary
// actions are granted; the carved-out action is not.
func TestAzureWildcardNotActions_CarveOutHonoured(t *testing.T) {
	g := discoverWildcard(t, wcRG, []map[string]any{wildcardPerm([]string{"*"}, []string{"Microsoft.Authorization/*/Write"})}, nil)
	ev := &AzureEvaluator{}
	src := &CloudIdentity{CanonicalID: "azure:user_" + wcUser}
	tgt := &CloudResource{CanonicalID: wcAccount}

	if got := ev.EvaluatePermission(scenarioStepEdge(g, src, tgt, listKeys), &RequestContext{}); got.State != PolicySupported {
		t.Errorf("listKeys under Contributor-style grant = %+v, want granted", got)
	}
	carved := scenarioStepEdge(g, src, tgt, "Microsoft.Authorization/roleAssignments/write")
	if got := ev.EvaluatePermission(carved, &RequestContext{}); got.State == PolicySupported {
		t.Error("a notActions carve-out must not be granted by the wildcard")
	}
}

// Reader-style: "*/read" grants reads and nothing else.
func TestAzureWildcardSuffix_ReadOnly(t *testing.T) {
	g := discoverWildcard(t, wcRG, []map[string]any{wildcardPerm([]string{"*/read"}, []string{})}, nil)
	ev := &AzureEvaluator{}
	src := &CloudIdentity{CanonicalID: "azure:user_" + wcUser}
	tgt := &CloudResource{CanonicalID: wcAccount}

	if got := ev.EvaluatePermission(scenarioStepEdge(g, src, tgt, "Microsoft.Storage/storageAccounts/read"), &RequestContext{}); got.State != PolicySupported {
		t.Errorf("read under */read = %+v, want granted", got)
	}
	if got := ev.EvaluatePermission(scenarioStepEdge(g, src, tgt, listKeys), &RequestContext{}); got.State == PolicySupported {
		t.Errorf("listKeys under */read = %+v, want not granted", got)
	}
}

// A resource-group deny must block the resource even though the granting
// Owner edge's own target is the subscription. This is why denials are
// re-applied per step against the step's resource.
func TestAzureWildcardOwner_DenyAtResourceGroupBlocksResource(t *testing.T) {
	deny := []map[string]any{{"properties": map[string]any{
		"scope":                   wcRG,
		"doNotApplyToChildScopes": false,
		"permissions":             []map[string]any{wildcardPerm([]string{listKeys}, []string{})},
		"principals":              []map[string]any{{"id": wcUser, "type": "User"}},
		"excludePrincipals":       []map[string]any{},
	}}}
	g := discoverWildcard(t, wcSub, []map[string]any{wildcardPerm([]string{"*"}, []string{})}, deny)
	ev := &AzureEvaluator{}
	edge := scenarioStepEdge(g, &CloudIdentity{CanonicalID: "azure:user_" + wcUser}, &CloudResource{CanonicalID: wcAccount}, listKeys)
	if got := ev.EvaluatePermission(edge, &RequestContext{}); got.State != Blocked {
		t.Errorf("listKeys under a resource-group deny = %+v, want Blocked", got)
	}
}
