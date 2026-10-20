package cloudgraph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	hTenant     = "t1"
	hRootID     = "/providers/Microsoft.Management/managementGroups/t1"
	hChildMG    = "/providers/Microsoft.Management/managementGroups/mg-child"
	hSiblingMG  = "/providers/Microsoft.Management/managementGroups/mg-sibling"
	hSubScope   = "/subscriptions/sub-1"
	hOwnerRole  = "/role-owner"
	hAccount    = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa1"
	hAliceOID   = "alice-oid"
	hBobOID     = "bob-oid"
	hAliceCanon = "azure:user_alice-oid"
)

// hierarchyTree places sub-1 under mg-child and sub-2 under a sibling group.
// The sibling is the case the exact-scope filter exists for: a list at
// mg-child's scope must not pull in grants made on other subscriptions.
const hierarchyTree = `{"id":"` + hRootID + `","properties":{"children":[
 {"id":"` + hChildMG + `","type":"Microsoft.Management/managementGroups","children":[
   {"id":"` + hSubScope + `","type":"/subscriptions"}]},
 {"id":"` + hSiblingMG + `","type":"Microsoft.Management/managementGroups","children":[
   {"id":"/subscriptions/sub-2","type":"/subscriptions"}]}
]}}`

// hServer serves the hierarchy, the role and deny lists at each scope, and the
// Owner role definition. Paths not listed are a test failure.
func hServer(t *testing.T, treeBody string, denyAtChild string) *httptest.Server {
	t.Helper()
	childRoles := `{"value":[
	 {"properties":{"principalId":"` + hAliceOID + `","scope":"` + hChildMG + `","roleDefinitionId":"` + hOwnerRole + `"}},
	 {"properties":{"principalId":"` + hBobOID + `","scope":"/subscriptions/sub-2","roleDefinitionId":"` + hOwnerRole + `"}}
	]}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case path == "/providers/Microsoft.Management/managementGroups/t1":
			if treeBody == "forbidden" {
				w.WriteHeader(http.StatusForbidden)
				io.WriteString(w, `{"error":{"code":"AuthorizationFailed"}}`)
				return
			}
			io.WriteString(w, treeBody)
		case path == "/providers/Microsoft.Management/managementGroups/mg-child/providers/Microsoft.Authorization/roleAssignments":
			io.WriteString(w, childRoles)
		case path == "/providers/Microsoft.Management/managementGroups/mg-child/providers/Microsoft.Authorization/denyAssignments":
			io.WriteString(w, denyAtChild)
		case path == "/providers/Microsoft.Management/managementGroups/t1/providers/Microsoft.Authorization/roleAssignments",
			path == "/providers/Microsoft.Management/managementGroups/t1/providers/Microsoft.Authorization/denyAssignments",
			path == "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments",
			path == "/subscriptions/sub-1/providers/Microsoft.Authorization/denyAssignments":
			io.WriteString(w, `{"value":[]}`)
		case path == hOwnerRole:
			io.WriteString(w, `{"properties":{"roleName":"Owner","permissions":[{"actions":["*"],"notActions":[],"dataActions":[],"notDataActions":[]}]}}`)
		default:
			t.Errorf("unexpected ARM path %s", path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// hDenyChild has one deny that applies to this subscription through mg-child,
// and one doNotApplyToChildScopes deny that applies only at mg-child itself.
var hDenyChild = `{"value":[
 {"properties":{"scope":"` + hChildMG + `","doNotApplyToChildScopes":false,
   "permissions":[{"actions":["` + listKeys + `"],"notActions":[],"dataActions":[],"notDataActions":[]}],
   "principals":[{"id":"` + hAliceOID + `","type":"User"}],"excludePrincipals":[]}},
 {"properties":{"scope":"` + hChildMG + `","doNotApplyToChildScopes":true,
   "permissions":[{"actions":["*"],"notActions":[],"dataActions":[],"notDataActions":[]}],
   "principals":[{"id":"` + hAliceOID + `","type":"User"}],"excludePrincipals":[]}}
]}`

func hClient(t *testing.T, srv *httptest.Server) *AzureDiscoveryClient {
	t.Helper()
	tok := azureTokenMock(t)
	t.Cleanup(tok.Close)
	return newTestAzureDiscoveryClient(t, tok.URL, srv.URL, srv.URL)
}

func hIdentities() []*CloudIdentity {
	return []*CloudIdentity{{CanonicalID: hAliceCanon, Kind: "entra-user"}}
}

func hResources() []*CloudResource {
	return []*CloudResource{{CanonicalID: hAccount, Kind: "Microsoft.Storage/storageAccounts"}}
}

func TestInheritedOwner_ReachesSubscriptionResource(t *testing.T) {
	srv := hServer(t, hierarchyTree, `{"value":[]}`)
	defer srv.Close()
	c := hClient(t, srv)

	perms, _, err := c.DiscoverPermissionsWithInheritance(context.Background(), hIdentities(), hResources())
	if err != nil {
		t.Fatalf("DiscoverPermissionsWithInheritance: %v", err)
	}
	var edge *CloudPermission
	for _, p := range perms {
		if p.Source.CanonicalID == hAliceCanon {
			edge = p
		}
	}
	if edge == nil {
		t.Fatal("alice's management-group Owner produced no edge")
	}
	if edge.Attributes["inherited_from"] != hChildMG || edge.Attributes["role_scope"] != hSubScope {
		t.Errorf("attributes = %+v, want inherited_from %s and role_scope %s", edge.Attributes, hChildMG, hSubScope)
	}

	g := &DiscoveredGraph{Identities: hIdentities(), Resources: hResources(), Permissions: perms, Evaluations: map[string]PathState{}}
	res := ExecuteCloudScenario(CloudScenarioByID("data-access-azure"), g, &AzureEvaluator{}, hAliceCanon, hAccount)
	if res.Steps[0].ExecutionOutcome != "Allowed" {
		t.Errorf("listKeys under inherited Owner = %s, want Allowed", res.Steps[0].ExecutionOutcome)
	}
}

func TestInheritedAssignment_OtherSubscriptionGrantsIgnored(t *testing.T) {
	srv := hServer(t, hierarchyTree, `{"value":[]}`)
	defer srv.Close()
	c := hClient(t, srv)

	perms, _, err := c.DiscoverPermissionsWithInheritance(context.Background(), []*CloudIdentity{
		{CanonicalID: "azure:user_" + hBobOID, Kind: "entra-user"},
	}, hResources())
	if err != nil {
		t.Fatalf("DiscoverPermissionsWithInheritance: %v", err)
	}
	if len(perms) != 0 {
		t.Errorf("bob's grant on sub-2 leaked into sub-1's graph: %+v", perms)
	}
}

func TestInheritedDeny_BlocksSubscriptionAndDropsExactScopeOnly(t *testing.T) {
	srv := hServer(t, hierarchyTree, hDenyChild)
	defer srv.Close()
	c := hClient(t, srv)

	perms, _, err := c.DiscoverPermissionsWithInheritance(context.Background(), hIdentities(), hResources())
	if err != nil {
		t.Fatalf("DiscoverPermissionsWithInheritance: %v", err)
	}
	denials, stats, err := c.DiscoverDenyAssignmentsWithInheritance(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignmentsWithInheritance: %v", err)
	}
	// The exact-scope-only deny applies just at mg-child, not to this sub, so it
	// is dropped before counting and only the applicable deny remains.
	if len(denials) != 1 {
		t.Errorf("denials = %d, want 1 applicable inherited deny", len(denials))
	}
	if denials[0].Scope != hSubScope {
		t.Errorf("inherited deny scope = %s, want rewritten to %s", denials[0].Scope, hSubScope)
	}
	_ = stats

	g := &DiscoveredGraph{Identities: hIdentities(), Resources: hResources(), Permissions: perms, Denials: denials, Evaluations: map[string]PathState{}}
	res := ExecuteCloudScenario(CloudScenarioByID("data-access-azure"), g, &AzureEvaluator{}, hAliceCanon, hAccount)
	if res.Steps[0].ExecutionOutcome != "Blocked" {
		t.Errorf("listKeys under an inherited deny = %s, want Blocked", res.Steps[0].ExecutionOutcome)
	}
}

func TestAncestorManagementGroups_SubscriptionNotVisibleFailsClosed(t *testing.T) {
	tree := `{"id":"` + hRootID + `","properties":{"children":[{"id":"` + hSiblingMG + `","type":"Microsoft.Management/managementGroups","children":[]}]}}`
	srv := hServer(t, tree, `{"value":[]}`)
	defer srv.Close()
	c := hClient(t, srv)

	_, _, err := c.DiscoverPermissionsWithInheritance(context.Background(), hIdentities(), hResources())
	if err == nil || !strings.Contains(err.Error(), "not in the management group hierarchy") {
		t.Fatalf("err = %v, want a failure naming the invisible subscription; an empty ancestor set would hide inherited access", err)
	}
}

func TestAncestorManagementGroups_ForbiddenTreeNamesTheGap(t *testing.T) {
	srv := hServer(t, "forbidden", `{"value":[]}`)
	defer srv.Close()
	c := hClient(t, srv)

	_, _, err := c.DiscoverPermissionsWithInheritance(context.Background(), hIdentities(), hResources())
	if err == nil || !strings.Contains(err.Error(), "Reader on the tenant root management group") {
		t.Fatalf("err = %v, want the missing tenant-root Reader named", err)
	}
}

func TestMgPathTo_ReturnsRootFirstPathToParent(t *testing.T) {
	var tree mgTree
	if err := json.Unmarshal([]byte(hierarchyTree), &tree); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	path, ok := mgPathTo(tree.Properties.Children, hSubScope, []string{hRootID}, 0)
	if !ok || len(path) != 2 || path[0] != hRootID || path[1] != hChildMG {
		t.Errorf("path = %v (found %v), want [root, mg-child]", path, ok)
	}
}
