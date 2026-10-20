package cloudgraph

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	denyAlice   = "azure:user_alice-oid"
	denyRG      = "/subscriptions/sub-1/resourceGroups/rg-data"
	denyInRG    = "/subscriptions/sub-1/resourceGroups/rg-data/providers/Microsoft.Storage/storageAccounts/sa1"
	denyOutside = "/subscriptions/sub-1/resourceGroups/rg-other/providers/Microsoft.Storage/storageAccounts/sa2"
	listKeys    = "Microsoft.Storage/storageAccounts/listKeys/action"
)

// denyListing is an ARM denyAssignments response with three entries: one for
// alice scoped to rg-data, one for everyone with an exact-scope-only flag, and
// one for everyone excluding alice.
const denyListing = `{"value":[
 {"properties":{"scope":"` + denyRG + `","doNotApplyToChildScopes":false,
   "permissions":[{"actions":["` + listKeys + `"],"notActions":[],"dataActions":[],"notDataActions":[]}],
   "principals":[{"id":"alice-oid","type":"User"}],"excludePrincipals":[]}},
 {"properties":{"scope":"/subscriptions/sub-1","doNotApplyToChildScopes":true,
   "permissions":[{"actions":["*"],"notActions":[],"dataActions":[],"notDataActions":[]}],
   "principals":[{"id":"` + azureEveryonePrincipal + `","type":"Everyone"}],"excludePrincipals":[]}},
 {"properties":{"scope":"/subscriptions/sub-1/resourceGroups/rg-other","doNotApplyToChildScopes":false,
   "permissions":[{"actions":["*"],"notActions":["Microsoft.Storage/storageAccounts/read"],"dataActions":[],"notDataActions":[]}],
   "principals":[{"id":"` + azureEveryonePrincipal + `","type":"Everyone"}],
   "excludePrincipals":[{"id":"alice-oid","type":"User"}]}}
]}`

func denyARM(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/subscriptions/sub-1/providers/Microsoft.Authorization/denyAssignments" {
			io.WriteString(w, denyListing)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// denyClient returns a client whose ARM endpoint serves denyListing.
func denyClient(t *testing.T) (*AzureDiscoveryClient, func()) {
	t.Helper()
	tok := azureTokenMock(t)
	arm := denyARM(t)
	return newTestAzureDiscoveryClient(t, tok.URL, arm.URL, arm.URL), func() {
		tok.Close()
		arm.Close()
	}
}

func TestDiscoverDenyAssignments_CountsAndExactScope(t *testing.T) {
	client, done := denyClient(t)
	defer done()
	denials, stats, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}
	if stats.Found != 3 || stats.ExactScopeOnly != 1 {
		t.Errorf("stats = %+v, want Found 3 and ExactScopeOnly 1", stats)
	}
	if len(denials) != 2 {
		t.Errorf("denials = %d, want 2 (one per non-exact deny block)", len(denials))
	}
}

func TestAttachAzureDenies_ScopedDenyBlocksOnlyItsScope(t *testing.T) {
	client, done := denyClient(t)
	defer done()
	denials, _, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}

	src := &CloudIdentity{CanonicalID: denyAlice, Kind: "entra-user"}
	inRG := &CloudPermission{Source: src, Target: &CloudResource{CanonicalID: denyInRG}, Action: listKeys, SourceType: "role-assignment",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": listKeys}}
	outside := &CloudPermission{Source: src, Target: &CloudResource{CanonicalID: denyOutside}, Action: listKeys, SourceType: "role-assignment",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": listKeys}}

	if marked := attachAzureDenies([]*CloudPermission{inRG, outside}, denials); marked != 1 {
		t.Fatalf("marked = %d, want exactly the in-scope edge", marked)
	}
	ev := &AzureEvaluator{}
	if got := ev.EvaluatePermission(inRG, &RequestContext{}); got.State != Blocked || got.BlockedBy != "deny-assignment" {
		t.Errorf("in-scope listKeys = %+v, want blocked by deny-assignment", got)
	}
	if got := ev.EvaluatePermission(outside, &RequestContext{}); got.State != PolicySupported {
		t.Errorf("out-of-scope listKeys = %+v, want the role grant to stand", got)
	}
}

func TestAttachAzureDenies_EveryoneDenyReachesNonExcludedPrincipal(t *testing.T) {
	client, done := denyClient(t)
	defer done()
	denials, _, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}
	bob := &CloudIdentity{CanonicalID: "azure:user_bob-oid", Kind: "entra-user"}
	edge := &CloudPermission{Source: bob, Target: &CloudResource{CanonicalID: denyOutside},
		Action: listKeys, SourceType: "role-assignment", Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": listKeys}}
	attachAzureDenies([]*CloudPermission{edge}, denials)
	if edge.Attributes["deny_assignment"] != "true" {
		t.Fatal("everyone-deny with wildcard action should mark bob's listKeys")
	}
	if got := (&AzureEvaluator{}).EvaluatePermission(edge, &RequestContext{}); got.State != Blocked {
		t.Errorf("state = %s, want blocked", got.State)
	}
}

func TestAttachAzureDenies_ExcludedPrincipalNotDenied(t *testing.T) {
	client, done := denyClient(t)
	defer done()
	denials, _, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}
	alice := &CloudIdentity{CanonicalID: denyAlice, Kind: "entra-user"}
	edge := &CloudPermission{Source: alice, Target: &CloudResource{CanonicalID: denyOutside},
		Action: "Microsoft.Storage/storageAccounts/read", SourceType: "role-assignment",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": "Microsoft.Storage/storageAccounts/read"}}
	attachAzureDenies([]*CloudPermission{edge}, denials)
	if edge.Attributes["deny_assignment"] == "true" {
		t.Error("excluded principal must not be denied by the everyone-deny")
	}
}

func TestAzureAnyPatternMatches_DenyPatterns(t *testing.T) {
	cases := []struct {
		patterns []string
		action   string
		want     bool
	}{
		{[]string{"*"}, "Microsoft.Storage/storageAccounts/read", true},
		{[]string{"Microsoft.Storage/*"}, "Microsoft.Storage/storageAccounts/read", true},
		{[]string{"Microsoft.Compute/*"}, "Microsoft.Storage/storageAccounts/read", false},
		{[]string{listKeys}, listKeys, true},
		{[]string{listKeys}, "Microsoft.Storage/storageAccounts/read", false},
	}
	for _, c := range cases {
		if got := azureAnyPatternMatches(c.patterns, c.action); got != c.want {
			t.Errorf("azureAnyPatternMatches(%v, %s) = %v, want %v", c.patterns, c.action, got, c.want)
		}
	}
}
