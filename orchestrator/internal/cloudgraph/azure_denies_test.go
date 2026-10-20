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

func TestDiscoverDenyAssignments_IndexesAndCountsExactScope(t *testing.T) {
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := denyARM(t)
	defer arm.Close()
	client := newTestAzureDiscoveryClient(t, tok.URL, arm.URL, arm.URL)

	index, stats, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}
	if stats.Found != 3 || stats.ExactScopeOnly != 1 {
		t.Errorf("stats = %+v, want Found 3 and ExactScopeOnly 1", stats)
	}
	if len(index["alice-oid"]) != 1 {
		t.Errorf("alice should be indexed under her object ID, got %d entries", len(index["alice-oid"]))
	}
	if len(index[azureEveryonePrincipal]) != 1 {
		t.Errorf("everyone-entry count = %d, want 1 (exact-scope entry skipped)", len(index[azureEveryonePrincipal]))
	}
}

func TestAttachAzureDenies_ScopedDenyBlocksOnlyItsScope(t *testing.T) {
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := denyARM(t)
	defer arm.Close()
	client := newTestAzureDiscoveryClient(t, tok.URL, arm.URL, arm.URL)
	index, _, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}

	src := &CloudIdentity{CanonicalID: denyAlice, Kind: "entra-user"}
	inRG := &CloudPermission{Source: src, Target: &CloudResource{CanonicalID: denyInRG}, Action: listKeys, SourceType: "role-assignment",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": listKeys}}
	outside := &CloudPermission{Source: src, Target: &CloudResource{CanonicalID: denyOutside}, Action: listKeys, SourceType: "role-assignment",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": listKeys}}

	marked := attachAzureDenies([]*CloudPermission{inRG, outside}, index)
	if marked < 1 {
		t.Fatalf("marked = %d, want at least the in-scope edge", marked)
	}

	ev := &AzureEvaluator{}
	if got := ev.EvaluatePermission(inRG, &RequestContext{}); got.State != Blocked || got.BlockedBy != "deny-assignment" {
		t.Errorf("in-scope listKeys = %+v, want blocked by deny-assignment", got)
	}
	if got := ev.EvaluatePermission(outside, &RequestContext{}); got.State != PolicySupported {
		t.Errorf("out-of-scope listKeys = %+v, want the role grant to stand", got)
	}
}

func TestAttachAzureDenies_WildcardEveryoneDenyBlocksSubscriptionAfterExcludedPrincipal(t *testing.T) {
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := denyARM(t)
	defer arm.Close()
	client := newTestAzureDiscoveryClient(t, tok.URL, arm.URL, arm.URL)
	index, _, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}

	// bob is not excluded from the rg-other everyone-deny, whose "*" action is
	// held by the deny even though notActions names storageAccounts/read: the
	// wildcard is not expanded, so that exemption is not honoured. The result
	// over-blocks, which is the conservative direction.
	bob := &CloudIdentity{CanonicalID: "azure:user_bob-oid", Kind: "entra-user"}
	edge := &CloudPermission{Source: bob, Target: &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-other/providers/Microsoft.Storage/storageAccounts/sa2"},
		Action: listKeys, SourceType: "role-assignment", Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": listKeys}}
	attachAzureDenies([]*CloudPermission{edge}, index)
	if edge.Attributes["deny_assignment"] != "true" {
		t.Fatal("wildcard everyone-deny should mark bob's listKeys")
	}
	if got := (&AzureEvaluator{}).EvaluatePermission(edge, &RequestContext{}); got.State != Blocked {
		t.Errorf("state = %s, want blocked", got.State)
	}
}

func TestAttachAzureDenies_ExcludedPrincipalNotDenied(t *testing.T) {
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := denyARM(t)
	defer arm.Close()
	client := newTestAzureDiscoveryClient(t, tok.URL, arm.URL, arm.URL)
	index, _, err := client.DiscoverDenyAssignments(context.Background())
	if err != nil {
		t.Fatalf("DiscoverDenyAssignments: %v", err)
	}
	// Alice is excluded from the rg-other everyone-deny. Her only denial
	// there is the rg-data deny, which does not cover rg-other.
	alice := &CloudIdentity{CanonicalID: denyAlice, Kind: "entra-user"}
	edge := &CloudPermission{Source: alice, Target: &CloudResource{CanonicalID: "/subscriptions/sub-1/resourceGroups/rg-other/providers/Microsoft.Storage/storageAccounts/sa2"},
		Action: "Microsoft.Storage/storageAccounts/read", SourceType: "role-assignment",
		Attributes: map[string]string{"role_scope": "/subscriptions/sub-1", "role_actions": "Microsoft.Storage/storageAccounts/read"}}
	attachAzureDenies([]*CloudPermission{edge}, index)
	if edge.Attributes["deny_assignment"] == "true" {
		t.Error("excluded principal must not be denied by the everyone-deny")
	}
}

func TestDenyActionsCover(t *testing.T) {
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
		if got := denyActionsCover(c.patterns, c.action); got != c.want {
			t.Errorf("denyActionsCover(%v, %s) = %v, want %v", c.patterns, c.action, got, c.want)
		}
	}
}
