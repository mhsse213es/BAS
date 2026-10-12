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
