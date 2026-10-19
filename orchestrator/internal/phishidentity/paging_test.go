package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// A second page must be read, so a partial first page is never graded as the whole
// answer. The next link keeps the same filter.
func TestListOAuthConsentGrantsForClients_FollowsNextLink(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("$skiptoken") == "" {
			json.NewEncoder(w).Encode(map[string]any{
				"@odata.nextLink": srv.URL + "/oauth2PermissionGrants?$filter=" + url.QueryEscape(r.URL.Query().Get("$filter")) + "&$skiptoken=p2",
				"value":           []map[string]any{{"id": "g1", "clientId": scopeClientA}},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{"id": "g2", "clientId": scopeClientA}}})
	}))
	defer srv.Close()
	c := newScopedClient(t, srv.URL)
	grants, err := c.ListOAuthConsentGrantsForClients(t.Context(), []string{scopeClientA})
	if err != nil {
		t.Fatalf("ListOAuthConsentGrantsForClients: %v", err)
	}
	if len(grants) != 2 {
		t.Errorf("grants = %d, want 2 across both pages", len(grants))
	}
}

// A next link that leaves the Graph host is refused, and no request is made to it.
func TestListOAuthConsentGrantsForClients_ForeignNextLinkRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"@odata.nextLink": "https://evil.example/oauth2PermissionGrants?$skiptoken=x",
			"value":           []map[string]any{},
		})
	}))
	defer srv.Close()
	c := newScopedClient(t, srv.URL)
	if _, err := c.ListOAuthConsentGrantsForClients(t.Context(), []string{scopeClientA}); err == nil {
		t.Fatal("a next link to another host was followed; it must be refused")
	}
}

// A listing that never ends is truncated: an error, never a partial success.
func TestListOAuthConsentGrantsForClients_EndlessPagesAreTruncatedNotPassed(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"@odata.nextLink": srv.URL + "/oauth2PermissionGrants?$filter=" + url.QueryEscape(r.URL.Query().Get("$filter")) + "&$skiptoken=again",
			"value":           []map[string]any{{"id": "g", "clientId": scopeClientA}},
		})
	}))
	defer srv.Close()
	c := newScopedClient(t, srv.URL)
	if _, err := c.ListOAuthConsentGrantsForClients(t.Context(), []string{scopeClientA}); err == nil {
		t.Fatal("an endless listing returned success; it must be an error")
	}
}

// A sign-in on a later page must count. Otherwise a deviceCode attempt on page two
// is invisible, and the verdict is drawn from an incomplete window.
func TestSignInsForUsers_LaterPageSignInIsNotDropped(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("$skiptoken") == "" {
			json.NewEncoder(w).Encode(map[string]any{
				"@odata.nextLink": srv.URL + "/auditLogs/signIns?$filter=" + url.QueryEscape(r.URL.Query().Get("$filter")) + "&$skiptoken=p2",
				"value":           []map[string]any{{"id": "s1", "authenticationProtocol": "deviceCode"}},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": "s2", "authenticationProtocol": "deviceCode",
				"appliedConditionalAccessPolicies": []map[string]any{{"displayName": "block", "result": "failure"}}}},
		})
	}))
	defer srv.Close()
	c := newScopedClient(t, srv.URL)
	events, err := c.SignInsForUsersByProtocol(t.Context(), "deviceCode", []string{"alice@contoso.example"})
	if err != nil {
		t.Fatalf("SignInsForUsersByProtocol: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2 across both pages", len(events))
	}
}
