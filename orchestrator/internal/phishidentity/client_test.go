package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

// TestListOAuthConsentGrants_HTTPTestServer_RealOAuthAndHTTPPath proves
// the real adapter code path -- actual OAuth client-credentials token
// exchange, an authenticated HTTP GET, and JSON parsing against a mock
// Graph server -- the same discipline
// emailgwefficacy.TestEmailGWScenarioMaturity_RealRun_AllPreventionScenarios
// already established for the Defender adapter. Not a live tenant; that
// stays separately tracked.
func TestListOAuthConsentGrants_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotAuthHeader string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "grant-1", "clientId": "sp-attacker-app", "consentType": "AllPrincipals", "scope": "Mail.Read Files.ReadWrite.All"},
				{"id": "grant-2", "clientId": "sp-benign-app", "consentType": "Principal", "principalId": "user-1", "scope": "User.Read"},
			},
		})
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	grants, err := client.ListOAuthConsentGrants(t.Context())
	if err != nil {
		t.Fatalf("ListOAuthConsentGrants() error = %v", err)
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q (real token exchange must flow through)", gotAuthHeader, "Bearer tok")
	}
	if len(grants) != 2 {
		t.Fatalf("len(grants) = %d, want 2", len(grants))
	}

	if !grants[0].IsTenantWideAndRisky() {
		t.Errorf("grants[0] (AllPrincipals + Mail.Read/Files.ReadWrite.All) IsTenantWideAndRisky() = false, want true")
	}
	if grants[1].IsTenantWideAndRisky() {
		t.Errorf("grants[1] (Principal + User.Read only) IsTenantWideAndRisky() = true, want false")
	}
}

func TestOAuthConsentGrant_RiskyScopes_FiltersAgainstConservativeList(t *testing.T) {
	g := OAuthConsentGrant{Scope: "User.Read Mail.ReadWrite openid profile"}
	risky := g.RiskyScopes()
	if len(risky) != 1 || risky[0] != "Mail.ReadWrite" {
		t.Errorf("RiskyScopes() = %v, want [\"Mail.ReadWrite\"]", risky)
	}
}

func TestOAuthConsentGrant_IsTenantWideAndRisky_RequiresBothConditions(t *testing.T) {
	cases := []struct {
		name string
		g    OAuthConsentGrant
		want bool
	}{
		{"tenant-wide but benign scope", OAuthConsentGrant{ConsentType: "AllPrincipals", Scope: "User.Read"}, false},
		{"risky scope but single-user consent", OAuthConsentGrant{ConsentType: "Principal", Scope: "Mail.Read"}, false},
		{"tenant-wide and risky", OAuthConsentGrant{ConsentType: "AllPrincipals", Scope: "Mail.Read"}, true},
	}
	for _, c := range cases {
		if got := c.g.IsTenantWideAndRisky(); got != c.want {
			t.Errorf("%s: IsTenantWideAndRisky() = %v, want %v", c.name, got, c.want)
		}
	}
}
