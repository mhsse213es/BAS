package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestRevokeSignInSessions_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotMethod, gotPath, gotAuthHeader string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuthHeader = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if err := client.RevokeSignInSessions(t.Context(), "user-123"); err != nil {
		t.Fatalf("RevokeSignInSessions() error = %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want %q", gotMethod, http.MethodPost)
	}
	if gotPath != "/users/user-123/revokeSignInSessions" {
		t.Errorf("path = %q, want %q", gotPath, "/users/user-123/revokeSignInSessions")
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer tok")
	}
}

func TestRevokeSignInSessions_NonSuccessStatus_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	if err := client.RevokeSignInSessions(t.Context(), "user-123"); err == nil {
		t.Error("RevokeSignInSessions() with a 403 response = nil error, want an error")
	}
}

// sessionGraphMock serves /users/{id} (?$select=signInSessionsValidFromDateTime)
// and /users/{id}/revokeSignInSessions from an in-memory, mutable
// timestamp -- revoke sets it forward, each GET returns whatever it
// currently is. advanceOnRevoke=false simulates a revoke that Graph
// accepted but that never actually changed the marker (the
// RevocationNotVerified case).
func sessionGraphMock(t *testing.T, initial time.Time, advanceOnRevoke bool) *httptest.Server {
	t.Helper()
	current := initial
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revokeSignInSessions"):
			if advanceOnRevoke {
				current = current.Add(1 * time.Hour)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{"signInSessionsValidFromDateTime": current.Format(time.RFC3339)})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestRevokeAndVerifySignInSessions_MarkerAdvances_Verified(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	baseline := time.Now().UTC().Truncate(time.Second)
	graphSrv := sessionGraphMock(t, baseline, true)
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	result := client.RevokeAndVerifySignInSessions(t.Context(), "user-123")
	if result.Verification != RevocationVerified {
		t.Fatalf("Verification = %q (%s), want %q", result.Verification, result.Detail, RevocationVerified)
	}
	if !result.After.After(result.Baseline) {
		t.Errorf("After (%s) did not advance past Baseline (%s)", result.After, result.Baseline)
	}
}

// TestRevokeAndVerifySignInSessions_PropagationDelay_VerifiedOnSecondPoll
// exercises the actual retry path: the marker does NOT advance on the
// first post-revocation read (simulating real propagation delay), only
// on the second -- proving the poll loop keeps trying within its
// budget instead of concluding NotVerified from one read alone.
func TestRevokeAndVerifySignInSessions_PropagationDelay_VerifiedOnSecondPoll(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	baseline := time.Now().UTC().Truncate(time.Second)
	current := baseline
	getsAfterRevoke := 0
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revokeSignInSessions"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet:
			if getsAfterRevoke == 2 { // GET #1 is the baseline read, GET #2 is the first (stale) poll, GET #3 advances
				current = current.Add(1 * time.Hour)
			}
			getsAfterRevoke++
			json.NewEncoder(w).Encode(map[string]any{"signInSessionsValidFromDateTime": current.Format(time.RFC3339)})
		}
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL
	client.VerificationPollAttempts = 3
	client.VerificationPollInterval = time.Millisecond

	result := client.RevokeAndVerifySignInSessions(t.Context(), "user-123")
	if result.Verification != RevocationVerified {
		t.Fatalf("Verification = %q (%s), want %q (the retry loop must keep polling until the marker advances, within its budget)", result.Verification, result.Detail, RevocationVerified)
	}
	if getsAfterRevoke < 3 { // baseline + first (stale) poll + second (advanced) poll
		t.Errorf("getsAfterRevoke = %d, want at least 3 (baseline read, one stale poll, one successful poll)", getsAfterRevoke)
	}
}

func TestRevokeAndVerifySignInSessions_MarkerNeverAdvances_NotVerified(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	baseline := time.Now().UTC().Truncate(time.Second)
	graphSrv := sessionGraphMock(t, baseline, false) // revoke accepted, marker never moves
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL
	client.VerificationPollAttempts = 2
	client.VerificationPollInterval = time.Millisecond // avoid a real sleep in tests

	result := client.RevokeAndVerifySignInSessions(t.Context(), "user-123")
	if result.Verification != RevocationNotVerified {
		t.Errorf("Verification = %q, want %q (a successful POST alone must never grade as verified)", result.Verification, RevocationNotVerified)
	}
}

func TestRevokeAndVerifySignInSessions_DispatchRejected_Unknown(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"signInSessionsValidFromDateTime": time.Now().UTC().Format(time.RFC3339)})
			return
		}
		w.WriteHeader(http.StatusForbidden) // revoke rejected
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	result := client.RevokeAndVerifySignInSessions(t.Context(), "user-123")
	if result.Verification != RevocationUnknown {
		t.Errorf("Verification = %q, want %q", result.Verification, RevocationUnknown)
	}
	if result.DispatchErr == nil {
		t.Error("DispatchErr = nil, want the 403 surfaced")
	}
}

func TestRevokeAndVerifySignInSessions_PostRevocationReadAlwaysErrors_Unknown(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	reads := 0
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet:
			reads++
			if reads == 1 { // the baseline read succeeds
				json.NewEncoder(w).Encode(map[string]any{"signInSessionsValidFromDateTime": time.Now().UTC().Format(time.RFC3339)})
				return
			}
			w.WriteHeader(http.StatusServiceUnavailable) // every post-revocation read throttled/fails
		}
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL
	client.VerificationPollAttempts = 2
	client.VerificationPollInterval = time.Millisecond

	result := client.RevokeAndVerifySignInSessions(t.Context(), "user-123")
	if result.Verification != RevocationUnknown {
		t.Errorf("Verification = %q, want %q (a failed re-read must never be read as either success or failure)", result.Verification, RevocationUnknown)
	}
}

func TestRevokeAndVerifySignInSessions_BaselineReadFails_Unknown(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	result := client.RevokeAndVerifySignInSessions(t.Context(), "user-123")
	if result.Verification != RevocationUnknown {
		t.Errorf("Verification = %q, want %q", result.Verification, RevocationUnknown)
	}
	if result.DispatchErr != nil {
		t.Error("DispatchErr should be nil -- the dispatch was never attempted because the baseline read failed first")
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
