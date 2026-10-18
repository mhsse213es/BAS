package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConditionalAccessPolicies_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotAuthHeader, gotPath string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "pol-1", "displayName": "Block legacy authentication and device code flow", "state": "enabled"},
				{"id": "pol-2", "displayName": "Require MFA for all users", "state": "enabledForReportingButNotEnforced"},
			},
		})
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	policies, err := client.ConditionalAccessPolicies(t.Context())
	if err != nil {
		t.Fatalf("ConditionalAccessPolicies() error = %v", err)
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer tok")
	}
	if gotPath != "/identity/conditionalAccess/policies" {
		t.Errorf("path = %q, want %q", gotPath, "/identity/conditionalAccess/policies")
	}
	if len(policies) != 2 {
		t.Fatalf("len(policies) = %d, want 2", len(policies))
	}
	if policies[0].State != "enabled" {
		t.Errorf("policies[0].State = %q, want %q", policies[0].State, "enabled")
	}
}

func TestSignInsByAuthenticationProtocol_HTTPTestServer_RealOAuthAndHTTPPath(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotAuthHeader string
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		if r.URL.Query().Get("$filter") == "" {
			t.Error("request is missing the $filter query parameter")
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "signin-1", "authenticationProtocol": "deviceCode", "createdDateTime": "2026-10-18T10:00:00Z",
					"appliedConditionalAccessPolicies": []map[string]any{
						{"displayName": "Block legacy authentication and device code flow", "result": "failure"},
					},
				},
				{
					"id": "signin-2", "authenticationProtocol": "ropc", "createdDateTime": "2026-10-18T10:05:00Z",
				},
			},
		})
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	events, err := client.SignInsByAuthenticationProtocol(t.Context(), "deviceCode")
	if err != nil {
		t.Fatalf("SignInsByAuthenticationProtocol() error = %v", err)
	}
	if gotAuthHeader != "Bearer tok" {
		t.Errorf("Authorization header = %q, want %q", gotAuthHeader, "Bearer tok")
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1 (the ropc record must be client-side filtered out)", len(events))
	}
	if events[0].AuthenticationProtocol != "deviceCode" {
		t.Errorf("events[0].AuthenticationProtocol = %q, want %q", events[0].AuthenticationProtocol, "deviceCode")
	}
	if len(events[0].AppliedConditionalAccessPolicies) != 1 || events[0].AppliedConditionalAccessPolicies[0].Result != "failure" {
		t.Errorf("events[0].AppliedConditionalAccessPolicies = %+v, want one entry with Result=failure", events[0].AppliedConditionalAccessPolicies)
	}
}

func TestSignInsByAuthenticationProtocol_ServerIgnoresFilter_ClientSideReFilters(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	// Simulates a tenant whose server-side $filter support for
	// authenticationProtocol is unconfirmed: it returns every
	// protocol regardless of the requested filter.
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "signin-1", "authenticationProtocol": "deviceCode", "createdDateTime": "2026-10-18T10:00:00Z"},
				{"id": "signin-2", "authenticationProtocol": "oAuth2", "createdDateTime": "2026-10-18T10:05:00Z"},
				{"id": "signin-3", "authenticationProtocol": "saml20", "createdDateTime": "2026-10-18T10:10:00Z"},
			},
		})
	}))
	defer graphSrv.Close()

	client := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*client.TokenURL() = tokenSrv.URL
	client.BaseURL = graphSrv.URL

	events, err := client.SignInsByAuthenticationProtocol(t.Context(), "deviceCode")
	if err != nil {
		t.Fatalf("SignInsByAuthenticationProtocol() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("len(events) = %d, want 1 -- the client-side re-filter must drop oAuth2/saml20 even though the server ignored $filter", len(events))
	}
}

func TestEvaluateDeviceCodeEnforcement_Blocked(t *testing.T) {
	outcome, _ := EvaluateDeviceCodeEnforcement([]SignInEvent{{
		ID: "signin-1", AuthenticationProtocol: "deviceCode",
		AppliedConditionalAccessPolicies: []AppliedConditionalAccessPolicy{{DisplayName: "Block device code", Result: "failure"}},
	}})
	if outcome != DeviceCodeBlocked {
		t.Errorf("outcome = %q, want %q", outcome, DeviceCodeBlocked)
	}
}

func TestEvaluateDeviceCodeEnforcement_Allowed_GenuineObservedNegative(t *testing.T) {
	outcome, _ := EvaluateDeviceCodeEnforcement([]SignInEvent{{
		ID: "signin-1", AuthenticationProtocol: "deviceCode",
		AppliedConditionalAccessPolicies: []AppliedConditionalAccessPolicy{{DisplayName: "Require MFA", Result: "success"}},
	}})
	if outcome != DeviceCodeAllowed {
		t.Errorf("outcome = %q, want %q", outcome, DeviceCodeAllowed)
	}
}

func TestEvaluateDeviceCodeEnforcement_NoSignIns_UnknownNeverFabricated(t *testing.T) {
	outcome, _ := EvaluateDeviceCodeEnforcement(nil)
	if outcome != DeviceCodeUnknown {
		t.Errorf("outcome = %q, want %q (absence of any observed sign-in is not proof of either outcome)", outcome, DeviceCodeUnknown)
	}
}
