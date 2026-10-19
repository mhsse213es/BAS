package phishidentity

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const scopeClientA = "11111111-2222-4333-8444-555555555555"
const scopeClientB = "66666666-7777-4888-8999-aaaaaaaaaaaa"

// scopedServer records every request URL the client makes.
func scopedServer(t *testing.T, body map[string]any) (*httptest.Server, *[]string) {
	t.Helper()
	var urls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urls = append(urls, r.URL.String())
		json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	return srv, &urls
}

func newScopedClient(t *testing.T, graphURL string) *Client {
	t.Helper()
	tokenSrv := tokenMock(t)
	t.Cleanup(tokenSrv.Close)
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenSrv.URL
	c.BaseURL = graphURL
	return c
}

// The grant listing is narrowed inside Graph's own query, one clause per client.
func TestListOAuthConsentGrantsForClients_FilterNarrowsInGraphQuery(t *testing.T) {
	srv, urls := scopedServer(t, map[string]any{"value": []map[string]any{}})
	c := newScopedClient(t, srv.URL)
	if _, err := c.ListOAuthConsentGrantsForClients(t.Context(), []string{scopeClientA, scopeClientB}); err != nil {
		t.Fatalf("ListOAuthConsentGrantsForClients: %v", err)
	}
	if len(*urls) != 1 {
		t.Fatalf("requests = %d, want exactly 1", len(*urls))
	}
	filter, err := url.Parse((*urls)[0])
	if err != nil {
		t.Fatalf("parse request URL: %v", err)
	}
	got := filter.Query().Get("$filter")
	for _, id := range []string{scopeClientA, scopeClientB} {
		if !strings.Contains(got, "clientId eq '"+id+"'") {
			t.Errorf("$filter = %q, want a clientId clause for %s", got, id)
		}
	}
}

// An empty list must make no request at all. It can never become a tenant-wide listing.
func TestListOAuthConsentGrantsForClients_EmptyRefusedWithZeroRequests(t *testing.T) {
	srv, urls := scopedServer(t, map[string]any{"value": []map[string]any{}})
	c := newScopedClient(t, srv.URL)
	if _, err := c.ListOAuthConsentGrantsForClients(t.Context(), nil); err == nil {
		t.Fatal("empty client list was accepted; it must be refused")
	}
	if len(*urls) != 0 {
		t.Errorf("empty client list made %d request(s); want 0", len(*urls))
	}
}

// A malformed client ID must not reach the OData filter.
func TestListOAuthConsentGrantsForClients_MalformedRefusedWithZeroRequests(t *testing.T) {
	srv, urls := scopedServer(t, map[string]any{"value": []map[string]any{}})
	c := newScopedClient(t, srv.URL)
	if _, err := c.ListOAuthConsentGrantsForClients(t.Context(), []string{"x' or clientId ne 'y"}); err == nil {
		t.Fatal("malformed client ID was accepted")
	}
	if len(*urls) != 0 {
		t.Errorf("malformed client ID made %d request(s); want 0", len(*urls))
	}
}

// Sign-ins are queried one user at a time, each with its own userId clause, and
// the protocol is re-checked on every record that comes back.
func TestSignInsForUsersByProtocol_OneScopedQueryPerUser(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{
			{"id": "s-" + r.URL.Query().Get("$filter"), "authenticationProtocol": "deviceCode", "createdDateTime": "2026-10-18T10:00:00Z"},
		}})
	}))
	defer srv.Close()
	c := newScopedClient(t, srv.URL)

	events, err := c.SignInsForUsersByProtocol(t.Context(), "deviceCode", []string{"alice@contoso.example", "bob@contoso.example"})
	if err != nil {
		t.Fatalf("SignInsForUsersByProtocol: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("requests = %d, want one per user (2)", calls.Load())
	}
	if len(events) != 2 {
		t.Errorf("events = %d, want 2", len(events))
	}
}

func TestSignInsForUsersByProtocol_EmptyRefusedWithZeroRequests(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()
	c := newScopedClient(t, srv.URL)
	if _, err := c.SignInsForUsersByProtocol(t.Context(), "deviceCode", nil); err == nil {
		t.Fatal("empty user list was accepted; it must be refused")
	}
	if calls.Load() != 0 {
		t.Errorf("empty user list made %d request(s); want 0", calls.Load())
	}
}
