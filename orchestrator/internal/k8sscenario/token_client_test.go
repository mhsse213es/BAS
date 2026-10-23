package k8sscenario

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestIssueToken_PostsTokenRequestAndReturnsTokenAndExpiry checks the TokenRequest body and path, and that the
// minted token and expiry come back to the caller.
func TestIssueToken_PostsTokenRequestAndReturnsTokenAndExpiry(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":{"token":"` + testToken + `","expirationTimestamp":"2026-10-23T12:00:00Z"}}`))
	})
	c := newTestAPIClient(t, srv)

	iss, err := c.IssueToken(context.Background(), "bas-sandbox", "bas-sbx-token-probe", 600)
	if err != nil {
		t.Fatal(err)
	}
	if string(iss.Token) != testToken || iss.Expires.IsZero() {
		t.Fatalf("issued = (%q, %v), want the token and an expiry", iss.Token, iss.Expires)
	}
	got := rec.reqs[0]
	if got.Method != http.MethodPost || got.Path != "/api/v1/namespaces/bas-sandbox/serviceaccounts/bas-sbx-token-probe/token" {
		t.Fatalf("request = %s %s, want POST to the probe ServiceAccount token subresource", got.Method, got.Path)
	}
	var body struct {
		Kind string `json:"kind"`
		Spec struct {
			Expiration int64 `json:"expirationSeconds"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(got.Body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Kind != "TokenRequest" || body.Spec.Expiration != 600 {
		t.Fatalf("body = %+v, want a TokenRequest for 600 seconds", body)
	}
}

// TestIssueToken_RefusesBadLifetimeAndNamesWithoutAnyRequest checks invalid input never reaches the API.
func TestIssueToken_RefusesBadLifetimeAndNamesWithoutAnyRequest(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) })
	c := newTestAPIClient(t, srv)
	ctx := context.Background()
	if _, err := c.IssueToken(ctx, "bas-sandbox", "bas-sbx-token-probe", 30); err == nil {
		t.Fatal("a lifetime below the minimum must be refused")
	}
	if _, err := c.IssueToken(ctx, "bas-sandbox", "bas-sbx-token-probe", 99999); err == nil {
		t.Fatal("a lifetime above the maximum must be refused")
	}
	if _, err := c.IssueToken(ctx, "Bad_Namespace", "bas-sbx-token-probe", 600); err == nil {
		t.Fatal("an invalid namespace name must be refused")
	}
	if rec.count() != 0 {
		t.Fatalf("%d requests were sent for invalid input", rec.count())
	}
}

// TestIssueToken_ErrorNeverContainsTheToken checks a refused request does not echo the credential into the error.
func TestIssueToken_ErrorNeverContainsTheToken(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"` + testToken + `"}`))
	})
	c := newTestAPIClient(t, srv)
	_, err := c.IssueToken(context.Background(), "bas-sandbox", "bas-sbx-token-probe", 600)
	if err == nil {
		t.Fatal("a 403 must be an error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Fatal("the error must not contain the token")
	}
}

// TestIdentityWithToken_ReturnsTheAuthenticatedUsername checks the identity call returns the username the server
// reports for the token.
func TestIdentityWithToken_ReturnsTheAuthenticatedUsername(t *testing.T) {
	rec := &recorder{}
	srv := newAPIServer(t, rec, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":{"userInfo":{"username":"system:serviceaccount:bas-sandbox:bas-sbx-token-probe"}}}`))
	})
	c := newTestAPIClient(t, srv)
	id, err := c.IdentityWithToken(context.Background(), []byte(testToken))
	if err != nil {
		t.Fatal(err)
	}
	if id != "system:serviceaccount:bas-sandbox:bas-sbx-token-probe" {
		t.Fatalf("identity = %q", id)
	}
	if rec.reqs[0].Path != "/apis/authentication.k8s.io/v1/selfsubjectreviews" {
		t.Fatalf("path = %s, want the SelfSubjectReview endpoint", rec.reqs[0].Path)
	}
}
