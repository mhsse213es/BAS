package cloudgraph

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// preflightARM answers ARM probes with the given subscription and RBAC codes.
func preflightARM(subCode, rbacCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/providers/Microsoft.Authorization/roleAssignments"),
			strings.Contains(r.URL.Path, "/providers/Microsoft.Authorization/denyAssignments"):
			w.WriteHeader(rbacCode)
			io.WriteString(w, `{}`)
		case strings.HasPrefix(r.URL.Path, "/subscriptions/"):
			w.WriteHeader(subCode)
			io.WriteString(w, `{}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// preflightGraph answers Graph probes with the given codes for users and service principals.
func preflightGraph(usersCode, spCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/users"):
			w.WriteHeader(usersCode)
			io.WriteString(w, `{}`)
		case strings.HasPrefix(r.URL.Path, "/servicePrincipals"):
			w.WriteHeader(spCode)
			io.WriteString(w, `{}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func checkByName(checks []PreflightCheck, name string) PreflightCheck {
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	return PreflightCheck{}
}

func TestAzurePreflight_AllGapsClosedPasses(t *testing.T) {
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := preflightARM(http.StatusOK, http.StatusOK)
	defer arm.Close()
	graph := preflightGraph(http.StatusOK, http.StatusOK)
	defer graph.Close()

	client := newTestAzureDiscoveryClient(t, tok.URL, graph.URL, arm.URL)
	checks := client.Preflight(context.Background())
	for _, c := range checks {
		if c.Status != "PASS" {
			t.Errorf("%s = %s (%s), want PASS", c.Name, c.Status, c.Detail)
		}
	}
	if len(checks) != 7 {
		t.Errorf("checks = %d, want 7", len(checks))
	}
}

func TestAzurePreflight_MissingSubscriptionNamedAsCause(t *testing.T) {
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := preflightARM(http.StatusNotFound, http.StatusNotFound)
	defer arm.Close()
	graph := preflightGraph(http.StatusOK, http.StatusOK)
	defer graph.Close()

	client := newTestAzureDiscoveryClient(t, tok.URL, graph.URL, arm.URL)
	checks := client.Preflight(context.Background())
	sub := checkByName(checks, "subscription-visible")
	if sub.Status != "FAIL" || !strings.Contains(sub.Detail, "not visible") {
		t.Errorf("subscription-visible = %+v, want FAIL naming the missing subscription", sub)
	}
	if checkByName(checks, "graph-users-readable").Status != "PASS" {
		t.Error("an ARM gap must not mark the independent Graph checks as failed")
	}
}

func TestAzurePreflight_MissingAdminConsentNamedAsCause(t *testing.T) {
	tok := azureTokenMock(t)
	defer tok.Close()
	arm := preflightARM(http.StatusOK, http.StatusOK)
	defer arm.Close()
	graph := preflightGraph(http.StatusForbidden, http.StatusForbidden)
	defer graph.Close()

	client := newTestAzureDiscoveryClient(t, tok.URL, graph.URL, arm.URL)
	checks := client.Preflight(context.Background())
	users := checkByName(checks, "graph-users-readable")
	if users.Status != "FAIL" || !strings.Contains(users.Detail, "admin consent") {
		t.Errorf("graph-users-readable = %+v, want FAIL naming admin consent", users)
	}
	sps := checkByName(checks, "graph-service-principals-readable")
	if sps.Status != "FAIL" || !strings.Contains(sps.Detail, "Application.Read.All") {
		t.Errorf("graph-service-principals-readable = %+v", sps)
	}
}

func TestAzurePreflight_TokenFailureSkipsDependentChecks(t *testing.T) {
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_client","error_description":"bad secret s1"}`)
	}))
	defer tok.Close()
	arm := preflightARM(http.StatusOK, http.StatusOK)
	defer arm.Close()
	graph := preflightGraph(http.StatusOK, http.StatusOK)
	defer graph.Close()

	client := newTestAzureDiscoveryClient(t, tok.URL, graph.URL, arm.URL)
	checks := client.Preflight(context.Background())
	if c := checkByName(checks, "token-graph"); c.Status != "FAIL" {
		t.Errorf("token-graph = %+v, want FAIL", c)
	}
	if c := checkByName(checks, "graph-users-readable"); c.Status != "SKIPPED" {
		t.Errorf("graph-users-readable = %s, want SKIPPED when the Graph token did not issue", c.Status)
	}
	for _, c := range checks {
		if strings.Contains(c.Detail, "s1") && !strings.Contains(c.Detail, "[REDACTED]") {
			t.Errorf("%s: client secret appeared unredacted in %q", c.Name, c.Detail)
		}
	}
}
