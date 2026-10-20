package cloudgraph

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/api/option"
)

// gcpForced makes every request whose path contains needle return status.
type gcpForced struct {
	needle string
	status int
}

// gcpPreflightClient serves routes, except that requests matching forced get the
// forced status. A nil forced serves routes unchanged.
func gcpPreflightClient(t *testing.T, routes []gcpRoute, forced *gcpForced) *GCPDiscoveryClient {
	t.Helper()
	api := &gcpFakeAPI{routes: routes}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if forced != nil && strings.Contains(r.URL.Path, forced.needle) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(forced.status)
			io.WriteString(w, `{"error":{"code":`+strconv.Itoa(forced.status)+`,"message":"denied by test"}}`)
			return
		}
		api.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	client, err := NewGCPDiscoveryClient(context.Background(), gcpProject,
		option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("NewGCPDiscoveryClient: %v", err)
	}
	return client
}

func gcpCheckNamed(t *testing.T, checks []PreflightCheck, name string) PreflightCheck {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in %+v", name, checks)
	return PreflightCheck{}
}

func TestGCPPreflight_AllPassIncludingAncestors(t *testing.T) {
	client := gcpPreflightClient(t, hierarchyRoutes(gcpAncestryFolderOrg), nil)
	checks := client.Preflight(context.Background())

	for _, c := range checks {
		if c.Status != "PASS" {
			t.Errorf("%s = %s (%s), want PASS", c.Name, c.Status, c.Detail)
		}
	}
	ancestorChecks := 0
	for _, c := range checks {
		if strings.HasPrefix(c.Name, "ancestor-iam-readable:") {
			ancestorChecks++
		}
	}
	if ancestorChecks != 2 {
		t.Errorf("ancestor checks = %d, want 2 (folder and organization)", ancestorChecks)
	}
}

// A forbidden deny-policy read is named, and the checks after it still run.
func TestGCPPreflight_DenyForbiddenIsNamedAndOthersRun(t *testing.T) {
	client := gcpPreflightClient(t, gcpStandardRoutes(), &gcpForced{needle: "denypolicies", status: http.StatusForbidden})
	checks := client.Preflight(context.Background())

	deny := gcpCheckNamed(t, checks, "deny-policies-readable")
	if deny.Status != "FAIL" || !strings.Contains(deny.Detail, "iam.denypolicies.list") || !strings.Contains(deny.Detail, "HTTP 403") {
		t.Errorf("deny check = %+v, want FAIL naming iam.denypolicies.list with HTTP 403", deny)
	}
	if got := gcpCheckNamed(t, checks, "buckets-readable"); got.Status != "PASS" {
		t.Errorf("buckets check after a deny failure = %+v, want PASS", got)
	}
	if got := gcpCheckNamed(t, checks, "service-accounts-readable"); got.Status != "PASS" {
		t.Errorf("service-accounts check after a deny failure = %+v, want PASS", got)
	}
}

// Without ancestry the project's ancestors are unknown, so their checks are
// SKIPPED. The project's own IAM read still runs.
func TestGCPPreflight_AncestryForbiddenSkipsAncestors(t *testing.T) {
	client := gcpPreflightClient(t, hierarchyRoutes(gcpAncestryFolderOrg), &gcpForced{needle: ":getAncestry", status: http.StatusForbidden})
	checks := client.Preflight(context.Background())

	anc := gcpCheckNamed(t, checks, "project-ancestry-readable")
	if anc.Status != "FAIL" || !strings.Contains(anc.Detail, "resourcemanager.projects.get") {
		t.Errorf("ancestry check = %+v, want FAIL naming resourcemanager.projects.get", anc)
	}
	if got := gcpCheckNamed(t, checks, "ancestor-iam-readable"); got.Status != "SKIPPED" {
		t.Errorf("ancestor check without ancestry = %+v, want SKIPPED", got)
	}
	for _, c := range checks {
		if strings.HasPrefix(c.Name, "ancestor-iam-readable:") {
			t.Errorf("ancestor %s was checked although ancestry failed", c.Name)
		}
	}
	if got := gcpCheckNamed(t, checks, "project-iam-readable"); got.Status != "PASS" {
		t.Errorf("project IAM check = %+v, want PASS", got)
	}
}

// An ancestor the principal cannot read is named by its own canonical id.
func TestGCPPreflight_ForbiddenFolderIsNamed(t *testing.T) {
	client := gcpPreflightClient(t, hierarchyRoutes(gcpAncestryFolderOrg), &gcpForced{needle: "/folders/111:getIamPolicy", status: http.StatusForbidden})
	checks := client.Preflight(context.Background())

	got := gcpCheckNamed(t, checks, "ancestor-iam-readable:folders/111")
	if got.Status != "FAIL" || !strings.Contains(got.Detail, "folders/111") {
		t.Errorf("folder check = %+v, want FAIL naming folders/111", got)
	}
	if org := gcpCheckNamed(t, checks, "ancestor-iam-readable:organizations/222"); org.Status != "PASS" {
		t.Errorf("organization check = %+v, want PASS", org)
	}
}

// A status that is not a permission gap is reported with its code, not as a
// permission message.
func TestGCPPreflight_UnexpectedStatusReportedWithCode(t *testing.T) {
	client := gcpPreflightClient(t, gcpStandardRoutes(), &gcpForced{needle: "/b", status: http.StatusBadRequest})
	got := gcpCheckNamed(t, client.Preflight(context.Background()), "buckets-readable")
	if got.Status != "FAIL" || !strings.Contains(got.Detail, "unexpected HTTP 400") {
		t.Errorf("buckets check = %+v, want FAIL with unexpected HTTP 400", got)
	}
}
