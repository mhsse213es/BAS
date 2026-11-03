package k8sscenario

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sarServer answers SubjectAccessReview and records the request it received.
func sarServer(t *testing.T, wantToken string, allowed bool, status int) (*httptest.Server, *map[string]any, *string) {
	t.Helper()
	var got map[string]any
	var path string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if r.Header.Get("Authorization") != "Bearer "+wantToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		if status != http.StatusCreated && status != http.StatusOK {
			http.Error(w, "boom", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":{"allowed":` + boolText(allowed) + `,"denied":` + boolText(!allowed) + `,"reason":"test"}}`))
	}))
	return srv, &got, &path
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func pemForServer(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestSARClient_SendsOnlyAReviewAndReadsTheDecision(t *testing.T) {
	srv, got, path := sarServer(t, "tok", false, http.StatusCreated)
	defer srv.Close()
	c, err := NewSARClient(srv.URL, "tok", pemForServer(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Review(context.Background(), SARSpec{User: "system:serviceaccount:bas-probe:probe",
		Verb: "impersonate", Resource: "serviceaccounts"})
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}
	if res.Allowed || !res.Denied || res.Reason != "test" {
		t.Errorf("decision misread: %+v", res)
	}
	if *path != sarPath {
		t.Errorf("wrong endpoint: %s", *path)
	}
	spec := (*got)["spec"].(map[string]any)
	attrs := spec["resourceAttributes"].(map[string]any)
	if spec["user"] != "system:serviceaccount:bas-probe:probe" || attrs["verb"] != "impersonate" ||
		attrs["resource"] != "serviceaccounts" || (*got)["kind"] != "SubjectAccessReview" {
		t.Errorf("request body wrong: %v", *got)
	}
}

func TestSARClient_RefusesWhatItShouldNot(t *testing.T) {
	if _, err := NewSARClient("http://plain.example", "tok", nil); err == nil {
		t.Error("plain http must be refused")
	}
	if _, err := NewSARClient("https://a.example", "  ", nil); err == nil {
		t.Error("an empty token must be refused")
	}
}

func TestSARClient_CredentialWithoutReviewRightsIsAnError(t *testing.T) {
	srv, _, _ := sarServer(t, "tok", false, http.StatusCreated)
	defer srv.Close()
	c, err := NewSARClient(srv.URL, "wrong", pemForServer(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Review(context.Background(), SARSpec{User: "u", Verb: "get", Resource: "pods"}); err == nil ||
		!strings.Contains(err.Error(), "cannot create reviews") {
		t.Errorf("a refused credential must be an error, got %v", err)
	}
}
