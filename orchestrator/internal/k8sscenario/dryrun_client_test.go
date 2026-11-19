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

// dryRunAPI answers the namespace, pod dry-run and webhook endpoints. It records every method it receives so tests
// can assert that no write was sent.
type dryRunAPI struct {
	token      string
	level      string
	podStatus  int
	podMessage string
	methods    []string
	dryRunSeen bool
	podBody    map[string]any
}

func (d *dryRunAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.methods = append(d.methods, r.Method)
	if r.Header.Get("Authorization") != "Bearer "+d.token {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/") && r.URL.Path != "/api/v1/namespaces/lab-ns":
		http.NotFound(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/lab-ns":
		_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{
			"name": "lab-ns", "labels": map[string]string{PSAEnforceLabel: d.level}}})
	case r.Method == http.MethodPost && r.URL.Path == "/api/v1/namespaces/lab-ns/pods":
		d.dryRunSeen = r.URL.Query().Get("dryRun") == "All"
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &d.podBody)
		if d.podStatus == http.StatusCreated {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"kind":"Pod"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(d.podStatus)
		_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "reason": "Forbidden", "message": d.podMessage})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/apis/admissionregistration.k8s.io/v1/"):
		items := []any{}
		if strings.Contains(r.URL.Path, "validating") {
			items = append(items, map[string]any{"webhooks": []any{map[string]any{"sideEffects": "NoneOnDryRun"}}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
	default:
		http.Error(w, "not routed in this test", http.StatusTeapot)
	}
}

func dryRunServer(t *testing.T, api *dryRunAPI) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	return srv
}

func TestDryRunClient_ReadsLevelDryRunsAndNeverWrites(t *testing.T) {
	api := &dryRunAPI{token: "tok", level: "restricted", podStatus: http.StatusForbidden,
		podMessage: `pods "x" is forbidden: violates PodSecurity "restricted:latest"`}
	srv := dryRunServer(t, api)
	c, err := NewDryRunClient(srv.URL, "tok", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if err != nil {
		t.Fatal(err)
	}
	level, found, err := c.NamespacePSALevel(context.Background(), "lab-ns")
	if err != nil || !found || level != "restricted" {
		t.Fatalf("level: %q %v %v", level, found, err)
	}
	dr, err := c.DryRunPod(context.Background(), "lab-ns", map[string]any{"kind": "Pod"})
	if err != nil {
		t.Fatal(err)
	}
	if dr.Allowed || dr.StatusCode != http.StatusForbidden || !strings.Contains(dr.Message, "violates PodSecurity") {
		t.Errorf("refusal misread: %+v", dr)
	}
	if !api.dryRunSeen {
		t.Error("the pod create must carry dryRun=All")
	}
	for _, m := range api.methods {
		if m != http.MethodGet && m != http.MethodPost {
			t.Errorf("unexpected method %s", m)
		}
	}
	if _, err := c.WebhookSideEffects(context.Background()); err != nil {
		t.Errorf("webhook list: %v", err)
	}
}

func TestDryRunClient_AllowedAnd404(t *testing.T) {
	api := &dryRunAPI{token: "tok", level: "restricted", podStatus: http.StatusCreated}
	srv := dryRunServer(t, api)
	c, _ := NewDryRunClient(srv.URL, "tok", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	dr, err := c.DryRunPod(context.Background(), "lab-ns", map[string]any{})
	if err != nil || !dr.Allowed {
		t.Errorf("a 201 dry-run must be allowed: %+v %v", dr, err)
	}
	if _, found, err := c.NamespacePSALevel(context.Background(), "missing-ns"); err != nil || found {
		t.Errorf("a missing namespace must be found=false without error: %v %v", found, err)
	}
}

func TestDryRunClient_RefusedCredentialIsAnError(t *testing.T) {
	api := &dryRunAPI{token: "tok", level: "restricted"}
	srv := dryRunServer(t, api)
	c, _ := NewDryRunClient(srv.URL, "wrong", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	if _, err := c.DryRunPod(context.Background(), "lab-ns", map[string]any{}); err == nil {
		t.Error("a 401 must be an error, not a refusal")
	}
}

func TestDryRunClient_RefusesWhatItShouldNot(t *testing.T) {
	if _, err := NewDryRunClient("http://plain.example", "tok", nil); err == nil {
		t.Error("plain http must be refused")
	}
	if _, err := NewDryRunClient("https://a.example", " ", nil); err == nil {
		t.Error("an empty token must be refused")
	}
}
