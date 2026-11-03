package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/controlval"
	"github.com/audspect/bas/internal/k8sscenario"
)

// admissionServer answers the namespace read, the pod dry-run and the webhook list for one namespace level.
func admissionServer(t *testing.T, token, level string, podStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/lab-ns":
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{
				"labels": map[string]string{k8sscenario.PSAEnforceLabel: level}}})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pods"):
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(podStatus)
			_ = json.NewEncoder(w).Encode(map[string]any{"kind": "Status", "message": `violates PodSecurity "restricted:latest"`})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/apis/admissionregistration.k8s.io/v1/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
		default:
			http.NotFound(w, r)
		}
	}))
}

func admissionHandler(srv *httptest.Server, class, token string) *Handler {
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: class},
	}}
	return &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
		Credentials: func(string) (string, []byte, error) { return token, pemOf(srv), nil }}}
}

func runAdmission(t *testing.T, h *Handler, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/admission-checks/run", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.RunK8sAdmissionCheck(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestRunK8sAdmissionCheck_RefusedIsBlockedAndPasses(t *testing.T) {
	srv := admissionServer(t, "tok", "restricted", http.StatusForbidden)
	defer srv.Close()
	code, out := runAdmission(t, admissionHandler(srv, k8sscenario.ClassLab, "tok"),
		`{"clusterId":"k8sc-1","checkId":"privileged-pod-restricted-namespace","namespace":"lab-ns"}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", code, out)
	}
	res := out["result"].(map[string]any)
	if res["outcome"] != string(controlval.OutcomeBlocked) || res["verdict"] != string(controlval.VerdictPass) {
		t.Errorf("want blocked/PASS, got %v/%v", res["outcome"], res["verdict"])
	}
}

func TestRunK8sAdmissionCheck_NotApplicableIsSkippedWithStatus200(t *testing.T) {
	srv := admissionServer(t, "tok", "baseline", http.StatusForbidden)
	defer srv.Close()
	code, out := runAdmission(t, admissionHandler(srv, k8sscenario.ClassLab, "tok"),
		`{"clusterId":"k8sc-1","checkId":"privileged-pod-restricted-namespace","namespace":"lab-ns"}`)
	if code != http.StatusOK {
		t.Fatalf("a skip is a result, not an error: got %d %v", code, out)
	}
	if out["result"].(map[string]any)["verdict"] != string(controlval.VerdictSkipped) {
		t.Errorf("want SKIPPED, got %v", out["result"])
	}
}

func TestRunK8sAdmissionCheck_Refusals(t *testing.T) {
	srv := admissionServer(t, "tok", "restricted", http.StatusForbidden)
	defer srv.Close()
	h := admissionHandler(srv, k8sscenario.ClassLab, "tok")
	cases := []struct {
		name string
		body string
		want int
	}{
		{"unknown check", `{"clusterId":"k8sc-1","checkId":"nope","namespace":"lab-ns"}`, http.StatusBadRequest},
		{"bad namespace name", `{"clusterId":"k8sc-1","checkId":"privileged-pod-restricted-namespace","namespace":"Lab_NS/../x"}`, http.StatusBadRequest},
		{"empty namespace", `{"clusterId":"k8sc-1","checkId":"privileged-pod-restricted-namespace","namespace":""}`, http.StatusBadRequest},
		{"unknown cluster", `{"clusterId":"nope","checkId":"privileged-pod-restricted-namespace","namespace":"lab-ns"}`, http.StatusNotFound},
		{"unknown field", `{"clusterId":"k8sc-1","checkId":"privileged-pod-restricted-namespace","namespace":"lab-ns","x":1}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		if code, out := runAdmission(t, h, c.body); code != c.want {
			t.Errorf("%s: want %d, got %d: %v", c.name, c.want, code, out)
		}
	}
}

func TestRunK8sAdmissionCheck_RejectedCredentialIs502(t *testing.T) {
	srv := admissionServer(t, "tok", "restricted", http.StatusForbidden)
	defer srv.Close()
	code, _ := runAdmission(t, admissionHandler(srv, k8sscenario.ClassLab, "wrong"),
		`{"clusterId":"k8sc-1","checkId":"privileged-pod-restricted-namespace","namespace":"lab-ns"}`)
	if code != http.StatusBadGateway {
		t.Errorf("a rejected credential must be a 502, got %d", code)
	}
}
