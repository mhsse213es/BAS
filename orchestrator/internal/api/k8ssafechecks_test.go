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

// reviewServer answers SubjectAccessReview. It allows the reviews for resources in allowResources, and denies the rest.
func reviewServer(t *testing.T, token string, allowResources ...string) *httptest.Server {
	t.Helper()
	allow := map[string]bool{}
	for _, r := range allowResources {
		allow[r] = true
	}
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authorization.k8s.io/v1/subjectaccessreviews" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Spec struct {
				ResourceAttributes struct {
					Resource string `json:"resource"`
				} `json:"resourceAttributes"`
			} `json:"spec"`
		}
		_ = json.Unmarshal(raw, &body)
		allowed := allow[body.Spec.ResourceAttributes.Resource]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"allowed": allowed, "denied": !allowed}})
	}))
}

func safeCheckHandler(srv *httptest.Server, class string, token string) *Handler {
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-1", DisplayName: "lab-east", ServerURL: srv.URL, Class: class},
	}}
	return &Handler{k8sScenario: &K8sScenarioService{Registry: reg,
		Credentials: func(string) (string, []byte, error) { return token, pemOf(srv), nil }}}
}

func runSafeCheck(t *testing.T, h *Handler, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/safe-checks/run", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.RunK8sSafeCheck(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestRunK8sSafeCheck_DeniedIsBlockedAndPasses(t *testing.T) {
	srv := reviewServer(t, "tok")
	defer srv.Close()
	h := safeCheckHandler(srv, k8sscenario.ClassLab, "tok")
	code, out := runSafeCheck(t, h,
		`{"clusterId":"k8sc-1","checkId":"impersonate-serviceaccounts","subject":"system:serviceaccount:bas-probe:probe"}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", code, out)
	}
	res := out["result"].(map[string]any)
	if res["outcome"] != string(controlval.OutcomeBlocked) || res["verdict"] != string(controlval.VerdictPass) {
		t.Errorf("want blocked/PASS, got %v/%v", res["outcome"], res["verdict"])
	}
}

func TestRunK8sSafeCheck_AllowedIsFail(t *testing.T) {
	srv := reviewServer(t, "tok", "rolebindings")
	defer srv.Close()
	h := safeCheckHandler(srv, k8sscenario.ClassNonProduction, "tok")
	code, out := runSafeCheck(t, h,
		`{"clusterId":"k8sc-1","checkId":"rolebinding-create-foreign-namespace","subject":"alice"}`)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %v", code, out)
	}
	res := out["result"].(map[string]any)
	if res["outcome"] != string(controlval.OutcomeAllowed) || res["verdict"] != string(controlval.VerdictFail) {
		t.Errorf("want allowed/FAIL, got %v/%v", res["outcome"], res["verdict"])
	}
}

func TestRunK8sSafeCheck_ProductionAllowsSafe(t *testing.T) {
	srv := reviewServer(t, "tok")
	defer srv.Close()
	h := safeCheckHandler(srv, k8sscenario.ClassProduction, "tok")
	if code, out := runSafeCheck(t, h,
		`{"clusterId":"k8sc-1","checkId":"impersonate-serviceaccounts","subject":"alice"}`); code != http.StatusOK {
		t.Errorf("production must allow Safe checks: got %d %v", code, out)
	}
}

func TestRunK8sSafeCheck_Refusals(t *testing.T) {
	srv := reviewServer(t, "tok")
	defer srv.Close()
	good := safeCheckHandler(srv, k8sscenario.ClassLab, "tok")
	badCred := safeCheckHandler(srv, k8sscenario.ClassLab, "wrong")
	noCred := &Handler{k8sScenario: &K8sScenarioService{Registry: good.k8sScenario.Registry,
		Credentials: func(string) (string, []byte, error) { return "", nil, ErrK8sClusterNoCredential }}}
	cases := []struct {
		name string
		h    *Handler
		body string
		want int
	}{
		{"unknown check", good, `{"clusterId":"k8sc-1","checkId":"delete-everything","subject":"alice"}`, http.StatusBadRequest},
		{"empty subject", good, `{"clusterId":"k8sc-1","checkId":"impersonate-serviceaccounts","subject":" "}`, http.StatusBadRequest},
		{"unknown cluster", good, `{"clusterId":"nope","checkId":"impersonate-serviceaccounts","subject":"alice"}`, http.StatusNotFound},
		{"no credential", noCred, `{"clusterId":"k8sc-1","checkId":"impersonate-serviceaccounts","subject":"alice"}`, http.StatusConflict},
		{"credential cannot create reviews", badCred, `{"clusterId":"k8sc-1","checkId":"impersonate-serviceaccounts","subject":"alice"}`, http.StatusBadGateway},
		{"unknown field", good, `{"clusterId":"k8sc-1","checkId":"impersonate-serviceaccounts","subject":"alice","x":1}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		if code, out := runSafeCheck(t, c.h, c.body); code != c.want {
			t.Errorf("%s: want %d, got %d: %v", c.name, c.want, code, out)
		}
	}
}

func TestProfileAllowed(t *testing.T) {
	if !profileAllowed(k8sscenario.ClassProduction, "safe") {
		t.Error("production must allow safe")
	}
	if profileAllowed(k8sscenario.ClassProduction, "lab") {
		t.Error("production must not allow the lab profile")
	}
	if profileAllowed("unknown-class", "safe") {
		t.Error("an unknown class must allow nothing")
	}
}
