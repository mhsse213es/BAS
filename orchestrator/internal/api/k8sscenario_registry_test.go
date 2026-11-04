package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/k8sscenario"
)

// createRun posts to the run endpoint. The engine is a zero value and is never reached in these tests: every case
// is refused before the engine runs.
func createRun(t *testing.T, h *Handler, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/k8s-scenarios/runs", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.CreateK8sRun(rec, req)
	return rec.Code, rec.Body.String()
}

func runHandler(audit *recordingAudit) *Handler {
	reg := &fakeClusterRegistry{clusters: []k8sscenario.ClusterRecord{
		{ID: "k8sc-lab", DisplayName: "kind-bas-lab", ServerURL: "https://127.0.0.1:61567", Class: k8sscenario.ClassLab},
		{ID: "k8sc-prod", DisplayName: "prod-east", ServerURL: "https://prod.example:6443", Class: k8sscenario.ClassProduction},
	}}
	return &Handler{k8sScenario: &K8sScenarioService{Engine: &k8sscenario.Engine{}, Registry: reg, Audit: audit,
		Clusters: map[string]string{"kind-bas-lab": "https://127.0.0.1:61567"}, Namespaces: []string{"bas-sandbox"}}}
}

func TestCreateK8sRun_DisplayNameIsRejected(t *testing.T) {
	code, body := createRun(t, runHandler(&recordingAudit{}),
		`{"cluster":"kind-bas-lab","namespace":"bas-sandbox","action":"configmap-patch-labelled","params":{}}`)
	if code != http.StatusBadRequest || !strings.Contains(body, "clusterId is required") {
		t.Errorf("a name-based run must be refused: %d %s", code, body)
	}
}

func TestCreateK8sRun_UnknownRegistryIDIsRejected(t *testing.T) {
	code, _ := createRun(t, runHandler(&recordingAudit{}),
		`{"clusterId":"k8sc-missing","namespace":"bas-sandbox","action":"configmap-patch-labelled","params":{}}`)
	if code != http.StatusBadRequest {
		t.Errorf("an unknown registry ID must be refused: %d", code)
	}
}

func TestCreateK8sRun_ProductionEntryIsRefusedForLabExecution(t *testing.T) {
	audit := &recordingAudit{}
	code, _ := createRun(t, runHandler(audit),
		`{"clusterId":"k8sc-prod","namespace":"bas-sandbox","action":"configmap-patch-labelled","params":{}}`)
	if code != http.StatusForbidden {
		t.Errorf("a production-class cluster must be refused for lab execution: %d", code)
	}
		if len(audit.events) != 1 || audit.events[0].Fields["profile"] != "lab" {
		t.Errorf("the refusal must be audited: %+v", audit.events)
	}
}
