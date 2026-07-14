package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/audspect/bas/internal/rulelib"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

func rulelibTestHandler(t *testing.T) *Handler {
	t.Helper()
	h := New(nil, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
	return h.WithRuleLibrary(rulelib.NewEngine())
}

func TestListRules_ReturnsEmbeddedBundle(t *testing.T) {
	h := rulelibTestHandler(t)
	rec := httptest.NewRecorder()
	h.ListRules(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected at least one rule from the embedded bundle")
	}
}

func TestGetRule_FoundAndNotFound(t *testing.T) {
	h := rulelibTestHandler(t)
	listRec := httptest.NewRecorder()
	h.ListRules(listRec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	var list []map[string]any
	json.Unmarshal(listRec.Body.Bytes(), &list)
	firstID := list[0]["id"].(string)

	rec := httptest.NewRecorder()
	h.GetRule(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", firstID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	notFoundRec := httptest.NewRecorder()
	h.GetRule(notFoundRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "AUDRULE-999999"))
	if notFoundRec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for an unknown rule id", notFoundRec.Code)
	}
}

func TestSearchRules_FiltersByQueryParams(t *testing.T) {
	h := rulelibTestHandler(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules/search?backend=splunk", nil)
	h.SearchRules(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	for _, r := range out {
		translations := r["translations"].([]any)
		found := false
		for _, tr := range translations {
			if tr.(map[string]any)["backend"] == "splunk" {
				found = true
			}
		}
		if !found {
			t.Fatalf("result %v has no splunk translation despite backend=splunk filter", r["id"])
		}
	}
}

func TestRulesByTechnique_UnknownTechniqueReturnsEmptyList(t *testing.T) {
	h := rulelibTestHandler(t)
	rec := httptest.NewRecorder()
	h.RulesByTechnique(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "T9999.999"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var out []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 0 {
		t.Fatalf("expected an empty list for an unknown technique, got %d", len(out))
	}
}

func TestExportRule_ReturnsRequestedFormat(t *testing.T) {
	h := rulelibTestHandler(t)
	listRec := httptest.NewRecorder()
	h.ListRules(listRec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
	var list []map[string]any
	json.Unmarshal(listRec.Body.Bytes(), &list)
	firstID := list[0]["id"].(string)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/rules/export?id="+firstID+"&format=sigma", nil)
	h.ExportRule(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/plain", rec.Header().Get("Content-Type"))
	}

	badRec := httptest.NewRecorder()
	badReq := httptest.NewRequest(http.MethodGet, "/api/rules/export?id="+firstID+"&format=cobol", nil)
	h.ExportRule(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unsupported format", badRec.Code)
	}
}
