package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

const importSigma = `
title: Certutil Download
id: 11111111-2222-3333-4444-555555555555
tags: [attack.t1105]
logsource: {product: windows, category: process_creation}
detection:
  selection:
    CommandLine|contains|all: ['urlcache', '-split']
  condition: selection
`

const importSigmaNotEmulable = `
title: Needs a parent
tags: [attack.t1059]
logsource: {product: windows, category: process_creation}
detection:
  selection: {ParentImage|endswith: '\winword.exe', CommandLine|contains: cmd}
  condition: selection
`

type importResp struct {
	Results []struct {
		Title     string `json:"title"`
		Emulable  bool   `json:"emulable"`
		DraftID   string `json:"draftId"`
		Duplicate bool   `json:"duplicate"`
		Error     string `json:"error"`
		Coverage  struct {
			NotEmulated []string `json:"notEmulated"`
		} `json:"coverage"`
	} `json:"results"`
}

func postImportJSON(t *testing.T, fn http.HandlerFunc, path string, body any, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	if params != nil {
		req = withURLParams(req, params)
	}
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func importOne(t *testing.T, h *Handler, source string) importResp {
	t.Helper()
	rec := postImportJSON(t, h.ImportSigma, "/api/content-import/sigma", map[string]string{"source": source}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("import: %d %s", rec.Code, rec.Body.String())
	}
	var r importResp
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return r
}

func newImportHandler(t *testing.T, pool *pgxpool.Pool) *Handler {
	t.Helper()
	return New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
}

func draftScenarioID(t *testing.T, h *Handler, id string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.GetImportDraft(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", id))
	var d struct {
		Scenario struct {
			ID string `json:"id"`
		} `json:"scenario"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &d)
	return d.Scenario.ID
}

func approve(t *testing.T, h *Handler, id string) *httptest.ResponseRecorder {
	return postImportJSON(t, h.ApproveImportDraft, "/x", map[string]string{"note": "reviewed"}, map[string]string{"id": id})
}

func TestImportSigma_MakesADraftThatCannotRunUntilApproved(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		r := importOne(t, h, importSigma)
		if len(r.Results) != 1 || !r.Results[0].Emulable || r.Results[0].DraftID == "" {
			t.Fatalf("%+v", r)
		}
		sid := draftScenarioID(t, h, r.Results[0].DraftID)
		if sid == "" {
			t.Fatal("draft has no scenario")
		}
		if _, ok := h.engine.Get(sid); ok {
			t.Fatal("an unapproved draft must not exist as a scenario that could be run")
		}

		rec := approve(t, h, r.Results[0].DraftID)
		if rec.Code != http.StatusOK {
			t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
		}
		sc, ok := h.engine.Get(sid)
		if !ok || sc.Source != "custom" || len(sc.Steps) != 1 || !strings.HasPrefix(sc.Steps[0].Marker, "imp-") {
			t.Fatalf("approved scenario missing or wrong: %+v", sc)
		}
		if rec := approve(t, h, r.Results[0].DraftID); rec.Code != http.StatusConflict {
			t.Errorf("a second approval must be refused, got %d", rec.Code)
		}
	})
}

func TestImportSigma_ImportingTheSameRuleTwiceReusesTheDraft(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		a, b := importOne(t, h, importSigma), importOne(t, h, importSigma)
		if a.Results[0].DraftID != b.Results[0].DraftID || !b.Results[0].Duplicate {
			t.Errorf("want the same draft flagged duplicate: %+v %+v", a.Results[0], b.Results[0])
		}
	})
}

func TestImportSigma_ARuleThatCannotBeReproducedMakesNoDraftAndSaysWhy(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		r := importOne(t, h, importSigmaNotEmulable)
		if r.Results[0].Emulable || r.Results[0].DraftID != "" || len(r.Results[0].Coverage.NotEmulated) == 0 {
			t.Errorf("%+v", r.Results[0])
		}
	})
}

func TestImportSigma_SeveralRulesAndABadOneInOneRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		r := importOne(t, h, importSigma+"\n---\n"+importSigmaNotEmulable+"\n---\nthis is: [not a rule")
		if len(r.Results) != 3 {
			t.Fatalf("each document gets its own result: %+v", r)
		}
		if r.Results[0].DraftID == "" || r.Results[1].DraftID != "" || r.Results[2].Error == "" {
			t.Errorf("%+v", r.Results)
		}
	})
}

func TestReject_KeepsTheDraftOutOfTheScenarioList(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		r := importOne(t, h, importSigma)
		id := r.Results[0].DraftID
		sid := draftScenarioID(t, h, id)
		if rec := postImportJSON(t, h.RejectImportDraft, "/x", map[string]string{"note": "no"}, map[string]string{"id": id}); rec.Code != http.StatusOK {
			t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
		}
		if _, ok := h.engine.Get(sid); ok {
			t.Error("a rejected draft must never become a scenario")
		}
		if rec := approve(t, h, id); rec.Code != http.StatusConflict {
			t.Errorf("a rejected draft cannot then be approved: %d", rec.Code)
		}
	})
}

func TestImportYARA_MakesADraftAndValidatesTheOS(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		src := `rule Demo { meta: attack = "T1204" strings: $a = "benign-test-string" condition: $a }`
		if rec := postImportJSON(t, h.ImportYARA, "/y", map[string]string{"source": src, "os": "macos"}, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("os must be windows or linux: %d", rec.Code)
		}
		rec := postImportJSON(t, h.ImportYARA, "/y", map[string]string{"source": src, "os": "linux"}, nil)
		var r importResp
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		if rec.Code != http.StatusOK || len(r.Results) != 1 || r.Results[0].DraftID == "" {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
	})
}

func approvedScenario(t *testing.T, h *Handler, source string) string {
	t.Helper()
	r := importOne(t, h, source)
	id := r.Results[0].DraftID
	sid := draftScenarioID(t, h, id)
	if rec := approve(t, h, id); rec.Code != http.StatusOK {
		t.Fatalf("approve: %s", rec.Body.String())
	}
	return sid
}

func TestImportChain_BuildsFromApprovedStepsOnlyAndNeedsReview(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		a := approvedScenario(t, h, importSigma)
		b := approvedScenario(t, h, strings.Replace(importSigma, "Certutil Download", "Second Rule", 1))

		stage := func(id, runIf string) map[string]any { return map[string]any{"scenarioId": id, "stepIndex": 0, "runIf": runIf} }
		rec := postImportJSON(t, h.ImportChain, "/c", map[string]any{"name": "Two step", "stages": []any{stage(a, ""), stage(b, "prev_allowed")}}, nil)
		var r importResp
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		if rec.Code != http.StatusOK || len(r.Results) != 1 || r.Results[0].DraftID == "" {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		cid := draftScenarioID(t, h, r.Results[0].DraftID)
		if _, ok := h.engine.Get(cid); ok {
			t.Error("a chain is a draft too: it must not exist as a scenario before approval")
		}

		if rec := postImportJSON(t, h.ImportChain, "/c", map[string]any{"name": "Bad", "stages": []any{stage(a, ""), stage("no-such-scenario", "")}}, nil); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("an unknown scenario must be refused: %d", rec.Code)
		}
		if rec := postImportJSON(t, h.ImportChain, "/c", map[string]any{"name": "Bad", "stages": []any{stage(a, ""), stage(b, "sometimes")}}, nil); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("a bad run_if must be refused: %d", rec.Code)
		}
	})
}

func TestImport_RejectsAnOversizedBody(t *testing.T) {
	if testing.Short() {
		t.Skip("container-backed")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := newImportHandler(t, pool)
		rec := postImportJSON(t, h.ImportSigma, "/s", map[string]string{"source": strings.Repeat("a", 600<<10)}, nil)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("want 413, got %d", rec.Code)
		}
	})
}
