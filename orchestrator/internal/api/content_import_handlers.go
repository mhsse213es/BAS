package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/audspect/bas/internal/contentimport"
	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/scenario"
)

// Imported content (Sigma and YARA rules, chains) becomes a DRAFT: a row that cannot run anywhere. It becomes a runnable
// custom scenario only when a user holding content:transition (Admin) approves it, and the approval is audited. See
// internal/contentimport for how a draft is generated and why it is inert.

const (
	maxImportBody  = 512 << 10
	maxImportRules = 50
)

var sigmaDocSplit = regexp.MustCompile(`(?m)^---\s*$`)

type importItem struct {
	Title     string                 `json:"title"`
	RuleID    string                 `json:"ruleId,omitempty"`
	Emulable  bool                   `json:"emulable"`
	Coverage  contentimport.Coverage `json:"coverage"`
	DraftID   string                 `json:"draftId,omitempty"`
	Duplicate bool                   `json:"duplicate,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

func readImportBody(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxImportBody))
	if err != nil {
		jsonError(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// storeDraft saves the scenario as a waiting draft, or returns the one already waiting for the same source.
func (h *Handler) storeDraft(r *http.Request, kind, title, marker string, sc *scenario.Scenario, cov contentimport.Coverage) (id string, dup bool, err error) {
	if existing, ferr := db.FindPendingImportDraft(r.Context(), h.db, marker); ferr != nil {
		return "", false, ferr
	} else if existing != nil {
		return existing.ID, true, nil
	}
	sj, err := json.Marshal(sc)
	if err != nil {
		return "", false, err
	}
	cj, _ := json.Marshal(cov)
	d := &db.ImportDraft{ID: uuid.NewString(), Kind: kind, Title: title, Marker: marker, Scenario: sj, Coverage: cj, CreatedBy: actorFor(r)}
	if err := db.InsertImportDraft(r.Context(), h.db, d); err != nil {
		return "", false, err
	}
	return d.ID, false, nil
}

// POST /api/content-import/sigma  {source, technique?}: one or more Sigma rules (YAML documents separated by ---).
func (h *Handler) ImportSigma(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source    string `json:"source"`
		Technique string `json:"technique"`
	}
	if !readImportBody(w, r, &req) {
		return
	}
	docs := []string{}
	for _, d := range sigmaDocSplit.Split(req.Source, -1) {
		if strings.TrimSpace(d) != "" {
			docs = append(docs, d)
		}
	}
	if len(docs) == 0 {
		jsonError(w, "source is empty", http.StatusBadRequest)
		return
	}
	if len(docs) > maxImportRules {
		jsonError(w, fmt.Sprintf("at most %d rules per import", maxImportRules), http.StatusBadRequest)
		return
	}
	items := []importItem{}
	for _, doc := range docs {
		rule, err := contentimport.ParseSigma([]byte(doc))
		if err != nil {
			items = append(items, importItem{Title: "(unreadable rule)", Error: err.Error()})
			continue
		}
		res, err := contentimport.GenerateSigma(rule, req.Technique)
		if err != nil {
			items = append(items, importItem{Title: rule.Title, RuleID: rule.ID, Error: err.Error()})
			continue
		}
		it := importItem{Title: rule.Title, RuleID: rule.ID, Emulable: res.Coverage.Emulable, Coverage: res.Coverage}
		if res.Step != nil {
			sc := contentimport.BuildScenario("sigma", rule.Title, describeSigma(rule, res), res.OS, *res.Step)
			id, dup, err := h.storeDraft(r, "sigma", rule.Title, res.Step.Marker, sc, res.Coverage)
			if err != nil {
				jsonError(w, "could not store the draft: "+err.Error(), http.StatusInternalServerError)
				return
			}
			it.DraftID, it.Duplicate = id, dup
		}
		items = append(items, it)
	}
	h.auditLog(r, "content_import.sigma", "", map[string]any{"rules": len(docs)}, "ok")
	respond(w, map[string]any{"results": items})
}

func describeSigma(rule *contentimport.SigmaRule, res *contentimport.SigmaResult) string {
	d := "Imported from the Sigma rule \"" + rule.Title + "\"."
	if rule.ID != "" {
		d += " Rule id " + rule.ID + "."
	}
	d += " The step carries the rule's strings inertly (nothing the rule describes is executed) to check that the detection fires."
	if len(res.Coverage.Notes) > 0 {
		d += " Caveats: " + strings.Join(res.Coverage.Notes, "; ")
	}
	return d
}

// POST /api/content-import/yara  {source, os, technique?}: one or more YARA rules.
func (h *Handler) ImportYARA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source    string `json:"source"`
		OS        string `json:"os"`
		Technique string `json:"technique"`
	}
	if !readImportBody(w, r, &req) {
		return
	}
	if req.OS != "windows" && req.OS != "linux" {
		jsonError(w, "os must be windows or linux", http.StatusBadRequest)
		return
	}
	rules, err := contentimport.ParseYARA(req.Source)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if len(rules) > maxImportRules {
		jsonError(w, fmt.Sprintf("at most %d rules per import", maxImportRules), http.StatusBadRequest)
		return
	}
	items := []importItem{}
	for _, rule := range rules {
		res, err := contentimport.GenerateYARA(rule, req.OS, req.Technique)
		if err != nil {
			items = append(items, importItem{Title: rule.Name, Error: err.Error()})
			continue
		}
		it := importItem{Title: rule.Name, Emulable: res.Coverage.Emulable, Coverage: res.Coverage}
		if res.Step != nil {
			desc := "Imported from the YARA rule \"" + rule.Name + "\". The step writes a small inert file holding the rule's match strings and checks whether the host's security software removes it; the file is never executed."
			sc := contentimport.BuildScenario("yara", rule.Name, desc, req.OS, *res.Step)
			id, dup, err := h.storeDraft(r, "yara", rule.Name, res.Step.Marker, sc, res.Coverage)
			if err != nil {
				jsonError(w, "could not store the draft: "+err.Error(), http.StatusInternalServerError)
				return
			}
			it.DraftID, it.Duplicate = id, dup
		}
		items = append(items, it)
	}
	h.auditLog(r, "content_import.yara", "", map[string]any{"rules": len(rules)}, "ok")
	respond(w, map[string]any{"results": items})
}

// POST /api/content-import/chain  {name, stages:[{scenarioId, stepIndex, runIf}]}.
// Stages are looked up by reference in scenarios the server already holds, so a request can never supply its own command.
func (h *Handler) ImportChain(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Stages []struct {
			ScenarioID string `json:"scenarioId"`
			StepIndex  int    `json:"stepIndex"`
			RunIf      string `json:"runIf"`
		} `json:"stages"`
	}
	if !readImportBody(w, r, &req) {
		return
	}
	stages := make([]contentimport.Stage, 0, len(req.Stages))
	for i, ref := range req.Stages {
		sc, ok := h.engine.Get(ref.ScenarioID)
		if !ok {
			jsonError(w, fmt.Sprintf("stage %d: scenario %q not found", i+1, ref.ScenarioID), http.StatusUnprocessableEntity)
			return
		}
		if ref.StepIndex < 0 || ref.StepIndex >= len(sc.Steps) {
			jsonError(w, fmt.Sprintf("stage %d: scenario %q has no step %d", i+1, ref.ScenarioID, ref.StepIndex), http.StatusUnprocessableEntity)
			return
		}
		st := sc.Steps[ref.StepIndex]
		stages = append(stages, contentimport.Stage{Name: st.Name, TechniqueID: st.TechniqueID, ActionKey: st.ActionKey, Executor: st.Executor, Command: st.Command,
			Cleanup: st.Cleanup, Marker: st.Marker, RunIf: ref.RunIf, TimeoutSec: st.TimeoutSec, Risk: st.Risk,
			Reversible: st.Reversible, SafeForProd: st.ProductionSafe})
	}
	step, err := contentimport.CompileChain(req.Name, stages)
	if err != nil {
		jsonError(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	osName := "windows"
	if step.Executor == "bash" {
		osName = "linux"
	}
	var sb strings.Builder
	for i, s := range stages {
		ri := s.RunIf
		if i == 0 || ri == "" {
			ri = "always"
		}
		fmt.Fprintf(&sb, "%d. %s (%s, run %s)\n", i+1, s.Name, s.TechniqueID, ri)
	}
	cov := contentimport.Coverage{Emulable: true, Emulated: []string{fmt.Sprintf("%d stages", len(stages))}}
	sc := contentimport.BuildScenario("chain", req.Name, "Chain of reviewed steps:\n"+sb.String(), osName, *step)
	id, dup, err := h.storeDraft(r, "chain", req.Name, step.Marker, sc, cov)
	if err != nil {
		jsonError(w, "could not store the draft: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "content_import.chain", id, map[string]any{"stages": len(stages)}, "ok")
	respond(w, map[string]any{"results": []importItem{{Title: req.Name, Emulable: true, Coverage: cov, DraftID: id, Duplicate: dup}}})
}

// GET /api/content-import/drafts?status=draft|approved|rejected
func (h *Handler) ListImportDrafts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	switch status {
	case "", db.ImportDraftPending, db.ImportDraftApproved, db.ImportDraftRejected:
	default:
		jsonError(w, "status must be draft, approved or rejected", http.StatusBadRequest)
		return
	}
	drafts, err := db.ListImportDrafts(r.Context(), h.db, status, 200)
	if err != nil {
		jsonError(w, "could not list drafts", http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"drafts": drafts})
}

// GET /api/content-import/drafts/{id}
func (h *Handler) GetImportDraft(w http.ResponseWriter, r *http.Request) {
	d, err := db.GetImportDraft(r.Context(), h.db, chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "could not read the draft", http.StatusInternalServerError)
		return
	}
	if d == nil {
		jsonError(w, "draft not found", http.StatusNotFound)
		return
	}
	respond(w, d)
}

// POST /api/content-import/drafts/{id}/approve  {note?}: saves the draft as a custom scenario. Admin only.
func (h *Handler) ApproveImportDraft(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req) // optional body
	d, err := db.GetImportDraft(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, "could not read the draft", http.StatusInternalServerError)
		return
	}
	if d == nil {
		jsonError(w, "draft not found", http.StatusNotFound)
		return
	}
	if d.Status != db.ImportDraftPending {
		jsonError(w, "this draft was already "+d.Status, http.StatusConflict)
		return
	}
	var sc scenario.Scenario
	if err := json.Unmarshal(d.Scenario, &sc); err != nil {
		jsonError(w, "the stored draft is unreadable", http.StatusInternalServerError)
		return
	}
	if existing, ok := h.engine.Get(sc.ID); ok && existing.Source != "custom" {
		jsonError(w, fmt.Sprintf("scenario id %q is taken by %s content", sc.ID, existing.Source), http.StatusConflict)
		return
	}
	// Claim first: only one reviewer can approve a draft, even if two click at once.
	claimed, err := db.ClaimImportDraft(r.Context(), h.db, id, db.ImportDraftApproved, actorFor(r), req.Note, sc.ID)
	if err != nil {
		jsonError(w, "could not record the approval", http.StatusInternalServerError)
		return
	}
	if !claimed {
		jsonError(w, "this draft was already reviewed", http.StatusConflict)
		return
	}
	if err := h.engine.SaveAs(r.Context(), &sc, actorFor(r)); err != nil {
		_ = db.ReleaseImportDraft(r.Context(), h.db, id)
		jsonError(w, "the scenario could not be saved: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	h.auditLog(r, "content_import.approve", id, map[string]any{"scenario": sc.ID, "kind": d.Kind, "title": d.Title}, "ok")
	respond(w, map[string]any{"status": db.ImportDraftApproved, "scenarioId": sc.ID})
}

// POST /api/content-import/drafts/{id}/reject  {note?}. Admin only.
func (h *Handler) RejectImportDraft(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req)
	d, err := db.GetImportDraft(r.Context(), h.db, id)
	if err != nil {
		jsonError(w, "could not read the draft", http.StatusInternalServerError)
		return
	}
	if d == nil {
		jsonError(w, "draft not found", http.StatusNotFound)
		return
	}
	claimed, err := db.ClaimImportDraft(r.Context(), h.db, id, db.ImportDraftRejected, actorFor(r), req.Note, "")
	if err != nil {
		jsonError(w, "could not record the rejection", http.StatusInternalServerError)
		return
	}
	if !claimed {
		jsonError(w, "this draft was already "+d.Status, http.StatusConflict)
		return
	}
	h.auditLog(r, "content_import.reject", id, map[string]any{"kind": d.Kind, "title": d.Title}, "ok")
	respond(w, map[string]any{"status": db.ImportDraftRejected})
}
