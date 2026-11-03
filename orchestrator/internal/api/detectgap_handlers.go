package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/detectgap"
	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/rulelib"
)

type gapBackend struct {
	Backend    string `json:"backend"`
	Language   string `json:"language"`
	Mapping    string `json:"mapping"`
	Pipeline   string `json:"pipeline,omitempty"`
	DataSource string `json:"dataSource,omitempty"`
	ExportURL  string `json:"exportUrl"`
}

type gapRule struct {
	ID        string            `json:"id"`
	SigmaID   string            `json:"sigmaId"`
	Title     string            `json:"title"`
	Severity  string            `json:"severity"`
	Status    string            `json:"status"`
	Author    string            `json:"author"`
	Match     string            `json:"match"` // exact | parent: the rule is tagged with the technique, or only with its parent
	LogSource rulelib.LogSource `json:"logSource"`
	Source    rulelib.Source    `json:"source"`
	Backends  []gapBackend      `json:"backends"`
}

type gapTechnique struct {
	TechniqueID      string         `json:"techniqueId"`
	Name             string         `json:"name"`
	Status           string         `json:"status"`
	Reason           string         `json:"reason"`
	Steps            map[string]int `json:"steps"`
	RuleAvailability string         `json:"ruleAvailability"`
	Effectiveness    string         `json:"effectiveness"`
	RuleCount        int            `json:"ruleCount"`
	Rules            []gapRule      `json:"rules,omitempty"`
}

var gapStatusOrder = map[detectgap.Status]int{
	detectgap.DetectionGap: 0, detectgap.Unknown: 1, detectgap.ExecutionError: 2, detectgap.Skipped: 3, detectgap.Detected: 4,
}

var gapSeverityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

// GetRunDetectionGaps classifies every technique in a run from evidence (the run's step results and its reviewed
// verifications) and, for each detection gap, lists the library rules that could close it with the per-SIEM export
// links. GET /api/scenarios/runs/{runId}/detection-gaps?backend=&rules=all&limit=
//
// Statuses: Detected, Detection gap, Execution error, Skipped, Unknown. A gap needs a reviewed "not detected"
// verification of a technique that ran to completion; a technique nobody verified is Unknown, never a gap. Rule
// availability says only that a rule exists, and effectiveness is always "Not validated".
func (h *Handler) GetRunDetectionGaps(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil {
		jsonError(w, "verification store unavailable", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	_, _, _, results, err := h.loadRunForVerification(r.Context(), runID)
	if err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	current, err := h.verification.CurrentForRun(r.Context(), runID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	backend := strings.TrimSpace(r.URL.Query().Get("backend"))
	allRules := r.URL.Query().Get("rules") == "all"
	limit := 10
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, 50)
	}

	byTech := map[string]*detectgap.Technique{}
	names := map[string]string{}
	var order []string
	for _, res := range results {
		id := res.Technique.ID
		if id == "" {
			continue // a posture check, not an ATT&CK technique
		}
		t := byTech[id]
		if t == nil {
			t = &detectgap.Technique{TechniqueID: id, Outcomes: map[models.CheckResult]int{}}
			byTech[id] = t
			names[id] = res.Technique.Name
			order = append(order, id)
		}
		t.Outcomes[res.Result]++
	}
	for _, rec := range current {
		if t := byTech[rec.TechniqueID]; t != nil {
			t.Attestations = append(t.Attestations, detectgap.Attestation{Result: rec.Result, State: rec.WorkflowState})
		}
	}

	summary := map[string]int{}
	rows := make([]gapTechnique, 0, len(order))
	statuses := map[string]detectgap.Status{}
	for _, id := range order {
		t := byTech[id]
		c := detectgap.Classify(*t)
		summary[string(c.Status)]++
		steps := map[string]int{}
		for k, v := range t.Outcomes {
			steps[string(k)] = v
		}
		rules, match := h.rulesFor(id)
		row := gapTechnique{
			TechniqueID: id, Name: names[id], Status: string(c.Status), Reason: c.Reason, Steps: steps,
			RuleAvailability: detectgap.Availability(rules, backend), Effectiveness: detectgap.Effectiveness, RuleCount: len(rules),
		}
		if c.Status == detectgap.DetectionGap || allRules {
			row.Rules = gapRules(rules, match, backend, limit)
		}
		statuses[id] = c.Status
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := gapStatusOrder[statuses[rows[i].TechniqueID]], gapStatusOrder[statuses[rows[j].TechniqueID]]
		if a != b {
			return a < b
		}
		return rows[i].TechniqueID < rows[j].TechniqueID
	})

	lib := map[string]any{"loaded": h.rules != nil}
	if h.rules != nil {
		m := h.rules.Metadata()
		lib["sigmaCommit"], lib["license"], lib["attribution"], lib["ruleCount"] = m.SigmaCommit, m.SourceLicense, m.Attribution, m.RuleCount
	}
	respond(w, map[string]any{"runId": runID, "summary": summary, "library": lib, "techniques": rows})
}

// rulesFor returns the rules tagged with the technique, or, when there are none for a sub-technique, the rules
// tagged only with its parent (labelled so: a parent rule is broader).
func (h *Handler) rulesFor(techniqueID string) ([]rulelib.Rule, string) {
	if h.rules == nil {
		return nil, ""
	}
	if rs := h.rules.RulesByTechnique(techniqueID); len(rs) > 0 {
		return rs, "exact"
	}
	if i := strings.Index(techniqueID, "."); i > 0 {
		if rs := h.rules.RulesByTechnique(techniqueID[:i]); len(rs) > 0 {
			return rs, "parent"
		}
	}
	return nil, ""
}

var languageFormat = map[string]string{"KQL": "kql", "SPL": "spl", "Lucene": "lucene", "LogScale": "logscale"}

func gapRules(rules []rulelib.Rule, match, backend string, limit int) []gapRule {
	sorted := append([]rulelib.Rule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := gapSeverityOrder[strings.ToLower(sorted[i].Severity)], gapSeverityOrder[strings.ToLower(sorted[j].Severity)]
		if a != b {
			return a < b
		}
		return sorted[i].ID < sorted[j].ID
	})
	var out []gapRule
	for _, r := range sorted {
		g := gapRule{ID: r.ID, SigmaID: r.SigmaID, Title: r.Title, Severity: r.Severity, Status: r.Status, Author: r.Author,
			Match: match, LogSource: r.LogSource, Source: r.Source, Backends: []gapBackend{}}
		for _, t := range r.Translations {
			if backend != "" && t.Backend != backend {
				continue
			}
			g.Backends = append(g.Backends, gapBackend{Backend: t.Backend, Language: t.Language, Mapping: t.Mapping,
				Pipeline: t.Pipeline, DataSource: t.DataSource, ExportURL: "/api/rules/export?id=" + r.ID + "&format=" + languageFormat[t.Language]})
		}
		if backend != "" && len(g.Backends) == 0 {
			continue // no translation for the SIEM that was asked about: not offered as a fix
		}
		out = append(out, g)
		if len(out) == limit {
			break
		}
	}
	return out
}
