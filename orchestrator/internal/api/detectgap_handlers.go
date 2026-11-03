package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

type gapReport struct {
	RunID      string
	Summary    map[string]int
	Techniques []gapTechnique
	statuses   map[string]detectgap.Status
}

var errGapRunNotFound = errors.New("run not found")

// buildGapReport classifies every technique in a run from evidence. Rules are attached to gaps, or to every
// technique when allRules is set.
func (h *Handler) buildGapReport(ctx context.Context, runID, backend string, allRules bool, limit int) (*gapReport, error) {
	_, _, _, results, err := h.loadRunForVerification(ctx, runID)
	if err != nil {
		return nil, errGapRunNotFound
	}
	current, err := h.verification.CurrentForRun(ctx, runID)
	if err != nil {
		return nil, err
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

	rep := &gapReport{RunID: runID, Summary: map[string]int{}, statuses: map[string]detectgap.Status{}}
	for _, id := range order {
		t := byTech[id]
		c := detectgap.Classify(*t)
		rep.Summary[string(c.Status)]++
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
			row.Rules = gapRules(pickRules(rules, backend, limit), match, backend)
		}
		rep.statuses[id] = c.Status
		rep.Techniques = append(rep.Techniques, row)
	}
	sort.SliceStable(rep.Techniques, func(i, j int) bool {
		a, b := gapStatusOrder[rep.statuses[rep.Techniques[i].TechniqueID]], gapStatusOrder[rep.statuses[rep.Techniques[j].TechniqueID]]
		if a != b {
			return a < b
		}
		return rep.Techniques[i].TechniqueID < rep.Techniques[j].TechniqueID
	})
	return rep, nil
}

func (h *Handler) libraryInfo() map[string]any {
	lib := map[string]any{"loaded": h.rules != nil}
	if h.rules != nil {
		m := h.rules.Metadata()
		lib["sigmaCommit"], lib["license"], lib["attribution"], lib["ruleCount"] = m.SigmaCommit, m.SourceLicense, m.Attribution, h.rules.RuleCount()
	}
	return lib
}

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
	limit := 10
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, 50)
	}
	rep, err := h.buildGapReport(r.Context(), chi.URLParam(r, "runId"), strings.TrimSpace(r.URL.Query().Get("backend")),
		r.URL.Query().Get("rules") == "all", limit)
	if errors.Is(err, errGapRunNotFound) {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, map[string]any{"runId": rep.RunID, "summary": rep.Summary, "library": h.libraryInfo(), "techniques": rep.Techniques})
}

var safeRuleID = regexp.MustCompile(`^AUDRULE-\d{6}$`)
var queryExt = map[string]string{"KQL": "kql", "SPL": "spl", "Lucene": "lucene", "LogScale": "logscale", "AQL": "aql"}

// ExportRunDetectionGaps returns a zip of everything needed to close a run's detection gaps: for each gap the
// original Sigma rule and the generated query for each SIEM (or the one in ?backend=), a manifest that says where
// every rule came from and under what licence, the data source each query needs, and a NOTICE carrying the
// SigmaHQ attribution. Only detection gaps are included; a gap with no rule is listed as such, nothing is invented.
// GET /api/scenarios/runs/{runId}/detection-gaps/export?backend=&limit=
func (h *Handler) ExportRunDetectionGaps(w http.ResponseWriter, r *http.Request) {
	if h.verification == nil || h.rules == nil {
		jsonError(w, "verification store or rule library unavailable", http.StatusServiceUnavailable)
		return
	}
	runID := chi.URLParam(r, "runId")
	backend := strings.TrimSpace(r.URL.Query().Get("backend"))
	limit := 25
	if n, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && n > 0 {
		limit = min(n, 100)
	}
	rep, err := h.buildGapReport(r.Context(), runID, backend, false, limit)
	if errors.Is(err, errGapRunNotFound) {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	type mRule struct {
		gapRule
		Files []string `json:"files"`
	}
	type mTech struct {
		TechniqueID      string  `json:"techniqueId"`
		Name             string  `json:"name"`
		Reason           string  `json:"reason"`
		RuleAvailability string  `json:"ruleAvailability"`
		Effectiveness    string  `json:"effectiveness"`
		RuleCount        int     `json:"ruleCount"`
		Rules            []mRule `json:"rules"`
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		if f, err := zw.Create(name); err == nil {
			f.Write([]byte(body))
		}
	}
	var techs []mTech
	for _, t := range rep.Techniques {
		if t.Status != string(detectgap.DetectionGap) {
			continue
		}
		mt := mTech{TechniqueID: t.TechniqueID, Name: t.Name, Reason: t.Reason, RuleAvailability: t.RuleAvailability,
			Effectiveness: t.Effectiveness, RuleCount: t.RuleCount, Rules: []mRule{}}
		rules, _ := h.rulesFor(t.TechniqueID)
		picked := pickRules(rules, backend, limit)
		for i, gr := range t.Rules {
			if !safeRuleID.MatchString(gr.ID) {
				continue
			}
			mr := mRule{gapRule: gr}
			sigmaPath := "rules/" + gr.ID + ".sigma.yml"
			add(sigmaPath, picked[i].Detection)
			mr.Files = append(mr.Files, sigmaPath)
			for _, tr := range picked[i].Translations {
				ext, ok := queryExt[tr.Language]
				if !ok || (backend != "" && tr.Backend != backend) {
					continue
				}
				p := "queries/" + tr.Backend + "/" + gr.ID + "." + ext
				add(p, tr.Query+"\n")
				mr.Files = append(mr.Files, p)
			}
			mt.Rules = append(mt.Rules, mr)
		}
		techs = append(techs, mt)
	}
	if len(techs) == 0 {
		zw.Close()
		jsonError(w, "this run has no detection gap to export", http.StatusNotFound)
		return
	}

	lib := h.libraryInfo()
	manifest, _ := json.MarshalIndent(map[string]any{
		"runId": runID, "generatedBy": "Audspect BAS", "effectiveness": detectgap.Effectiveness,
		"library": lib, "backendFilter": backend,
		"note":       "A query only matches if the customer collects the data source named beside it. Rules are not validated against telemetry.",
		"techniques": techs,
	}, "", "  ")
	add("manifest.json", string(manifest))
	add("NOTICE.txt", fmt.Sprintf("Detection rules in this bundle are from the SigmaHQ project (%s),\n"+
		"commit %v, licensed under the Detection Rule License (DRL) 1.1:\n%s\n\n"+
		"Each rule keeps its original author, title, id and references. The per-SIEM queries were generated from the rules\n"+
		"by Audspect and are not part of the upstream project. Attribution to the rule authors must be retained when\n"+
		"you redistribute these rules.\n\n"+
		"Effectiveness: %s. No rule has been tested against your telemetry. A query matches only if you collect the data\n"+
		"source listed in manifest.json.\n", "https://github.com/SigmaHQ/sigma", lib["sigmaCommit"],
		"https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md", detectgap.Effectiveness))
	if err := zw.Close(); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "detectgap.exported", runID, map[string]any{"backend": backend, "gaps": len(techs)}, "ok")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="detection-gaps-`+runID+`.zip"`)
	w.Write(buf.Bytes())
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

var languageFormat = map[string]string{"KQL": "kql", "SPL": "spl", "Lucene": "lucene", "LogScale": "logscale", "AQL": "aql"}

// pickRules orders rules by severity then id, drops those with no translation for the requested SIEM (they are not
// offered as a fix for it), and keeps at most limit.
func pickRules(rules []rulelib.Rule, backend string, limit int) []rulelib.Rule {
	sorted := append([]rulelib.Rule(nil), rules...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := gapSeverityOrder[strings.ToLower(sorted[i].Severity)], gapSeverityOrder[strings.ToLower(sorted[j].Severity)]
		if a != b {
			return a < b
		}
		return sorted[i].ID < sorted[j].ID
	})
	var out []rulelib.Rule
	for _, r := range sorted {
		if backend != "" {
			has := false
			for _, t := range r.Translations {
				has = has || t.Backend == backend
			}
			if !has {
				continue
			}
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out
}

func gapRules(rules []rulelib.Rule, match, backend string) []gapRule {
	out := []gapRule{}
	for _, r := range rules {
		g := gapRule{ID: r.ID, SigmaID: r.SigmaID, Title: r.Title, Severity: r.Severity, Status: r.Status, Author: r.Author,
			Match: match, LogSource: r.LogSource, Source: r.Source, Backends: []gapBackend{}}
		for _, t := range r.Translations {
			if backend != "" && t.Backend != backend {
				continue
			}
			g.Backends = append(g.Backends, gapBackend{Backend: t.Backend, Language: t.Language, Mapping: t.Mapping,
				Pipeline: t.Pipeline, DataSource: t.DataSource, ExportURL: "/api/rules/export?id=" + r.ID + "&format=" + languageFormat[t.Language]})
		}
		out = append(out, g)
	}
	return out
}
