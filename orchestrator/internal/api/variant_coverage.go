package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/scenario"
)

// ── Response types ─────────────────────────────────────────────────────────────

// VariantCoverageReport is the top-level response for GET /variant-coverage.
type VariantCoverageReport struct {
	RunID        string                     `json:"runId"`
	ScenarioID   string                     `json:"scenarioId"`
	VariantDepth string                     `json:"variantDepth"`
	RunStatus    string                     `json:"runStatus"`
	Summary      VariantCoverageSummary     `json:"summary"`
	Techniques   []TechniqueVariantCoverage `json:"techniques"`
}

type VariantCoverageSummary struct {
	TechniquesTotal        int     `json:"techniquesTotal"`
	TechniquesWithBypass   int     `json:"techniquesWithBypass"`
	TechniquesFullyBlocked int     `json:"techniquesFullyBlocked"`
	VariantsExecuted       int     `json:"variantsExecuted"`
	Blocked                int     `json:"blocked"`
	Detected               int     `json:"detected"`
	Logged                 int     `json:"logged"`
	Bypassed               int     `json:"bypassed"`
	Errors                 int     `json:"errors"`
	// BypassRate = (bypassed+detected) / (total-errors-skipped) * 100
	BypassRate    float64 `json:"bypassRate"`
	// CoverageScore = blocked / (total-errors-skipped) * 100 (prevention effectiveness)
	CoverageScore float64 `json:"coverageScore"`
}

type TechniqueVariantCoverage struct {
	TechniqueID      string   `json:"techniqueId"`
	TechniqueName    string   `json:"techniqueName"`
	Tactic           string   `json:"tactic"`
	VariantsExecuted int      `json:"variantsExecuted"`
	Blocked          int      `json:"blocked"`
	Detected         int      `json:"detected"`
	Logged           int      `json:"logged"`
	Bypassed         int      `json:"bypassed"`
	Errors           int      `json:"errors"`
	BypassRate       float64  `json:"bypassRate"`
	HasBypass        bool     `json:"hasBypass"`

	BestBypassVariantID string           `json:"bestBypassVariantId,omitempty"`
	BestBypass          *VariantResultRow `json:"bestBypass,omitempty"`

	EncodingsCovered  []string `json:"encodingsCovered"`
	PrivilegesCovered []string `json:"privilegesCovered"`
	ContextsCovered   []string `json:"contextsCovered"`

	// Recommendation text
	Headline          string   `json:"headline"`
	RemediationPoints []string `json:"remediationPoints"`
}

// VariantResultRow is one row from scenario_variant_results, returned in the
// coverage report for best-bypass details and in the per-technique matrix.
type VariantResultRow struct {
	ID               string `json:"id"`
	VariantID        string `json:"variantId"`
	Encoding         string `json:"encoding"`
	Privilege        string `json:"privilege"`
	ExecutionContext  string `json:"executionContext"`
	ProxyTechniqueID string `json:"proxyTechniqueId,omitempty"`
	RequestedPriv    string `json:"requestedPrivilege,omitempty"`
	ActualPrivilege  string `json:"actualPrivilege,omitempty"`
	Verdict          string `json:"verdict"`
	DurationMs       int64  `json:"durationMs,omitempty"`
	IsBestBypass     bool   `json:"isBestBypass,omitempty"`
}

// ── computeVariantTechniqueSummary ─────────────────────────────────────────────

// computeVariantTechniqueSummary aggregates scenario_variant_results for a run
// into scenario_variant_technique_summary (one row per technique), storing the
// pre-computed best_bypass_variant_id so report rendering never re-calculates
// the ORDER BY privilege/context/encoding ordering at read time.
//
// Called from SubmitScenarioResult after persistVariantResults completes.
// Idempotent via ON CONFLICT (run_id, technique_id) DO UPDATE.
func (h *Handler) computeVariantTechniqueSummary(
	ctx context.Context,
	runID string,
	simResults []models.SimulationResult,
	meta map[string]scenario.StepMeta,
) {
	// Fast-path: if no variant meta in this run, nothing to do.
	hasVariant := false
	for _, m := range meta {
		if m.BaseTaskID != "" {
			hasVariant = true
			break
		}
	}
	if !hasVariant {
		return
	}

	// Build technique-name map from simResults (covers both base + variant steps).
	techName := map[string]string{}
	techTactic := map[string]string{}
	for _, r := range simResults {
		if r.Technique.ID != "" {
			techName[r.Technique.ID] = r.Technique.Name
			techTactic[r.Technique.ID] = r.Technique.Tactic
		}
	}

	// Aggregate per-technique counts from in-memory results.
	type agg struct {
		blocked, detected, logged, bypassed, errors, skipped int
		encodings, privileges, contexts                       map[string]bool
	}
	byTech := map[string]*agg{}
	for _, res := range simResults {
		m, ok := meta[res.ID]
		if !ok || m.BaseTaskID == "" || m.VariantSpec == nil {
			continue
		}
		techID := res.Technique.ID
		if byTech[techID] == nil {
			byTech[techID] = &agg{
				encodings: map[string]bool{},
				privileges: map[string]bool{},
				contexts:  map[string]bool{},
			}
		}
		a := byTech[techID]
		sp := m.VariantSpec
		a.encodings[normStr(sp.Encoding, "plain")] = true
		a.privileges[normStr(sp.Privilege, "user")] = true
		a.contexts[normStr(sp.ExecContext, "direct")] = true
		switch variantVerdictStr(res) {
		case "blocked":
			a.blocked++
		case "detected":
			a.detected++
		case "logged":
			a.logged++
		case "bypassed":
			a.bypassed++
		case "error":
			a.errors++
		case "skipped":
			a.skipped++
		}
	}

	for techID, a := range byTech {
		total := a.blocked + a.detected + a.logged + a.bypassed + a.errors + a.skipped

		// Best bypass: most dangerous allowed result by privilege > context > encoding.
		// Ordering: bypassed > detected > logged; then privilege tier; then exec context; then encoding.
		var bestID *string
		h.db.QueryRow(ctx, `
			SELECT id FROM scenario_variant_results
			WHERE run_id = $1 AND technique_id = $2
			  AND verdict IN ('bypassed','detected','logged')
			ORDER BY
			  CASE verdict   WHEN 'bypassed'       THEN 3 WHEN 'detected'      THEN 2 WHEN 'logged'         THEN 1 ELSE 0 END DESC,
			  CASE privilege WHEN 'system'         THEN 3 WHEN 'admin'         THEN 2                        ELSE 1 END DESC,
			  CASE execution_context
			                 WHEN 'com'            THEN 4 WHEN 'scheduled-task' THEN 3 WHEN 'wmi'            THEN 2 ELSE 1 END DESC,
			  CASE encoding  WHEN 'charcode'       THEN 3 WHEN 'base64'        THEN 2                        ELSE 1 END DESC
			LIMIT 1`,
			runID, techID,
		).Scan(&bestID)

		encs := setToSlice(a.encodings)
		privs := setToSlice(a.privileges)
		ctxs := setToSlice(a.contexts)

		_, _ = h.db.Exec(ctx, `
			INSERT INTO scenario_variant_technique_summary
			  (run_id, technique_id, technique_name, tactic, variants_executed,
			   blocked, detected, logged, bypassed, errors, skipped,
			   best_bypass_variant_id, encodings_tested, privileges_tested, contexts_tested)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
			ON CONFLICT (run_id, technique_id) DO UPDATE SET
			  variants_executed      = EXCLUDED.variants_executed,
			  blocked                = EXCLUDED.blocked,
			  detected               = EXCLUDED.detected,
			  logged                 = EXCLUDED.logged,
			  bypassed               = EXCLUDED.bypassed,
			  errors                 = EXCLUDED.errors,
			  skipped                = EXCLUDED.skipped,
			  best_bypass_variant_id = EXCLUDED.best_bypass_variant_id,
			  encodings_tested       = EXCLUDED.encodings_tested,
			  privileges_tested      = EXCLUDED.privileges_tested,
			  contexts_tested        = EXCLUDED.contexts_tested,
			  computed_at            = NOW()`,
			runID, techID, techName[techID], techTactic[techID], total,
			a.blocked, a.detected, a.logged, a.bypassed, a.errors, a.skipped,
			bestID, encs, privs, ctxs,
		)
	}
}

// ── GET /api/scenarios/runs/{runId}/variant-coverage ──────────────────────────

func (h *Handler) GetVariantCoverageReport(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	ctx := r.Context()

	var scenarioID, variantDepth, runStatus string
	if err := h.db.QueryRow(ctx,
		`SELECT scenario_id, COALESCE(variant_depth,'none'), status FROM scenario_runs WHERE id = $1`,
		runID,
	).Scan(&scenarioID, &variantDepth, &runStatus); err != nil {
		jsonError(w, "run not found", http.StatusNotFound)
		return
	}

	report := VariantCoverageReport{
		RunID:        runID,
		ScenarioID:   scenarioID,
		VariantDepth: variantDepth,
		RunStatus:    runStatus,
		Techniques:   []TechniqueVariantCoverage{},
	}

	if variantDepth == "none" {
		jsonOK(w, report)
		return
	}

	// Load pre-computed technique summaries.
	rows, err := h.db.Query(ctx, `
		SELECT technique_id, COALESCE(technique_name,''), COALESCE(tactic,''),
		       variants_executed, blocked, detected, logged, bypassed, errors, skipped,
		       best_bypass_variant_id,
		       COALESCE(encodings_tested,'{}'), COALESCE(privileges_tested,'{}'), COALESCE(contexts_tested,'{}')
		  FROM scenario_variant_technique_summary
		 WHERE run_id = $1
		 ORDER BY bypassed DESC, detected DESC, blocked ASC`,
		runID,
	)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Best bypass IDs to fetch in bulk.
	var bestIDs []string
	type summRow struct {
		techID, techName, tactic                   string
		total, blocked, detected, logged, bypassed int
		errors                                     int
		bestBypassID                               *string
		encodings, privileges, contexts            []string
	}
	var summaries []summRow

	for rows.Next() {
		var s summRow
		if err := rows.Scan(
			&s.techID, &s.techName, &s.tactic,
			&s.total, &s.blocked, &s.detected, &s.logged, &s.bypassed, &s.errors, new(int),
			&s.bestBypassID,
			&s.encodings, &s.privileges, &s.contexts,
		); err != nil {
			continue
		}
		summaries = append(summaries, s)
		if s.bestBypassID != nil {
			bestIDs = append(bestIDs, *s.bestBypassID)
		}
	}
	rows.Close()

	// Load best bypass variant details in one query.
	bestBypassMap := map[string]VariantResultRow{}
	if len(bestIDs) > 0 {
		placeholders := make([]string, len(bestIDs))
		args := make([]any, len(bestIDs))
		for i, id := range bestIDs {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
			args[i] = id
		}
		brows, berr := h.db.Query(ctx,
			`SELECT id, variant_id, encoding, privilege, execution_context,
			        COALESCE(proxy_technique_id,''), COALESCE(requested_privilege,''), COALESCE(actual_privilege,''),
			        verdict, COALESCE(duration_ms,0)
			   FROM scenario_variant_results
			  WHERE id IN (`+strings.Join(placeholders, ",")+`)`,
			args...,
		)
		if berr == nil {
			defer brows.Close()
			for brows.Next() {
				var v VariantResultRow
				if err := brows.Scan(&v.ID, &v.VariantID, &v.Encoding, &v.Privilege, &v.ExecutionContext,
					&v.ProxyTechniqueID, &v.RequestedPriv, &v.ActualPrivilege, &v.Verdict, &v.DurationMs,
				); err == nil {
					v.IsBestBypass = true
					bestBypassMap[v.ID] = v
				}
			}
		}
	}

	// Assemble technique rows.
	for _, s := range summaries {
		allowed := s.bypassed + s.detected + s.logged
		counted := s.total - s.errors
		br := pct(allowed, counted)

		tc := TechniqueVariantCoverage{
			TechniqueID:      s.techID,
			TechniqueName:    s.techName,
			Tactic:           s.tactic,
			VariantsExecuted: s.total,
			Blocked:          s.blocked,
			Detected:         s.detected,
			Logged:           s.logged,
			Bypassed:         s.bypassed,
			Errors:           s.errors,
			BypassRate:       br,
			HasBypass:        allowed > 0,
			EncodingsCovered: s.encodings,
			PrivilegesCovered: s.privileges,
			ContextsCovered:  s.contexts,
		}
		if s.bestBypassID != nil {
			tc.BestBypassVariantID = *s.bestBypassID
			if v, ok := bestBypassMap[*s.bestBypassID]; ok {
				tc.BestBypass = &v
				tc.Headline, tc.RemediationPoints = coverageRecommendation(
					s.techID, v.Encoding, v.ExecutionContext, v.Privilege)
			}
		}
		if tc.Headline == "" {
			tc.Headline = "All tested variants were blocked or detected."
			tc.RemediationPoints = []string{
				"Verify detection alerts were raised (not just prevented silently)",
				"Enable ScriptBlock logging (Event 4104) to confirm visibility into blocked attempts",
			}
		}
		report.Techniques = append(report.Techniques, tc)
	}

	// Aggregate run-level summary.
	report.Summary = buildCoverageSummary(report.Techniques)
	jsonOK(w, report)
}

// ── GET /api/scenarios/runs/{runId}/variant-coverage/{techniqueId} ─────────────

// GetVariantMatrix returns every variant result row for one technique in a run,
// ordered worst-first. The best bypass row is flagged with isBestBypass=true.
func (h *Handler) GetVariantMatrix(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	techID := chi.URLParam(r, "techniqueId")
	ctx := r.Context()

	// Look up best bypass id for this technique/run.
	var bestBypassID string
	h.db.QueryRow(ctx,
		`SELECT COALESCE(best_bypass_variant_id,'')
		   FROM scenario_variant_technique_summary
		  WHERE run_id = $1 AND technique_id = $2`,
		runID, strings.ToUpper(strings.TrimSpace(techID)),
	).Scan(&bestBypassID)

	rows, err := h.db.Query(ctx, `
		SELECT id, variant_id, encoding, privilege, execution_context,
		       COALESCE(proxy_technique_id,''), COALESCE(requested_privilege,''), COALESCE(actual_privilege,''),
		       verdict, COALESCE(duration_ms,0)
		  FROM scenario_variant_results
		 WHERE run_id = $1 AND technique_id = $2
		 ORDER BY
		   CASE verdict   WHEN 'bypassed'        THEN 1 WHEN 'detected'       THEN 2 WHEN 'logged'          THEN 3
		                  WHEN 'blocked'         THEN 4                        ELSE 5 END,
		   CASE privilege WHEN 'system'          THEN 1 WHEN 'admin'          THEN 2                        ELSE 3 END,
		   CASE execution_context
		                  WHEN 'com'             THEN 1 WHEN 'scheduled-task'  THEN 2 WHEN 'wmi'             THEN 3 ELSE 4 END,
		   CASE encoding  WHEN 'charcode'        THEN 1 WHEN 'base64'         THEN 2                        ELSE 3 END`,
		runID, strings.ToUpper(strings.TrimSpace(techID)),
	)
	if err != nil {
		jsonError(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var matrix []VariantResultRow
	for rows.Next() {
		var v VariantResultRow
		if err := rows.Scan(&v.ID, &v.VariantID, &v.Encoding, &v.Privilege, &v.ExecutionContext,
			&v.ProxyTechniqueID, &v.RequestedPriv, &v.ActualPrivilege, &v.Verdict, &v.DurationMs,
		); err == nil {
			v.IsBestBypass = (v.ID == bestBypassID)
			matrix = append(matrix, v)
		}
	}

	jsonOK(w, map[string]any{
		"runId":       runID,
		"techniqueId": techID,
		"bestBypass":  bestBypassID,
		"total":       len(matrix),
		"rows":        matrix,
	})
}

// ── Recommendation engine ──────────────────────────────────────────────────────

// coverageRecommendation returns a headline finding sentence and 3–5 actionable
// remediation bullet points for the most dangerous tested bypass combination.
func coverageRecommendation(techID, enc, execCtx, priv string) (headline string, points []string) {
	noun := techExecLang(techID)

	switch execCtx {
	case "wmi":
		headline = fmt.Sprintf("%s via WMI (T1047) was not prevented", noun)
		points = []string{
			"Enable WMI activity auditing (Events 5857–5861, Microsoft-Windows-WMI-Activity/Operational)",
			"Block wmic.exe via AppLocker or WDAC if Win32_Process.Create is not operationally required",
			"Add EDR alert: PowerShell spawning child processes through WMI instead of CreateProcess",
			"Review EDR WMI execution detection rules and verify they are in Block mode (not Audit)",
		}
	case "scheduled-task":
		headline = fmt.Sprintf("%s via Scheduled Task (T1053.005) was not prevented", noun)
		points = []string{
			"Enable Task Scheduler audit logging (Events 4698, 4699, 4702 — Security log)",
			"Alert on schtasks.exe creating tasks with /sc once — strong BAS and malware indicator",
			"Consider AppLocker rules restricting schtasks.exe execution in non-administrative contexts",
			"Review EDR scheduled task detection rules — verify Block mode is active",
		}
	case "com":
		headline = fmt.Sprintf("%s via COM WScript.Shell (T1559.001) was not prevented", noun)
		points = []string{
			"Add EDR rule: alert when WScript.Shell.Run spawns child processes (powershell.exe, cmd.exe)",
			"Enable Script Auditing (Event 4104) to capture WScript-invoked payload content",
			"Review COM object instantiation policy — restrict New-Object -COM WScript.Shell in Constrained Language Mode",
		}
	default:
		// Direct execution — focus on encoding
		switch enc {
		case "base64":
			headline = fmt.Sprintf("%s with Base64 encoding (-EncodedCommand) was not detected", noun)
			points = []string{
				"Enable PowerShell ScriptBlock logging (Event 4104) — decodes base64 transparently",
				"Enable ASR rule: Block execution of potentially obfuscated scripts (GUID 5BEB7EFE)",
				"Ensure AMSI is functioning and not bypassed — base64 payloads are decoded before AMSI inspection",
			}
		case "charcode":
			headline = fmt.Sprintf("%s with charcode obfuscation (IEX([char]N+...)) was not detected", noun)
			points = []string{
				"Enable PowerShell ScriptBlock logging (Event 4104) — charcode is decoded before logging",
				"Deploy PowerShell Constrained Language Mode to restrict arbitrary IEX invocations",
				"Enable ASR rule: Block execution of potentially obfuscated scripts (GUID 5BEB7EFE)",
			}
		default:
			headline = fmt.Sprintf("%s executed without triggering a prevention or detection control", noun)
			points = []string{
				fmt.Sprintf("Review EDR prevention policy coverage for %s", techID),
				"Enable PowerShell Module logging (Event 4103) and ScriptBlock logging (Event 4104)",
				"Verify ASR rules are in Block mode — Audit mode does not prevent execution",
			}
		}
	}

	// Append privilege note if elevated — always actionable.
	switch priv {
	case "admin":
		points = append(points,
			"Execution succeeded at local administrator privilege — review privileged access controls and local admin restrictions (LAPS / PAW model)")
	case "system":
		points = append(points,
			"Execution succeeded at SYSTEM privilege — verify privilege escalation path controls and SYSTEM-level execution restrictions")
	}

	return headline, points
}

func techExecLang(techID string) string {
	prefixes := []struct{ prefix, label string }{
		{"T1059.001", "PowerShell execution"},
		{"T1059.003", "Windows Command Shell execution"},
		{"T1059.005", "Visual Basic execution"},
		{"T1059",     "Script/command execution"},
		{"T1047",     "WMI execution"},
		{"T1053",     "Scheduled task execution"},
		{"T1218",     "System binary proxy execution"},
		{"T1055",     "Process injection"},
	}
	for _, p := range prefixes {
		if strings.HasPrefix(techID, p.prefix) {
			return p.label
		}
	}
	return techID + " execution"
}

// ── helpers ───────────────────────────────────────────────────────────────────

func buildCoverageSummary(techs []TechniqueVariantCoverage) VariantCoverageSummary {
	var s VariantCoverageSummary
	s.TechniquesTotal = len(techs)
	for _, t := range techs {
		s.VariantsExecuted += t.VariantsExecuted
		s.Blocked += t.Blocked
		s.Detected += t.Detected
		s.Logged += t.Logged
		s.Bypassed += t.Bypassed
		s.Errors += t.Errors
		if t.HasBypass {
			s.TechniquesWithBypass++
		} else if t.Bypassed+t.Detected == 0 {
			s.TechniquesFullyBlocked++
		}
	}
	counted := s.VariantsExecuted - s.Errors
	s.BypassRate    = pct(s.Bypassed+s.Detected, counted)
	s.CoverageScore = pct(s.Blocked, counted)
	return s
}

func setToSlice(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return math.Round(float64(n)/float64(total)*1000) / 10
}

