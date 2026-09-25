package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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

	if len(byTech) == 0 {
		return
	}
	techIDs := make([]string, 0, len(byTech))
	for techID := range byTech {
		techIDs = append(techIDs, techID)
	}
	bestBypassByTech := fetchBestBypassIDs(ctx, h.db, runID, techIDs)

	// Batched upsert: one pipelined round trip for every technique in this
	// run instead of one Exec per technique (see fetchBestBypassIDs' doc
	// comment for why the lookup above is batched the same way -- this
	// function previously issued 2 serial DB round trips PER TECHNIQUE,
	// meaning a run covering dozens of techniques could issue 60-80+
	// round trips here alone).
	const upsert = `
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
		  computed_at            = NOW()`

	batch := &pgx.Batch{}
	for techID, a := range byTech {
		total := a.blocked + a.detected + a.logged + a.bypassed + a.errors + a.skipped
		batch.Queue(upsert,
			runID, techID, techName[techID], techTactic[techID], total,
			a.blocked, a.detected, a.logged, a.bypassed, a.errors, a.skipped,
			bestBypassByTech[techID], setToSlice(a.encodings), setToSlice(a.privileges), setToSlice(a.contexts),
		)
	}
	br := h.db.SendBatch(ctx, batch)
	for range byTech {
		_, _ = br.Exec()
	}
	_ = br.Close()
}

// fetchBestBypassIDs finds, for every technique in techIDs, the single
// "most dangerous allowed result" variant (same priority ordering
// computeVariantTechniqueSummary always used: bypassed > detected > logged;
// then privilege tier; then exec context; then encoding) -- in ONE query
// for the whole run, via Postgres's DISTINCT ON. This is provably
// equivalent to running the original per-technique
// "ORDER BY <same 4 CASE expressions> LIMIT 1" query once per technique:
// DISTINCT ON (technique_id) requires its leading ORDER BY column to be
// technique_id, and picks exactly one row per technique_id group using the
// SAME remaining ORDER BY columns to decide which one -- so grouping by
// technique_id here and ordering by technique_id first, then the identical
// 4 priority expressions, selects the identical winning row per technique
// that N separate LIMIT-1 queries would have. A technique with no
// bypassed/detected/logged result at all simply has no row in the result
// set (matching the original's silent nil on ErrNoRows), which the
// map access below correctly returns as a nil *string --
// scenario_variant_technique_summary.best_bypass_variant_id stores that as
// SQL NULL exactly as before.
func fetchBestBypassIDs(ctx context.Context, db *pgxpool.Pool, runID string, techIDs []string) map[string]*string {
	placeholders := make([]string, len(techIDs))
	args := make([]any, 0, len(techIDs)+1)
	args = append(args, runID)
	for i, id := range techIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}

	result := make(map[string]*string, len(techIDs))
	rows, err := db.Query(ctx, `
		SELECT DISTINCT ON (technique_id) technique_id, id
		FROM scenario_variant_results
		WHERE run_id = $1 AND technique_id IN (`+strings.Join(placeholders, ",")+`)
		  AND verdict IN ('bypassed','detected','logged')
		ORDER BY technique_id,
		  CASE verdict   WHEN 'bypassed'       THEN 3 WHEN 'detected'      THEN 2 WHEN 'logged'         THEN 1 ELSE 0 END DESC,
		  CASE privilege WHEN 'system'         THEN 3 WHEN 'admin'         THEN 2                        ELSE 1 END DESC,
		  CASE execution_context
		                 WHEN 'com'            THEN 4 WHEN 'scheduled-task' THEN 3 WHEN 'wmi'            THEN 2 ELSE 1 END DESC,
		  CASE encoding  WHEN 'charcode'       THEN 3 WHEN 'base64'        THEN 2                        ELSE 1 END DESC`,
		args...,
	)
	if err != nil {
		// Matches the original's own error-tolerant behavior (it never
		// checked QueryRow/Scan's error either) -- every technique simply
		// gets no best-bypass id, same as if none had qualified.
		return result
	}
	defer rows.Close()
	for rows.Next() {
		var techID, id string
		if rows.Scan(&techID, &id) == nil {
			result[techID] = &id
		}
	}
	return result
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

// ── Campaign Variant Summary ──────────────────────────────────────────────────

// refreshCampaignVariantSummary aggregates scenario_variant_technique_summary
// for all runs in the campaign and upserts campaign_variant_summary.
// Called async after computeVariantTechniqueSummary completes for a run
// that belongs to a campaign.
func (h *Handler) refreshCampaignVariantSummary(ctx context.Context, campaignID string) {
	// 1. Aggregate totals across all campaign runs.
	var techTested, varExec, blocked, detected, bypassed, runCount int
	if err := h.db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT svt.technique_id),
		       COALESCE(SUM(svt.variants_executed),0),
		       COALESCE(SUM(svt.blocked),0),
		       COALESCE(SUM(svt.detected + svt.logged),0),
		       COALESCE(SUM(svt.bypassed),0),
		       COUNT(DISTINCT svt.run_id)
		  FROM scenario_variant_technique_summary svt
		  JOIN scenario_runs sr ON sr.id = svt.run_id
		 WHERE sr.campaign_id = $1`, campaignID,
	).Scan(&techTested, &varExec, &blocked, &detected, &bypassed, &runCount); err != nil || techTested == 0 {
		return
	}

	counted := blocked + detected + bypassed
	var prevScore, detScore float64
	if counted > 0 {
		prevScore = float64(blocked) / float64(counted) * 100
		if nonBlocked := detected + bypassed; nonBlocked > 0 {
			detScore = float64(detected) / float64(nonBlocked) * 100
		}
	}

	// 2. Top recurring bypasses — techniques that bypassed controls in most runs.
	type topRow struct {
		techID, techName, tactic string
		times                    int
		sampleID                 *string
	}
	var topRows []topRow
	var sampleIDs []string

	trows, err := h.db.Query(ctx, `
		SELECT svt.technique_id,
		       MAX(svt.technique_name),
		       MAX(svt.tactic),
		       COUNT(DISTINCT svt.run_id) AS times_observed,
		       MAX(svt.best_bypass_variant_id) AS sample_bypass_id
		  FROM scenario_variant_technique_summary svt
		  JOIN scenario_runs sr ON sr.id = svt.run_id
		 WHERE sr.campaign_id = $1 AND svt.bypassed > 0
		 GROUP BY svt.technique_id
		 ORDER BY times_observed DESC
		 LIMIT 10`, campaignID)
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var r topRow
			if trows.Scan(&r.techID, &r.techName, &r.tactic, &r.times, &r.sampleID) == nil {
				topRows = append(topRows, r)
				if r.sampleID != nil {
					sampleIDs = append(sampleIDs, *r.sampleID)
				}
			}
		}
		trows.Close()
	}

	// Bulk-fetch best bypass details for label construction.
	type bpDetail struct{ enc, execCtx, priv string }
	bpDetails := map[string]bpDetail{}
	if len(sampleIDs) > 0 {
		phs := make([]string, len(sampleIDs))
		args := make([]any, len(sampleIDs))
		for i, id := range sampleIDs {
			phs[i] = fmt.Sprintf("$%d", i+1)
			args[i] = id
		}
		brows, berr := h.db.Query(ctx,
			`SELECT id, encoding, execution_context, privilege
			   FROM scenario_variant_results WHERE id IN (`+strings.Join(phs, ",")+`)`,
			args...,
		)
		if berr == nil {
			defer brows.Close()
			for brows.Next() {
				var id, enc, execCtx, priv string
				if brows.Scan(&id, &enc, &execCtx, &priv) == nil {
					bpDetails[id] = bpDetail{enc, execCtx, priv}
				}
			}
		}
	}

	type campTopBypass struct {
		TechniqueID      string `json:"techniqueId"`
		TechniqueName    string `json:"techniqueName"`
		Tactic           string `json:"tactic"`
		TimesObserved    int    `json:"timesObserved"`
		MostCommonBypass string `json:"mostCommonBypass"`
	}
	topBypasses := make([]campTopBypass, 0, len(topRows))
	for _, r := range topRows {
		label := ""
		if r.sampleID != nil {
			if d, ok := bpDetails[*r.sampleID]; ok {
				label = campBypassLabel(d.enc, d.execCtx, d.priv)
			}
		}
		topBypasses = append(topBypasses, campTopBypass{r.techID, r.techName, r.tactic, r.times, label})
	}

	// 3. Tactic risk breakdown.
	type campTacticRow struct {
		Tactic         string  `json:"tactic"`
		Tested         int     `json:"tested"`
		Bypassed       int     `json:"bypassed"`
		PreventionRate float64 `json:"preventionRate"`
		RiskLevel      string  `json:"riskLevel"`
	}
	var tacticBreakdown []campTacticRow

	tarows, terr := h.db.Query(ctx, `
		SELECT svt.tactic,
		       COUNT(DISTINCT svt.technique_id) AS tested,
		       SUM(CASE WHEN svt.bypassed > 0 THEN 1 ELSE 0 END) AS bypass_instances,
		       COALESCE(SUM(svt.blocked),0) AS blocked_sum,
		       COALESCE(SUM(svt.blocked + svt.detected + svt.logged + svt.bypassed),0) AS counted_sum
		  FROM scenario_variant_technique_summary svt
		  JOIN scenario_runs sr ON sr.id = svt.run_id
		 WHERE sr.campaign_id = $1 AND svt.tactic != ''
		 GROUP BY svt.tactic
		 ORDER BY bypass_instances DESC`, campaignID)
	if terr == nil {
		defer tarows.Close()
		for tarows.Next() {
			var tactic string
			var tested, bypassInst, blockedSum, countedSum int
			if tarows.Scan(&tactic, &tested, &bypassInst, &blockedSum, &countedSum) == nil {
				rate := 0.0
				if countedSum > 0 {
					rate = float64(blockedSum) / float64(countedSum) * 100
				}
				risk := "Low"
				if bypassInst >= 3 || rate < 80 {
					risk = "High"
				} else if bypassInst >= 1 || rate < 95 {
					risk = "Medium"
				}
				tacticBreakdown = append(tacticBreakdown, campTacticRow{tactic, tested, bypassInst, rate, risk})
			}
		}
	}

	// 4. Previous campaign's bypassed count for trend (same scenario, earlier start).
	var prevBypassed *int
	var pb int
	if err := h.db.QueryRow(ctx, `
		SELECT cvs.bypassed
		  FROM campaign_variant_summary cvs
		  JOIN campaigns c ON c.id = cvs.campaign_id
		 WHERE c.scenario_id = (SELECT scenario_id FROM campaigns WHERE id = $1)
		   AND c.started_at < (SELECT started_at FROM campaigns WHERE id = $1)
		 ORDER BY c.started_at DESC
		 LIMIT 1`, campaignID,
	).Scan(&pb); err == nil {
		prevBypassed = &pb
	}

	// 5. Serialize and upsert.
	topJSON, _ := json.Marshal(topBypasses)
	tacJSON, _ := json.Marshal(tacticBreakdown)

	h.db.Exec(ctx, `
		INSERT INTO campaign_variant_summary
		       (campaign_id, techniques_tested, variants_executed, blocked, detected, bypassed,
		        run_count, prevention_score, detection_score, top_bypasses, tactic_breakdown,
		        prev_bypassed, computed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
		ON CONFLICT (campaign_id) DO UPDATE SET
		    techniques_tested = EXCLUDED.techniques_tested,
		    variants_executed = EXCLUDED.variants_executed,
		    blocked           = EXCLUDED.blocked,
		    detected          = EXCLUDED.detected,
		    bypassed          = EXCLUDED.bypassed,
		    run_count         = EXCLUDED.run_count,
		    prevention_score  = EXCLUDED.prevention_score,
		    detection_score   = EXCLUDED.detection_score,
		    top_bypasses      = EXCLUDED.top_bypasses,
		    tactic_breakdown  = EXCLUDED.tactic_breakdown,
		    prev_bypassed     = EXCLUDED.prev_bypassed,
		    computed_at       = NOW()`,
		campaignID, techTested, varExec, blocked, detected, bypassed,
		runCount, prevScore, detScore, topJSON, tacJSON, prevBypassed,
	)
}

// campBypassLabel formats a bypass combination as "Charcode + WMI + Admin".
func campBypassLabel(enc, execCtx, priv string) string {
	var parts []string
	switch enc {
	case "base64":
		parts = append(parts, "Base64")
	case "charcode":
		parts = append(parts, "Charcode")
	}
	switch execCtx {
	case "wmi":
		parts = append(parts, "WMI")
	case "scheduled-task":
		parts = append(parts, "Schtasks")
	case "com":
		parts = append(parts, "COM")
	}
	switch priv {
	case "admin":
		parts = append(parts, "Admin")
	case "system":
		parts = append(parts, "System")
	}
	if len(parts) == 0 {
		return "Plain / Direct"
	}
	return strings.Join(parts, " + ")
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return math.Round(float64(n)/float64(total)*1000) / 10
}

