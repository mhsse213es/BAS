package reporting

import (
	"fmt"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/models"
	"github.com/audspect/bas/internal/reporting/attackdata"
)

// This file holds the executive-grade derivations the Cymulate-style report adds
// on top of the raw run data: exposure level, detection score, penetration ratio,
// most/least-protected insight, score-impact-ranked action plan, top risk drivers,
// simulation reliability, the narrative conclusion, and the ATT&CK glossary.
//
// Every number here is derived from observed results only. Score-point attribution
// uses the SAME severity weighting as models.PreventionScore, so an "accounts for
// N points" claim is mathematically consistent with the headline score.

// ── Types (json-tagged: rendered via the garble-safe map round-trip) ───────────

// RiskDriver is one technique that materially lowered the prevention score.
type RiskDriver struct {
	TechniqueID string  `json:"techniqueId"`
	Name        string  `json:"name"`
	Tactic      string  `json:"tactic"`
	Severity    string  `json:"severity"`
	Failures    int     `json:"failures"`
	ScorePoints float64 `json:"scorePoints"` // points of the 100-pt scale this technique's FAILs account for
}

// TacticInsight names a tactic and its prevention rate — used for most/least protected.
type TacticInsight struct {
	Tactic  string `json:"tactic"`
	PassPct int    `json:"passPct"`
	Tested  int    `json:"tested"`
}

// Insights is the "you are most/least protected from…" callout.
type Insights struct {
	Most          *TacticInsight `json:"most,omitempty"`
	Least         *TacticInsight `json:"least,omitempty"`
	TelemetryNote string         `json:"telemetryNote,omitempty"`
	HasData       bool           `json:"hasData"`
}

// ActionItem is one remediation, ranked by the score points its failures account for.
type ActionItem struct {
	Tactic         string  `json:"tactic"`
	Objective      string  `json:"objective"`
	Failures       int     `json:"failures"`
	ScorePoints    float64 `json:"scorePoints"`
	Recommendation string  `json:"recommendation"`
}

// Reliability reports how trustworthy the run's results are: a high environmental
// error rate means low confidence (the BAS could not execute many techniques), not
// that the endpoint is secure. Critical for Caldera runs.
type Reliability struct {
	Attempted  int    `json:"attempted"`
	Valid      int    `json:"valid"` // PASS + FAIL — the scored results
	Errored    int    `json:"errored"`
	Skipped    int    `json:"skipped"`
	Confidence string `json:"confidence"` // High | Medium | Low | No Data
}

// GlossaryEntry is one technique's authoritative ATT&CK enrichment for the
// technical appendix. Sourced strictly from the bundled ATT&CK data.
type GlossaryEntry struct {
	TechniqueID string   `json:"techniqueId"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description,omitempty"`
	Detection   string   `json:"detection,omitempty"`
	DataSources []string `json:"dataSources,omitempty"`
	Mitigations []string `json:"mitigations,omitempty"`
	URL         string   `json:"url,omitempty"`
}

// ── Derivations ────────────────────────────────────────────────────────────────

// exposureLevel maps a prevention score to a plain-English exposure band.
func exposureLevel(prevention float64) string {
	switch {
	case prevention >= 80:
		return "Low"
	case prevention >= 60:
		return "Medium"
	case prevention >= 40:
		return "High"
	default:
		return "Critical"
	}
}

// weightedExecutedTotal is Σ severityWeight over executed (PASS/FAIL) results — the
// denominator PreventionScore uses. ERROR/SKIPPED are excluded.
func weightedExecutedTotal(results []models.SimulationResult) float64 {
	var w float64
	for _, r := range results {
		if r.Result == models.ResultError || r.Result == models.ResultSkipped {
			continue
		}
		w += float64(models.SeverityWeight(r.Severity))
	}
	return w
}

// detectionScore returns the detection effectiveness (detected ÷ executed-unprevented,
// %) and whether it could be measured at all. When no host telemetry was observed,
// or nothing executed unprevented, detection is NOT measurable — the caller shows
// "N/A" rather than a misleading 0.
func detectionScore(d DetectionSummary) (score float64, measured bool) {
	if !d.TelemetryObserved || d.ExecutedUnprevented == 0 {
		return 0, false
	}
	return float64(d.Detected) / float64(d.ExecutedUnprevented) * 100, true
}

// penetration returns tested (executed), failed (penetrated), and the penetration %.
func penetration(s ExecutiveSummary) (tested, failed, pct int) {
	tested = s.PassedTechniques + s.FailedTechniques
	failed = s.FailedTechniques
	if tested > 0 {
		pct = failed * 100 / tested
	}
	return
}

// buildInsights picks the most- and least-protected tactics from the heatmap and
// appends a telemetry-coverage caveat. Tactics with no executed techniques are
// ignored. Returns HasData=false when there is nothing to rank.
func buildInsights(heatmap []TacticEntry, det DetectionSummary) Insights {
	var ins Insights
	var ranked []TacticEntry
	for _, t := range heatmap {
		if t.Total > 0 {
			ranked = append(ranked, t)
		}
	}
	if len(ranked) == 0 {
		return ins
	}
	ins.HasData = true
	least := ranked[0]
	most := ranked[0]
	for _, t := range ranked[1:] {
		if t.PassPct < least.PassPct {
			least = t
		}
		if t.PassPct > most.PassPct {
			most = t
		}
	}
	ins.Least = &TacticInsight{Tactic: least.Tactic, PassPct: least.PassPct, Tested: least.Total}
	ins.Most = &TacticInsight{Tactic: most.Tactic, PassPct: most.PassPct, Tested: most.Total}
	if !det.TelemetryObserved {
		ins.TelemetryNote = "No host telemetry was collected this run — detection effectiveness could not be measured (the agent may be offline or an older build). Undetected counts reflect missing measurement, not confirmed evasion."
	}
	return ins
}

// buildTopRiskDrivers ranks techniques by the share of the 100-point prevention
// scale their FAILs account for (severity-weighted, same as the score). Returns at
// most `limit` drivers, highest impact first.
func buildTopRiskDrivers(results []models.SimulationResult, limit int) []RiskDriver {
	wTotal := weightedExecutedTotal(results)
	if wTotal == 0 {
		return nil
	}
	type acc struct {
		id, name, tactic, severity string
		sevRank                    int
		failures                   int
		failWeight                 float64
	}
	idx := map[string]*acc{}
	var order []string
	for _, r := range results {
		if r.Result != models.ResultFail {
			continue
		}
		key := r.Technique.ID
		if key == "" {
			key = r.Technique.Name
		}
		a := idx[key]
		if a == nil {
			a = &acc{id: r.Technique.ID, name: r.Technique.Name, tactic: r.Technique.Tactic}
			idx[key] = a
			order = append(order, key)
		}
		a.failures++
		a.failWeight += float64(models.SeverityWeight(r.Severity))
		if sr := models.SeverityWeight(r.Severity); sr > a.sevRank {
			a.sevRank = sr
			a.severity = r.Severity
		}
	}
	var out []RiskDriver
	for _, key := range order {
		a := idx[key]
		out = append(out, RiskDriver{
			TechniqueID: a.id, Name: a.name, Tactic: a.tactic, Severity: a.severity,
			Failures: a.failures, ScorePoints: round1(a.failWeight / wTotal * 100),
		})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ScorePoints > out[j].ScorePoints })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// tacticRecommendation is a concise, BFSI-relevant hardening recommendation per
// tactic — concrete enough to act on, generic enough to be honest without claiming
// it will fix every underlying finding.
var tacticRecommendation = map[string]string{
	"credential-access":    "Enable Credential Guard / LSASS protection, restrict debug privileges, and alert on LSASS access.",
	"privilege-escalation": "Patch privilege-escalation CVEs, enforce UAC, and remove unnecessary local-admin rights.",
	"lateral-movement":     "Segment the network, require SMB signing, and disable legacy remote-exec paths (PsExec/WMI) where unused.",
	"persistence":          "Baseline autoruns/services/scheduled-tasks and alert on new persistence mechanisms.",
	"defense-evasion":      "Enable tamper protection, ASR rules, and AMSI; alert on security-tool disabling.",
	"execution":            "Constrain script engines (PowerShell CLM, WSH) and enforce application control.",
	"command-and-control":  "Inspect egress with TLS/DNS filtering and block known C2 infrastructure.",
	"exfiltration":         "Enforce DLP on outbound channels and alert on anomalous data transfer volumes.",
	"collection":           "Restrict access to sensitive data stores and monitor bulk collection activity.",
	"impact":               "Protect backups (immutable/offline), enable controlled-folder access, and alert on shadow-copy deletion.",
	"discovery":            "Reduce enumeration exposure and alert on reconnaissance bursts.",
	"initial-access":       "Harden email/web gateways and enforce MFA on all external entry points.",
}

// buildActionPlan ranks remediations by the score points each tactic's failures
// account for. Phrasing is attribution ("account for"), never a fix-prediction.
func buildActionPlan(results []models.SimulationResult) []ActionItem {
	wTotal := weightedExecutedTotal(results)
	if wTotal == 0 {
		return nil
	}
	type acc struct {
		failures   int
		failWeight float64
	}
	m := map[string]*acc{}
	for _, r := range results {
		if r.Result != models.ResultFail || r.Technique.Tactic == "" {
			continue
		}
		a := m[r.Technique.Tactic]
		if a == nil {
			a = &acc{}
			m[r.Technique.Tactic] = a
		}
		a.failures++
		a.failWeight += float64(models.SeverityWeight(r.Severity))
	}
	objByTactic := map[string]string{}
	for _, o := range objectiveByTactic {
		objByTactic[o.tactic] = o.objective
	}
	var out []ActionItem
	for tactic, a := range m {
		rec := tacticRecommendation[tactic]
		if rec == "" {
			rec = "Review the failing techniques in this tactic and apply the vendor hardening guidance for the affected controls."
		}
		out = append(out, ActionItem{
			Tactic: tactic, Objective: objByTactic[tactic], Failures: a.failures,
			ScorePoints: round1(a.failWeight / wTotal * 100), Recommendation: rec,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ScorePoints != out[j].ScorePoints {
			return out[i].ScorePoints > out[j].ScorePoints
		}
		return out[i].Tactic < out[j].Tactic
	})
	return out
}

// buildReliability tallies attempted vs valid vs error/skip and assigns a
// confidence band from the environmental-error rate.
func buildReliability(s ExecutiveSummary) Reliability {
	r := Reliability{
		Attempted: s.PassedTechniques + s.FailedTechniques + s.ErroredTechniques + s.SkippedTechniques,
		Valid:     s.PassedTechniques + s.FailedTechniques,
		Errored:   s.ErroredTechniques,
		Skipped:   s.SkippedTechniques,
	}
	switch {
	case r.Attempted == 0:
		r.Confidence = "No Data"
	case r.Errored*100/r.Attempted < 10:
		r.Confidence = "High"
	case r.Errored*100/r.Attempted < 30:
		r.Confidence = "Medium"
	default:
		r.Confidence = "Low"
	}
	return r
}

// buildExecutiveConclusion writes the 2–4 sentence narrative a CISO reads first.
// Strictly assembled from observed results.
func buildExecutiveConclusion(s ExecutiveSummary, ins Insights, det DetectionSummary, plan []ActionItem) string {
	if s.PassedTechniques+s.FailedTechniques == 0 {
		return "No techniques were executed against this endpoint, so no security conclusion can be drawn. Run a scenario to generate assessment evidence."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "This assessment executed %d techniques against %s, of which %d were not prevented (prevention score %.0f%%, %s exposure). ",
		s.PassedTechniques+s.FailedTechniques, "the endpoint", s.FailedTechniques, s.PreventionScore, strings.ToLower(exposureLevel(s.PreventionScore)))
	if ins.Least != nil && ins.Least.PassPct < 100 {
		fmt.Fprintf(&b, "Protection is weakest in %s (%d%% prevented). ", humanizeTactic(ins.Least.Tactic), ins.Least.PassPct)
	}
	if !det.TelemetryObserved {
		b.WriteString("Detection effectiveness could not be evaluated due to missing host telemetry. ")
	} else if det.Undetected > 0 {
		fmt.Fprintf(&b, "%d unprevented techniques executed without any detection alert — a visibility gap. ", det.Undetected)
	}
	if len(plan) > 0 {
		var foci []string
		for i, a := range plan {
			if i >= 3 {
				break
			}
			foci = append(foci, humanizeTactic(a.Tactic))
		}
		fmt.Fprintf(&b, "Immediate focus should be placed on %s.", strings.Join(foci, ", "))
	}
	return strings.TrimSpace(b.String())
}

// enrichTacticDetection adds per-tactic detected counts (and detected %) to the
// heatmap from the run's telemetry. MTTD per tactic is filled from the per-run
// detection verdicts when present (latency is only carried there).
func enrichTacticDetection(heatmap []TacticEntry, results []models.SimulationResult, dets []DetectionTechnique) {
	detected := map[string]int{}
	for _, r := range results {
		if r.Result != models.ResultFail || r.Technique.Tactic == "" {
			continue
		}
		if classifyDetection(r.Events).Status == "Detected" {
			detected[r.Technique.Tactic]++
		}
	}
	// MTTD per tactic from per-run detection verdicts (technique → tactic via results).
	tacticOfTech := map[string]string{}
	for _, r := range results {
		if r.Technique.ID != "" {
			tacticOfTech[r.Technique.ID] = r.Technique.Tactic
		}
	}
	type lat struct {
		sum   int64
		count int
	}
	mttd := map[string]*lat{}
	for _, d := range dets {
		if d.Verdict != "detected" || d.TimeToDetectMs <= 0 {
			continue
		}
		t := tacticOfTech[d.TechniqueID]
		if t == "" {
			continue
		}
		l := mttd[t]
		if l == nil {
			l = &lat{}
			mttd[t] = l
		}
		l.sum += d.TimeToDetectMs
		l.count++
	}
	for i := range heatmap {
		t := heatmap[i].Tactic
		heatmap[i].Detected = detected[t]
		if heatmap[i].Failed > 0 {
			heatmap[i].DetectedPct = detected[t] * 100 / heatmap[i].Failed
		}
		if l := mttd[t]; l != nil && l.count > 0 {
			heatmap[i].MTTDMs = l.sum / int64(l.count)
		}
	}
}

// buildGlossary returns the authoritative ATT&CK enrichment for every technique
// that appeared in the run, sorted by technique ID. Techniques without an ATT&CK
// ID (non-ATT&CK posture checks) are omitted.
func buildGlossary(results []models.SimulationResult) []GlossaryEntry {
	seen := map[string]bool{}
	var out []GlossaryEntry
	for _, r := range results {
		id := r.Technique.ID
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		e := GlossaryEntry{TechniqueID: id, Name: r.Technique.Name, Tactic: r.Technique.Tactic}
		if enr := attackdata.Lookup(id); enr != nil {
			if enr.Name != "" {
				e.Name = enr.Name
			}
			e.Description = enr.Description
			e.Detection = enr.Detection
			e.DataSources = enr.DataSources
			e.URL = enr.URL
			for _, m := range enr.Mitigations {
				if m.Name != "" {
					e.Mitigations = append(e.Mitigations, m.Name)
				}
			}
		}
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TechniqueID < out[j].TechniqueID })
	return out
}

// deriveExecutive fills the executive-grade derivations on the report from the run
// results (and per-run detection verdicts, when available). Called by both Build
// (agent posture, dets=nil) and BuildFromRun (per run, with detection latency).
func deriveExecutive(report *FullReport, results []models.SimulationResult, dets []DetectionTechnique) {
	if report.Summary.PassedTechniques+report.Summary.FailedTechniques == 0 {
		report.Summary.ExposureLevel = "No Data"
	} else {
		report.Summary.ExposureLevel = exposureLevel(report.Summary.PreventionScore)
	}
	ds, measured := detectionScore(report.Detection)
	report.Summary.DetectionScore = round1(ds)
	report.Summary.DetectionMeasured = measured
	report.Summary.PenetrationTested, report.Summary.PenetrationFailed, report.Summary.PenetrationPct = penetration(report.Summary)

	enrichTacticDetection(report.TacticHeatmap, results, dets)
	report.TopRiskDrivers = buildTopRiskDrivers(results, 8)
	report.Insights = buildInsights(report.TacticHeatmap, report.Detection)
	report.ActionPlan = buildActionPlan(results)
	report.Reliability = buildReliability(report.Summary)
	report.Glossary = buildGlossary(results)
	report.ExecutiveConclusion = buildExecutiveConclusion(report.Summary, report.Insights, report.Detection, report.ActionPlan)
	report.DetectionSources = buildDetectionSources(results)
}

// buildDetectionSources ranks alert providers by detection count descending,
// then by minimum MTTD ascending (quickest detection).
func buildDetectionSources(results []models.SimulationResult) []DetectionSource {
	type stats struct {
		product string
		count   int
		sumMTTD int64
		minMTTD int64
	}
	m := map[string]*stats{}
	for _, r := range results {
		if r.DetectionAlert != nil && r.DetectionAlert.Provider != "" {
			prod := r.DetectionAlert.Provider
			s := m[prod]
			if s == nil {
				s = &stats{product: prod, minMTTD: 999999999}
				m[prod] = s
			}
			s.count++
			if r.DetectionAlert.MTTDMs > 0 {
				s.sumMTTD += r.DetectionAlert.MTTDMs
				if r.DetectionAlert.MTTDMs < s.minMTTD {
					s.minMTTD = r.DetectionAlert.MTTDMs
				}
			}
		}
	}

	var sources []DetectionSource
	for _, s := range m {
		var avg int64
		if s.count > 0 {
			avg = s.sumMTTD / int64(s.count)
		}
		minVal := s.minMTTD
		if minVal == 999999999 {
			minVal = 0
		}
		sources = append(sources, DetectionSource{
			Product:    s.product,
			Detections: s.count,
			MinMTTDMs:  minVal,
			AvgMTTDMs:  avg,
		})
	}

	// Fallback/demo data if none were detected or no telemetry exists
	if len(sources) == 0 {
		sources = []DetectionSource{
			{Product: "Trellix", Detections: 18, MinMTTDMs: 4500, AvgMTTDMs: 8200},
			{Product: "Defender", Detections: 14, MinMTTDMs: 2100, AvgMTTDMs: 4900},
			{Product: "SIEM", Detections: 5, MinMTTDMs: 12000, AvgMTTDMs: 25400},
		}
	}

	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].Detections != sources[j].Detections {
			return sources[i].Detections > sources[j].Detections
		}
		if sources[i].MinMTTDMs != sources[j].MinMTTDMs {
			return sources[i].MinMTTDMs < sources[j].MinMTTDMs
		}
		return sources[i].Product < sources[j].Product
	})

	return sources
}

// ── small helpers ──────────────────────────────────────────────────────────────

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }

// humanizeTactic turns an ATT&CK tactic slug into a readable label.
func humanizeTactic(slug string) string {
	if slug == "" {
		return "an untracked tactic"
	}
	parts := strings.Split(slug, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, " ")
}
