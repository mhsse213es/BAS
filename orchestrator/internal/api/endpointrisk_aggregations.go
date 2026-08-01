package api

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/endpointrisk"
	"github.com/audspect/bas/internal/models"
)

// filterByAsOf returns only the results executed at or before asOf --
// what makes computing the same aggregation "now" and "7 days ago" from one
// shared results fetch possible, the same idea as controlhealth's asOf
// parameter but applied to an already-fetched slice instead of a SQL WHERE.
func filterByAsOf(results []models.SimulationResult, asOf time.Time) []models.SimulationResult {
	out := make([]models.SimulationResult, 0, len(results))
	for _, r := range results {
		if !r.ExecutedAt.After(asOf) {
			out = append(out, r)
		}
	}
	return out
}

// complianceInput builds one CompliancePercent per loaded framework plus
// the real failed-control findings (with their existing remediation text),
// mirroring complianceRows (handlers.go:3734) but returning
// endpointrisk.ComplianceInput instead of report rows.
func (h *Handler) complianceInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.ComplianceInput {
	if h.complianceMapper == nil {
		return endpointrisk.ComplianceInput{}
	}
	results := filterByAsOf(allResults, asOf)
	pct := map[string]float64{}
	var findings []endpointrisk.Finding
	for _, fw := range h.complianceMapper.Frameworks() {
		cr, err := h.complianceMapper.GenerateReport(results, fw.ID, agentID, "", "")
		if err != nil {
			continue
		}
		pct[fw.Name] = cr.Summary.CompliancePercent
		for _, ctrl := range cr.Controls {
			if ctrl.Status != "fail" {
				continue
			}
			for _, ev := range ctrl.Evidence {
				if ev.Result != "fail" {
					continue
				}
				findings = append(findings, endpointrisk.Finding{
					Title:            ctrl.Name,
					Severity:         "High",
					Risk:             "Control " + ctrl.ID + " (" + ctrl.Category + ") failed validation.",
					AffectedStandard: fw.Name + " " + ctrl.ID,
					Remediation:      ev.Remediation,
				})
			}
		}
	}
	return endpointrisk.ComplianceInput{PercentByFramework: pct, FailedFindings: findings, Collected: len(pct) > 0}
}

// basReadinessInput aggregates pass rate, technique count, and last-run
// timestamp directly from the agent's own result history -- no new SQL
// query, reusing the exact same aggregateAgentResults call complianceInput
// already needs.
func (h *Handler) basReadinessInput(asOf time.Time, allResults []models.SimulationResult) endpointrisk.BASReadinessInput {
	results := filterByAsOf(allResults, asOf)
	var passed, failed int
	var lastAt *time.Time
	techSeen := map[string]bool{}
	for _, r := range results {
		if r.Result == models.ResultSkipped || r.Result == models.ResultError {
			continue
		}
		techSeen[r.Technique.ID] = true
		if r.Result == models.ResultPass || r.Result == models.ResultBlocked {
			passed++
		} else if r.Result == models.ResultFail {
			failed++
		}
		if lastAt == nil || r.ExecutedAt.After(*lastAt) {
			t := r.ExecutedAt
			lastAt = &t
		}
	}
	tested := passed + failed
	if tested == 0 {
		return endpointrisk.BASReadinessInput{}
	}
	return endpointrisk.BASReadinessInput{
		TechniquesTested: len(techSeen),
		PassRate:         float64(passed) / float64(tested) * 100,
		LastExecutedAt:   lastAt,
		Collected:        true,
	}
}
