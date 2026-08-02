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

// postureCheckFindingText holds the static per-check_id copy (description,
// expected/observed values, remediation, reference) used to build a
// Finding without inventing anything from raw command output. Keyed by
// check_id; shared across Security Configuration and Identity since a
// check_id is unique across both categories.
var postureCheckFindingText = map[string]struct {
	Title, Description, Expected, Observed, Remediation, Reference string
}{
	"windows-firewall-enabled":            {"Windows Firewall disabled", "Windows Firewall must be enabled for the Domain, Private, and Public profiles.", "Enabled", "Disabled", "Enable Windows Firewall for all profiles.", "Microsoft Security Baseline"},
	"windows-defender-realtime":           {"Defender real-time protection disabled", "Windows Defender's real-time protection must be active.", "Enabled", "Disabled", "Enable Windows Defender real-time protection.", "Microsoft Security Baseline"},
	"windows-bitlocker-enabled":           {"BitLocker not enabled", "The system volume should be encrypted with BitLocker.", "On", "Off", "Enable BitLocker on the system volume.", "CIS Microsoft Windows Benchmark"},
	"windows-rdp-nla-required":            {"RDP exposed without NLA", "RDP, if enabled, must require Network Level Authentication.", "Disabled or NLA required", "Enabled without NLA", "Disable RDP or require NLA.", "CIS Microsoft Windows Benchmark"},
	"windows-smbv1-disabled":              {"SMBv1 enabled", "The legacy, vulnerable SMBv1 protocol must be disabled.", "Disabled", "Enabled", "Disable the SMB1Protocol Windows feature.", "Microsoft Security Baseline"},
	"windows-guest-account-disabled":      {"Guest account enabled", "The built-in Guest account must be disabled.", "Disabled", "Enabled", "Disable the local Guest account.", "CIS Microsoft Windows Benchmark"},
	"windows-local-admin-count":           {"Excess local administrators", "Local Administrators group membership should be minimal.", "<= 2 members", "> 2 members", "Review and remove unnecessary local administrator accounts.", "CIS Microsoft Windows Benchmark"},
	"windows-password-min-length":         {"Weak minimum password length", "Minimum password length should be at least 12 characters.", ">= 12", "< 12", "Increase the minimum password length to 12+.", "CIS Microsoft Windows Benchmark"},
	"windows-password-max-age":            {"Password max age out of policy", "Maximum password age should be 90 days or fewer.", "1-90 days", "Out of range", "Set maximum password age to 90 days or fewer.", "CIS Microsoft Windows Benchmark"},
	"windows-account-lockout-threshold":   {"Account lockout threshold not configured", "Account lockout threshold should be between 1 and 10 attempts.", "1-10", "Not configured", "Configure an account lockout threshold.", "CIS Microsoft Windows Benchmark"},
	"linux-firewall-enabled":              {"UFW firewall not confirmed active", "The UFW firewall should be active.", "active", "inactive", "Enable UFW (ufw enable).", "CIS Ubuntu Benchmark"},
	"linux-apparmor-enabled":              {"AppArmor not enforcing", "AppArmor should be enabled and enforcing.", "enforcing", "not enforcing", "Enable and enforce AppArmor profiles.", "CIS Ubuntu Benchmark"},
	"linux-ssh-root-login-disabled":       {"SSH root login permitted", "SSH root login should be disabled.", "PermitRootLogin no", "permitted", "Set PermitRootLogin no in sshd_config.", "CIS Ubuntu Benchmark"},
	"linux-ssh-empty-passwords-forbidden": {"SSH empty passwords permitted", "SSH must not allow empty passwords.", "PermitEmptyPasswords no", "permitted", "Set PermitEmptyPasswords no in sshd_config.", "CIS Ubuntu Benchmark"},
	"linux-password-min-length":           {"Weak minimum password length", "Minimum password length should be at least 12 characters.", ">= 12", "< 12", "Set PASS_MIN_LEN 12 in /etc/login.defs.", "CIS Ubuntu Benchmark"},
	"linux-password-max-age":              {"Password max age out of policy", "Maximum password age should be 365 days or fewer.", "<= 365", "> 365", "Set PASS_MAX_DAYS 365 in /etc/login.defs.", "CIS Ubuntu Benchmark"},
	"linux-no-empty-password-accounts":    {"Accounts with empty passwords found", "No account should have an empty password.", "none", "one or more found", "Set a password or lock the affected account(s).", "CIS Ubuntu Benchmark"},
}

// postureCheckInput aggregates Security Configuration or Identity evidence
// (selected by category, a taxonomy category string) from allResults: the
// most recent result per check_id (asOf-filtered) determines that check's
// current pass/fail state; Score is a weighted pass rate using each
// check's taxonomy weight; LastPassed scans full history (still asOf-
// filtered) for that check_id's most recent pass, independent of what the
// latest result is.
func (h *Handler) postureCheckInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult, category string) endpointrisk.PostureCheckInput {
	if h.endpointRiskTaxonomy == nil {
		return endpointrisk.PostureCheckInput{}
	}
	results := filterByAsOf(allResults, asOf)

	type latest struct {
		result     models.SimulationResult
		lastPassed *time.Time
	}
	byCheck := map[string]*latest{}
	for _, r := range results {
		if r.CheckID == "" {
			continue
		}
		cat, _, ok := h.endpointRiskTaxonomy.CategoryForCheck(r.CheckID)
		if !ok || cat != category {
			continue
		}
		l, exists := byCheck[r.CheckID]
		if !exists {
			l = &latest{}
			byCheck[r.CheckID] = l
		}
		if r.Result == models.ResultPass {
			t := r.ExecutedAt
			if l.lastPassed == nil || t.After(*l.lastPassed) {
				l.lastPassed = &t
			}
		}
		if l.result.ID == "" || r.ExecutedAt.After(l.result.ExecutedAt) {
			l.result = r
		}
	}

	if len(byCheck) == 0 {
		return endpointrisk.PostureCheckInput{}
	}

	var passed, failed int
	var weightedPassed, weightedTotal float64
	var findings []endpointrisk.Finding
	for checkID, l := range byCheck {
		_, weight, _ := h.endpointRiskTaxonomy.CategoryForCheck(checkID)
		weightedTotal += weight
		if l.result.Result == models.ResultPass {
			passed++
			weightedPassed += weight
			continue
		}
		failed++
		text := postureCheckFindingText[checkID]
		observedAt := l.result.ExecutedAt
		findings = append(findings, endpointrisk.Finding{
			ID: checkID, Title: text.Title, Description: text.Description,
			Severity: "Medium", Risk: text.Description,
			Remediation: text.Remediation, Reference: text.Reference,
			Expected: text.Expected, Observed: text.Observed,
			Passed: false, LastObserved: &observedAt, LastPassed: l.lastPassed,
		})
	}

	score := 0
	if weightedTotal > 0 {
		score = int(weightedPassed/weightedTotal*100 + 0.5)
	}
	return endpointrisk.PostureCheckInput{
		Score: score, Passed: passed, Failed: failed, Total: passed + failed,
		Findings: findings, Collected: true,
	}
}

func (h *Handler) securityConfigInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.PostureCheckInput {
	return h.postureCheckInput(ctx, agentID, asOf, allResults, "security-configuration")
}

func (h *Handler) identityInput(ctx context.Context, agentID string, asOf time.Time, allResults []models.SimulationResult) endpointrisk.PostureCheckInput {
	return h.postureCheckInput(ctx, agentID, asOf, allResults, "identity")
}
