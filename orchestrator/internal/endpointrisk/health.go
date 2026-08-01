package endpointrisk

import (
	"github.com/audspect/bas/internal/exposure"
)

// Category IDs -- used both for the 5 collected categories (real score) and
// the 4 not-yet-collected placeholders, in the fixed display order the
// design spec's category table lists.
const (
	CategoryExposureAttackPath = "exposure-attackpath"
	CategoryDetectionHealth    = "detection-health"
	CategoryVulnerabilities    = "vulnerabilities"
	CategoryCompliance         = "compliance"
	CategoryBASReadiness       = "bas-readiness"
	CategorySecurityConfig     = "security-configuration"
	CategoryIdentity           = "identity"
	CategoryPatchManagement    = "patch-management"
	CategoryApplicationRisk    = "application-risk"
)

var notYetCollectedCategories = []struct{ ID, Name string }{
	{CategorySecurityConfig, "Security Configuration"},
	{CategoryIdentity, "Identity"},
	{CategoryPatchManagement, "Patch Management"},
	{CategoryApplicationRisk, "Application Risk"},
}

// ComputeHealth is pure -- no I/O -- so every combination is unit-testable
// without a database. pastCompliance/pastBAS are the same two inputs
// recomputed with evidence filtered to 7 days ago by the caller (Task 3);
// exposure-derived categories have no past counterpart, per spec §6, so
// trend only ever reflects Compliance + BAS Readiness.
func ComputeHealth(agentID string, profile exposure.AssetExposureProfile, compliance ComplianceInput, bas BASReadinessInput, pastCompliance ComplianceInput, pastBAS BASReadinessInput) EndpointHealth {
	exposureAttackPath := CategoryScore{
		ID: CategoryExposureAttackPath, Name: "Exposure / Attack Path", Collected: true,
		Score: mean2(profile.Scores.ExposureScore, profile.Scores.AttackPathScore),
	}
	exposureAttackPath.Deficit = 100 - exposureAttackPath.Score
	exposureAttackPath.Findings = attackPathFindings(profile)

	detection := CategoryScore{
		ID: CategoryDetectionHealth, Name: "Detection Health", Collected: true,
		Score: profile.Scores.DetectionCoverageScore,
	}
	detection.Deficit = 100 - detection.Score
	detection.Findings = detectionFindings(profile)

	vulns := CategoryScore{
		ID: CategoryVulnerabilities, Name: "Vulnerabilities", Collected: true,
		Score: profile.Scores.VulnerabilityScore,
	}
	vulns.Deficit = 100 - vulns.Score
	vulns.Findings = vulnerabilityFindings(profile)

	compCat := CategoryScore{ID: CategoryCompliance, Name: "Compliance", Collected: compliance.Collected}
	if compliance.Collected {
		compCat.Score = round(meanOf(compliance.PercentByFramework))
		compCat.Deficit = 100 - compCat.Score
		compCat.Findings = compliance.FailedFindings
	}

	basCat := CategoryScore{ID: CategoryBASReadiness, Name: "BAS Readiness", Collected: bas.Collected}
	if bas.Collected {
		basCat.Score = round(bas.PassRate)
		basCat.Deficit = 100 - basCat.Score
		basCat.Findings = basReadinessFindings(bas)
	}

	categories := []CategoryScore{exposureAttackPath, detection, vulns, compCat, basCat}
	for _, c := range notYetCollectedCategories {
		categories = append(categories, CategoryScore{ID: c.ID, Name: c.Name, Collected: false})
	}

	collectedScores := []int{}
	for _, c := range categories {
		if c.Collected {
			collectedScores = append(collectedScores, c.Score)
		}
	}

	return EndpointHealth{
		AgentID:         agentID,
		HealthScore:     round(meanInts(collectedScores)),
		CriticalityRisk: profile.Scores.CriticalityRisk,
		Categories:      categories,
		ActionPlan:      buildActionPlan(categories),
		AttackPathChain: buildAttackPathChain(profile),
		Trend:           computeTrend(compliance, pastCompliance, bas, pastBAS),
	}
}

func mean2(a, b int) int { return (a + b) / 2 }

func round(f float64) int {
	if f < 0 {
		return 0
	}
	return int(f + 0.5)
}

func meanOf(m map[string]float64) float64 {
	if len(m) == 0 {
		return 0
	}
	var sum float64
	for _, v := range m {
		sum += v
	}
	return sum / float64(len(m))
}

func meanInts(vs []int) float64 {
	if len(vs) == 0 {
		return 0
	}
	var sum int
	for _, v := range vs {
		sum += v
	}
	return float64(sum) / float64(len(vs))
}

// buildActionPlan ranks the collected categories by deficit, worst first,
// and surfaces each one's single worst finding (first in its Findings
// slice -- callers are responsible for ordering Findings worst-first when
// they build them, matching how exposure/pathcorrelation already rank
// their own output).
func buildActionPlan(categories []CategoryScore) []ActionItem {
	var out []ActionItem
	for _, c := range categories {
		if !c.Collected || c.Deficit <= 0 || len(c.Findings) == 0 {
			continue
		}
		out = append(out, ActionItem{
			CategoryID: c.ID, CategoryName: c.Name, Deficit: c.Deficit, Finding: c.Findings[0],
		})
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Deficit > out[i].Deficit {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

func buildAttackPathChain(profile exposure.AssetExposureProfile) []AttackPathStep {
	var out []AttackPathStep
	for _, g := range profile.Recommendations {
		out = append(out, AttackPathStep{From: g.Edge.From, To: g.Edge.To, Kind: string(g.Edge.Kind), Reason: g.Reason})
	}
	return out
}

func attackPathFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	for _, g := range profile.Recommendations {
		out = append(out, Finding{
			Title:       string(g.Priority) + ": " + g.Edge.From + " -> " + g.Edge.To,
			Severity:    string(g.Priority),
			Risk:        g.Reason,
			Remediation: g.Remediation,
		})
	}
	return out
}

func detectionFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	if profile.Detection.Gap > 0 {
		out = append(out, Finding{
			Title: "Detection gap on this endpoint", Severity: "High",
			Risk:        "No detection rule fired for a technique known to threaten this asset.",
			Remediation: "Add or tune a detection rule for the affected technique(s).",
		})
	}
	if profile.Detection.Unknown > 0 {
		out = append(out, Finding{
			Title: "Unverified detection coverage", Severity: "Medium",
			Risk:        "No verification evidence exists either way for a technique threatening this asset.",
			Remediation: "Run a verification pass (Detection Validation) against the affected technique(s).",
		})
	}
	return out
}

func vulnerabilityFindings(profile exposure.AssetExposureProfile) []Finding {
	var out []Finding
	for _, v := range profile.Vulnerabilities {
		sev := "Medium"
		switch {
		case v.KEV || v.CVSS >= 9:
			sev = "Critical"
		case v.CVSS >= 7:
			sev = "High"
		}
		out = append(out, Finding{
			Title:       v.CVEID,
			Severity:    sev,
			Risk:        cveRiskNarrative(v),
			Remediation: "Update the affected software to a patched version.",
		})
	}
	// worst-first, so buildActionPlan's Findings[0] is the worst CVE
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if severityRank(out[j].Severity) > severityRank(out[i].Severity) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func severityRank(s string) int {
	switch s {
	case "Critical":
		return 3
	case "High":
		return 2
	case "Medium":
		return 1
	default:
		return 0
	}
}

func cveRiskNarrative(v exposure.CVEExposure) string {
	if v.KEV {
		return v.CVEID + " is listed in CISA's Known Exploited Vulnerabilities catalog -- active exploitation confirmed in the wild."
	}
	return v.CVEID + " (CVSS " + ftoa1(v.CVSS) + ") threatens this asset via a technique in its attack surface."
}

func ftoa1(f float64) string {
	// avoids importing strconv/fmt for one call site's simple 1-decimal format
	i := int(f*10 + 0.5)
	return itoa(i/10) + "." + itoa(i%10)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func basReadinessFindings(bas BASReadinessInput) []Finding {
	if bas.PassRate >= 90 {
		return nil
	}
	return []Finding{{
		Title: "Low BAS pass rate on this endpoint", Severity: "Medium",
		Risk:        "Simulations against this endpoint have been failing more than expected.",
		Remediation: "Review recent failed simulation results and address the underlying control gaps.",
	}}
}

// healthBand is a coarse Good/Fair/Poor grouping used only for trend
// comparison, the same "compare bands, not raw deltas" approach Control
// Health Foundation's computeTrend already uses -- a 1-point wobble inside
// "Poor" must not read as Improving.
func healthBand(score float64) int {
	switch {
	case score >= 80:
		return 2
	case score >= 50:
		return 1
	default:
		return 0
	}
}

// computeTrend reflects only Compliance + BAS Readiness (see spec §6);
// Exposure/Attack-Path/Detection Health have no past counterpart to compare.
func computeTrend(compliance, pastCompliance ComplianceInput, bas, pastBAS BASReadinessInput) string {
	if !compliance.Collected && !bas.Collected {
		return "InsufficientData"
	}
	if !pastCompliance.Collected && !pastBAS.Collected {
		return "InsufficientData"
	}
	current := trendInputScore(compliance, bas)
	past := trendInputScore(pastCompliance, pastBAS)
	cb, pb := healthBand(current), healthBand(past)
	switch {
	case cb > pb:
		return "Improving"
	case cb < pb:
		return "Declining"
	default:
		return "Stable"
	}
}

func trendInputScore(compliance ComplianceInput, bas BASReadinessInput) float64 {
	var sum, n float64
	if compliance.Collected {
		sum += meanOf(compliance.PercentByFramework)
		n++
	}
	if bas.Collected {
		sum += bas.PassRate
		n++
	}
	if n == 0 {
		return 0
	}
	return sum / n
}
