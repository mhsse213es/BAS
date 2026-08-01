package controlhealth

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Overall Health states.
const (
	HealthHealthy            = "Healthy"
	HealthPartiallyValidated = "PartiallyValidated"
	HealthDegraded           = "Degraded"
	HealthCritical           = "Critical"
	HealthUnknown            = "Unknown"
)

// HealthUnknownVerdict is the per-stream (prevention/detection) verdict used
// when a category has zero evidence for that stream -- distinct from
// HealthUnknown, which is the *Overall* health state.
const HealthUnknownVerdict = "unknown"

// Coverage thresholds (percent). Below coverageUnknownFloor there isn't
// enough evidence to claim anything; at/above coverageHealthyFloor with a
// passing prevention verdict, the category reads as Healthy rather than
// PartiallyValidated. Proposed V1 defaults -- see the design spec's open
// question before tuning these against real fleet data.
const (
	coverageUnknownFloor = 20
	coverageHealthyFloor = 70
)

// CategoryHealth is the computed, evidence-backed health of one control
// category -- the shape the /api/controlhealth/summary endpoint returns.
type CategoryHealth struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	PreventionHealth    string     `json:"preventionHealth"` // pass | fail | unknown
	DetectionHealth     string     `json:"detectionHealth"`  // pass | fail | unknown
	OverallHealth       string     `json:"overallHealth"`
	Coverage            int        `json:"coverage"` // 0-100
	ValidatedTechniques int        `json:"validatedTechniques"`
	MappedTechniques    int        `json:"mappedTechniques"`
	EvidenceCount       int        `json:"evidenceCount"`
	Trend               string     `json:"trend"` // Improving | Stable | Declining | InsufficientData
	LastValidated       *time.Time `json:"lastValidated,omitempty"`
}

// ComputeSummary is the package's single exported entry point: it loads all
// evidence once (within windowDays) and computes every category's current
// health plus a 7-day trend from it -- two DB round trips total, regardless
// of category count.
func ComputeSummary(ctx context.Context, pool *pgxpool.Pool, mapper *Mapper, windowDays int) ([]CategoryHealth, error) {
	since := time.Now().UTC().AddDate(0, 0, -windowDays)
	prevRows, err := loadPreventionEvidence(ctx, pool, since)
	if err != nil {
		return nil, fmt.Errorf("controlhealth: load prevention evidence: %w", err)
	}
	detRows, err := loadDetectionEvidence(ctx, pool, since)
	if err != nil {
		return nil, fmt.Errorf("controlhealth: load detection evidence: %w", err)
	}

	now := time.Now().UTC()
	weekAgo := now.AddDate(0, 0, -7)
	cats := mapper.Categories()
	out := make([]CategoryHealth, 0, len(cats))
	for _, cat := range cats {
		techs := mapper.PrimaryTechniques(cat.ID)
		current := computeCategoryHealth(cat, techs, prevRows, detRows, now)
		past := computeCategoryHealth(cat, techs, prevRows, detRows, weekAgo)
		current.Trend = computeTrend(current.OverallHealth, past.OverallHealth)
		out = append(out, current)
	}
	return out, nil
}

// computeCategoryHealth is pure -- no I/O -- so it and everything it calls
// is unit-testable without a database (see health_test.go). asOf lets the
// same evidence rows serve both the "now" and "7-days-ago" computations
// ComputeSummary needs for trend.
func computeCategoryHealth(cat CategoryDef, techs []string, prevRows, detRows []evidenceRow, asOf time.Time) CategoryHealth {
	prevVerdict, validated, prevCount, prevLast := aggregate(prevRows, techs, asOf)
	detVerdict, _, detCount, detLast := aggregate(detRows, techs, asOf)

	mapped := len(techs)
	coverage := 0
	if mapped > 0 {
		coverage = validated * 100 / mapped
	}

	last := prevLast
	if detLast != nil && (last == nil || detLast.After(*last)) {
		last = detLast
	}

	return CategoryHealth{
		ID:                  cat.ID,
		Name:                cat.Name,
		PreventionHealth:    prevVerdict,
		DetectionHealth:     detVerdict,
		OverallHealth:       overallHealth(prevVerdict, detVerdict, coverage),
		Coverage:            coverage,
		ValidatedTechniques: validated,
		MappedTechniques:    mapped,
		EvidenceCount:       prevCount + detCount,
		LastValidated:       last,
	}
}

// aggregate rolls up rows for the given technique set as of asOf: weakest
// link across each technique's most recent result (any fail -> category
// fails; pass only if every technique with a result passed), plus total
// evidence count and the most recent timestamp, both scoped to techs and to
// at-or-before asOf.
func aggregate(rows []evidenceRow, techs []string, asOf time.Time) (verdict string, validated, count int, lastAt *time.Time) {
	techSet := make(map[string]bool, len(techs))
	for _, t := range techs {
		techSet[t] = true
	}

	latest := make(map[string]evidenceRow)
	for _, row := range rows {
		if !techSet[row.TechniqueID] || row.At.After(asOf) {
			continue
		}
		count++
		if lastAt == nil || row.At.After(*lastAt) {
			t := row.At
			lastAt = &t
		}
		if cur, ok := latest[row.TechniqueID]; !ok || row.At.After(cur.At) {
			latest[row.TechniqueID] = row
		}
	}

	validated = len(latest)
	if validated == 0 {
		return HealthUnknownVerdict, 0, count, lastAt
	}
	verdict = "pass"
	for _, r := range latest {
		if r.Verdict == "fail" {
			verdict = "fail"
			break
		}
	}
	return verdict, validated, count, lastAt
}

// overallHealth applies the coverage-gated table: a passing prevention
// verdict only reads as Healthy once coverage clears coverageHealthyFloor;
// below coverageUnknownFloor there's too little evidence to say anything.
// The one cell the design spec's table didn't define -- prevention fail,
// detection unknown (never verified either way) -- is treated as Degraded,
// not Critical: "never verified" is worse than a confirmed-working
// detection, but better than a confirmed-failing one.
func overallHealth(prevention, detection string, coverage int) string {
	switch {
	case prevention == HealthUnknownVerdict:
		return HealthUnknown
	case coverage < coverageUnknownFloor:
		return HealthUnknown
	case prevention == "pass":
		if coverage >= coverageHealthyFloor {
			return HealthHealthy
		}
		return HealthPartiallyValidated
	case prevention == "fail" && detection == "pass":
		return HealthDegraded
	case prevention == "fail" && detection == "fail":
		return HealthCritical
	default: // prevention == "fail", detection == "unknown"
		return HealthDegraded
	}
}

// rankHealth orders Overall Health states best-to-worst for trend
// comparison; Unknown ranks below every real state (-1) so InsufficientData
// is always chosen instead of a misleading Improving/Declining.
func rankHealth(h string) int {
	switch h {
	case HealthHealthy:
		return 3
	case HealthPartiallyValidated:
		return 2
	case HealthDegraded:
		return 1
	case HealthCritical:
		return 0
	default:
		return -1
	}
}

// computeTrend compares Overall Health state, not raw pass-rate -- a
// pass-rate wobble inside a state that stays Critical must not read as
// Improving.
func computeTrend(current, past string) string {
	cr, pr := rankHealth(current), rankHealth(past)
	if cr < 0 || pr < 0 {
		return "InsufficientData"
	}
	switch {
	case cr > pr:
		return "Improving"
	case cr < pr:
		return "Declining"
	default:
		return "Stable"
	}
}
