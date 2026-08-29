// Package slareport computes fleet-wide SLA compliance statistics from a
// list of finding_slas episodes. No I/O -- the API layer fetches the raw
// rows and calls ComputeReport once. Historical (resolved-episode) on-time/
// late classification is deliberately timestamp-based (deadline_at vs
// resolved_at, via slapolicy.EvaluateSLABreach) rather than status-based --
// TickSLABreaches only runs every 5 minutes, so status can lag the ground
// truth by up to that long.
package slareport

import (
	"time"

	"github.com/audspect/bas/internal/slapolicy"
)

// Episode is one finding_slas row's data relevant to reporting.
type Episode struct {
	Severity   string
	DeadlineAt time.Time
	Status     string // "active" | "breached" | "resolved"
	ResolvedAt *time.Time
}

// Stats is one bucket's aggregate numbers -- used for both the fleet-wide
// overall summary (Severity == "") and each per-severity row.
type Stats struct {
	Severity       string
	TotalEpisodes  int
	OnTime         int
	Late           int
	CurrentlyOpen  int
	ComplianceRate float64 // OnTime / (OnTime+Late) * 100; 0 if none resolved yet
}

// MonthStats is one calendar month's resolution outcomes, bucketed by
// ResolvedAt.
type MonthStats struct {
	Month          string // "YYYY-MM"
	Resolved       int
	OnTime         int
	ComplianceRate float64
}

type Report struct {
	Overall      Stats
	BySeverity   []Stats
	MonthlyTrend []MonthStats
}

func ComputeReport(episodes []Episode) Report {
	overall := &Stats{}
	bySeverity := map[string]*Stats{}
	byMonth := map[string]*MonthStats{}

	for _, e := range episodes {
		sev := bySeverity[e.Severity]
		if sev == nil {
			sev = &Stats{Severity: e.Severity}
			bySeverity[e.Severity] = sev
		}
		overall.TotalEpisodes++
		sev.TotalEpisodes++

		if e.ResolvedAt == nil {
			overall.CurrentlyOpen++
			sev.CurrentlyOpen++
			continue
		}

		onTime := !slapolicy.EvaluateSLABreach(e.DeadlineAt, *e.ResolvedAt)
		if onTime {
			overall.OnTime++
			sev.OnTime++
		} else {
			overall.Late++
			sev.Late++
		}

		month := e.ResolvedAt.Format("2006-01")
		m := byMonth[month]
		if m == nil {
			m = &MonthStats{Month: month}
			byMonth[month] = m
		}
		m.Resolved++
		if onTime {
			m.OnTime++
		}
	}

	overall.ComplianceRate = complianceRate(overall.OnTime, overall.Late)
	r := Report{Overall: *overall}
	for _, s := range bySeverity {
		s.ComplianceRate = complianceRate(s.OnTime, s.Late)
		r.BySeverity = append(r.BySeverity, *s)
	}
	for _, m := range byMonth {
		m.ComplianceRate = complianceRate(m.OnTime, m.Resolved-m.OnTime)
		r.MonthlyTrend = append(r.MonthlyTrend, *m)
	}
	return r
}

func complianceRate(onTime, late int) float64 {
	total := onTime + late
	if total == 0 {
		return 0
	}
	return float64(onTime) / float64(total) * 100
}
