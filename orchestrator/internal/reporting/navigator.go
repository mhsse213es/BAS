package reporting

import (
	"fmt"
	"strings"
)

// MITRE ATT&CK Navigator layer export.
//
// The console renders a CSS coverage grid, but SOC teams live in the official
// ATT&CK Navigator. Exporting a standard layer JSON lets them load Audspect
// results as a colored layer over the real matrix, combine it with other layers
// (e.g. their detection coverage), and share it — something a screenshot of our
// grid cannot do. The schema follows Navigator layer format v4.5.

// NavigatorLayer is a MITRE ATT&CK Navigator layer document.
type NavigatorLayer struct {
	Name        string             `json:"name"`
	Versions    NavigatorVersions  `json:"versions"`
	Domain      string             `json:"domain"`
	Description string             `json:"description"`
	Techniques  []NavigatorTech    `json:"techniques"`
	Gradient    NavigatorGradient  `json:"gradient"`
	LegendItems []NavigatorLegend  `json:"legendItems"`
	Metadata    []NavigatorKV      `json:"metadata,omitempty"`
	Layout      NavigatorLayout    `json:"layout"`
	HideDisable bool               `json:"hideDisabled"`
}

type NavigatorVersions struct {
	Attack    string `json:"attack"`
	Navigator string `json:"navigator"`
	Layer     string `json:"layer"`
}

type NavigatorTech struct {
	TechniqueID string `json:"techniqueID"`
	Score       int    `json:"score"`
	Color       string `json:"color"`
	Comment     string `json:"comment,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type NavigatorGradient struct {
	Colors   []string `json:"colors"`
	MinValue int      `json:"minValue"`
	MaxValue int      `json:"maxValue"`
}

type NavigatorLegend struct {
	Label string `json:"label"`
	Color string `json:"color"`
}

type NavigatorKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type NavigatorLayout struct {
	Layout string `json:"layout"`
}

// Verdict → (color, score, label). Score is only for the gradient legend; the
// per-technique color is what actually renders.
const (
	navPreventedColor = "#0d9488" // teal
	navDetectedColor  = "#2563eb" // blue
	navMissedColor    = "#c00000" // red
	navTestedColor    = "#6b7689" // grey — executed, outcome unknown
)

// BuildNavigatorLayer maps a report's per-technique results to a Navigator
// layer. Prevention/detection verdicts (when present) take precedence over the
// raw execution verdict so the layer reflects control effectiveness, not just
// "did it run". Base technique IDs are used (Navigator colors the base cell).
func BuildNavigatorLayer(r *FullReport, name string) NavigatorLayer {
	if name == "" {
		name = "Audspect BAS Coverage"
	}
	// Deduplicate to one entry per base technique ID, worst outcome wins so a
	// technique that was missed in any atomic shows as missed.
	type agg struct {
		color   string
		score   int
		comment string
		rank    int // higher = worse; wins
	}
	byTech := map[string]agg{}
	consider := func(techID, execVerdict, detVerdict string) {
		base := baseTechnique(techID)
		if base == "" {
			return
		}
		color, score, label, rank := navClassify(execVerdict, detVerdict)
		if cur, ok := byTech[base]; !ok || rank > cur.rank {
			byTech[base] = agg{color: color, score: score, comment: label, rank: rank}
		}
	}

	// Prefer the rich TechniqueMatrix; fall back to TacticHeatmap-less data via
	// TopFindings/CoverageBreakdown missed techniques if the matrix is empty.
	if len(r.TechniqueMatrix) > 0 {
		for _, t := range r.TechniqueMatrix {
			consider(t.TechniqueID, t.ExecVerdict, t.DetectionVerdict)
		}
	} else {
		for _, t := range r.DetectionTechniques {
			consider(t.TechniqueID, "", t.Verdict)
		}
		for _, f := range r.TopFindings {
			consider(f.TechniqueID, f.ExecVerdict, f.DetectionVerdict)
		}
	}

	techs := make([]NavigatorTech, 0, len(byTech))
	for id, a := range byTech {
		techs = append(techs, NavigatorTech{
			TechniqueID: id, Score: a.score, Color: a.color, Comment: a.comment, Enabled: true,
		})
	}

	subject := r.Agent.Hostname
	if r.Scope != nil && r.Scope.Title != "" {
		subject = r.Scope.Title
	}

	return NavigatorLayer{
		Name:        name,
		Versions:    NavigatorVersions{Attack: "14", Navigator: "4.9.1", Layer: "4.5"},
		Domain:      "enterprise-attack",
		Description: "Audspect BAS breach-and-attack-simulation coverage. Teal=prevented, blue=detected-only, red=missed, grey=tested. Subject: " + subject,
		Techniques:  techs,
		Gradient:    NavigatorGradient{Colors: []string{navMissedColor, "#ffe699", navPreventedColor}, MinValue: 0, MaxValue: 100},
		LegendItems: []NavigatorLegend{
			{Label: "Prevented", Color: navPreventedColor},
			{Label: "Detected only", Color: navDetectedColor},
			{Label: "Missed (evaded)", Color: navMissedColor},
			{Label: "Tested", Color: navTestedColor},
		},
		Metadata: []NavigatorKV{
			{Name: "Subject", Value: subject},
			{Name: "Generated", Value: r.GeneratedAt.Format("2006-01-02 15:04 UTC")},
			{Name: "Prevention", Value: navPct(r.Summary.PreventionScore)},
		},
		Layout:      NavigatorLayout{Layout: "side"},
		HideDisable: false,
	}
}

// navClassify returns (color, score, label, rank) for a verdict pair. Detection
// verdict wins when present; otherwise the execution verdict is used.
func navClassify(execVerdict, detVerdict string) (string, int, string, int) {
	switch strings.ToLower(detVerdict) {
	case "prevented":
		return navPreventedColor, 100, "Prevented", 1
	case "detected":
		return navDetectedColor, 60, "Detected only", 2
	case "undetected":
		return navMissedColor, 0, "Missed — evaded controls", 4
	}
	switch strings.ToLower(execVerdict) {
	case "pass", "blocked":
		return navPreventedColor, 100, "Prevented / blocked", 1
	case "fail":
		return navMissedColor, 0, "Executed successfully (not prevented)", 4
	default:
		return navTestedColor, 40, "Tested", 3
	}
}

func baseTechnique(id string) string {
	id = strings.ToUpper(strings.TrimSpace(id))
	if i := strings.Index(id, "."); i > 0 {
		return id[:i]
	}
	return id
}

func navPct(f float64) string {
	return fmt.Sprintf("%.1f%%", f)
}
