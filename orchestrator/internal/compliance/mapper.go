package compliance

import (
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/models"
)

//go:embed mappings/*.yaml
var mappingFS embed.FS

// Mapper holds all loaded frameworks and a pre-built inverted index.
type Mapper struct {
	frameworks map[string]*FrameworkDef
	// exactIdx: exact techID (uppercase) → []result placeholder (populated per call)
	// We only store what techniques each framework/control cares about.
	// techIndex: techID (uppercase base) → map[frameworkID] → []controlID
	techIndex map[string]map[string][]string
}

// NewMapper loads all YAML files from the embedded mappings directory.
func NewMapper() (*Mapper, error) {
	m := &Mapper{
		frameworks: make(map[string]*FrameworkDef),
		techIndex:  make(map[string]map[string][]string),
	}

	entries, err := mappingFS.ReadDir("mappings")
	if err != nil {
		return nil, fmt.Errorf("compliance: read mappings dir: %w", err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := mappingFS.ReadFile("mappings/" + entry.Name())
		if err != nil {
			return nil, fmt.Errorf("compliance: read %s: %w", entry.Name(), err)
		}
		var fw FrameworkDef
		if err := yaml.Unmarshal(data, &fw); err != nil {
			return nil, fmt.Errorf("compliance: parse %s: %w", entry.Name(), err)
		}
		fw.TotalControls = len(fw.Controls)
		m.frameworks[fw.ID] = &fw

		// Build inverted index: techID → frameworkID → []controlID
		for _, ctrl := range fw.Controls {
			for _, tech := range ctrl.Techniques {
				tech = strings.ToUpper(strings.TrimSpace(tech))
				if tech == "" {
					continue
				}
				if m.techIndex[tech] == nil {
					m.techIndex[tech] = make(map[string][]string)
				}
				m.techIndex[tech][fw.ID] = append(m.techIndex[tech][fw.ID], ctrl.ID)
			}
		}
	}

	if len(m.frameworks) == 0 {
		return nil, fmt.Errorf("compliance: no frameworks loaded")
	}
	return m, nil
}

// Frameworks returns metadata for all loaded frameworks, sorted by ID.
func (m *Mapper) Frameworks() []FrameworkMeta {
	out := make([]FrameworkMeta, 0, len(m.frameworks))
	for _, fw := range m.frameworks {
		out = append(out, fw.FrameworkMeta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// GenerateReport maps BAS simulation results onto a framework's controls.
func (m *Mapper) GenerateReport(
	results []models.SimulationResult,
	frameworkID, agentID, runID, scenarioName string,
) (*ComplianceReport, error) {
	fw, ok := m.frameworks[frameworkID]
	if !ok {
		return nil, fmt.Errorf("unknown framework: %s", frameworkID)
	}

	// Build result lookup: exact techID and base techID → []SimulationResult
	exactIdx, baseIdx := buildResultIndexes(results)

	domainMap := make(map[string]*DomainResult)
	controlResults := make([]ControlResult, 0, len(fw.Controls))

	var totalControls, testedControls, passingControls, failingControls int

	for _, ctrl := range fw.Controls {
		cr := ControlResult{
			ID:       ctrl.ID,
			Name:     ctrl.Name,
			Domain:   ctrl.Domain,
			Category: ctrl.Category,
			Status:   "untested",
		}

		seen := make(map[string]bool) // deduplicate by result.ID
		for _, tech := range ctrl.Techniques {
			tech = strings.ToUpper(tech)
			var matched []models.SimulationResult

			if strings.Contains(tech, ".") {
				// Sub-technique: exact match only
				matched = exactIdx[tech]
			} else {
				// Base technique: match any sub-technique T1003 → T1003, T1003.001…
				matched = baseIdx[tech]
			}

			for _, r := range matched {
				if seen[r.ID] {
					continue
				}
				seen[r.ID] = true
				cr.Tested++
				ev := TechniqueEvidence{
					TechniqueID:   r.Technique.ID,
					TechniqueName: r.Technique.Name,
					Result:        string(r.Result),
					Details:       r.Details,
					Remediation:   r.Remediation,
				}
				cr.Evidence = append(cr.Evidence, ev)
				switch r.Result {
				case models.ResultPass, models.ResultBlocked:
					cr.Passed++
				case models.ResultFail:
					cr.Failed++
				}
			}
		}

		if cr.Tested > 0 {
			if cr.Failed > 0 {
				cr.Status = "fail"
			} else {
				cr.Status = "pass"
			}
		}

		// Per-domain aggregation
		if domainMap[ctrl.Domain] == nil {
			domainMap[ctrl.Domain] = &DomainResult{Name: ctrl.Domain}
		}
		d := domainMap[ctrl.Domain]
		d.Total++
		totalControls++

		switch cr.Status {
		case "pass":
			testedControls++
			passingControls++
			d.Passing++
		case "fail":
			testedControls++
			failingControls++
			d.Failing++
		default:
			d.Untested++
		}

		controlResults = append(controlResults, cr)
	}

	// Sort domains alphabetically
	domains := make([]DomainResult, 0, len(domainMap))
	for _, d := range domainMap {
		if d.Passing+d.Failing > 0 {
			d.CompliancePct = round2(float64(d.Passing) / float64(d.Passing+d.Failing) * 100)
		}
		domains = append(domains, *d)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })

	coveragePct := 0.0
	if totalControls > 0 {
		coveragePct = round2(float64(testedControls) / float64(totalControls) * 100)
	}
	compliancePct := 0.0
	if testedControls > 0 {
		compliancePct = round2(float64(passingControls) / float64(testedControls) * 100)
	}

	meta := fw.FrameworkMeta

	return &ComplianceReport{
		Framework:    meta,
		AgentID:      agentID,
		RunID:        runID,
		ScenarioName: scenarioName,
		GeneratedAt:  time.Now().UTC(),
		Summary: ComplianceSummary{
			TotalControls:     totalControls,
			TestedControls:    testedControls,
			PassingControls:   passingControls,
			FailingControls:   failingControls,
			UntestedControls:  totalControls - testedControls,
			CoveragePercent:   coveragePct,
			CompliancePercent: compliancePct,
		},
		Domains:  domains,
		Controls: controlResults,
	}, nil
}

// WriteCSV writes the compliance report as a CSV to w.
func WriteCSV(w io.Writer, r *ComplianceReport) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"Framework", "Version", "Control ID", "Control Name",
		"Domain", "Category", "Status", "Tested", "Passed", "Failed", "Failing Techniques",
	})
	for _, ctrl := range r.Controls {
		var failing []string
		for _, ev := range ctrl.Evidence {
			if ev.Result == "fail" {
				failing = append(failing, ev.TechniqueID)
			}
		}
		_ = cw.Write([]string{
			r.Framework.Name,
			r.Framework.Version,
			ctrl.ID,
			ctrl.Name,
			ctrl.Domain,
			ctrl.Category,
			ctrl.Status,
			strconv.Itoa(ctrl.Tested),
			strconv.Itoa(ctrl.Passed),
			strconv.Itoa(ctrl.Failed),
			strings.Join(failing, "; "),
		})
	}
	cw.Flush()
}

// ── helpers ───────────────────────────────────────────────────────────────────

// buildResultIndexes returns two indexes:
//   - exactIdx: uppercase techID → results (exact match, e.g. T1003.001)
//   - baseIdx:  base techID → all results whose base matches (T1003 → T1003, T1003.001, …)
func buildResultIndexes(results []models.SimulationResult) (
	exactIdx map[string][]models.SimulationResult,
	baseIdx map[string][]models.SimulationResult,
) {
	exactIdx = make(map[string][]models.SimulationResult)
	baseIdx = make(map[string][]models.SimulationResult)

	for _, r := range results {
		if r.Result == models.ResultSkipped {
			continue
		}
		techID := strings.ToUpper(strings.TrimSpace(r.Technique.ID))
		if techID == "" {
			continue
		}
		exactIdx[techID] = append(exactIdx[techID], r)

		base := techID
		if i := strings.Index(techID, "."); i > 0 {
			base = techID[:i]
		}
		baseIdx[base] = append(baseIdx[base], r)
	}
	return
}

func round2(f float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(f, 'f', 2, 64), 64)
	return v
}
