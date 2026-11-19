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

// ControlWithFramework pairs a control with the ID of the framework that
// defines it -- AllControls flattens every loaded framework's controls
// into one slice for consumers (Global Search Phase 5) that don't care
// about per-framework grouping.
type ControlWithFramework struct {
	FrameworkID string
	Control     ControlDef
}

// AllControls returns every control across every loaded framework, sorted
// by FrameworkID then control ID for deterministic output.
func (m *Mapper) AllControls() []ControlWithFramework {
	out := make([]ControlWithFramework, 0)
	for _, fw := range m.frameworks {
		for _, ctrl := range fw.Controls {
			out = append(out, ControlWithFramework{FrameworkID: fw.ID, Control: ctrl})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FrameworkID != out[j].FrameworkID {
			return out[i].FrameworkID < out[j].FrameworkID
		}
		return out[i].Control.ID < out[j].Control.ID
	})
	return out
}

// GenerateReport maps BAS simulation results onto a framework's controls.
//
// Control status is derived from technique-level evidence and the raw results are left as they are. A mapped
// technique is TESTED when a result for it gave a verdict (pass, blocked or fail). It has FAILED when any such result
// is a fail, and is INCONCLUSIVE when it only errored or was vetoed. SKIPPED results are not evidence at all.
// A base technique (T1003) is covered by a result for any of its sub-techniques; a sub-technique (T1003.001) only by
// itself. Control status, strongest first: failed (any executed technique succeeded), resisted (every mapped technique
// ran), partial (some ran), inconclusive (none ran cleanly, some errored or were vetoed), untested.
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

	var totalControls, testableControls, manualControls int
	var resisted, partial, failed, inconclusive int
	var techMapped, techTested int

	for _, ctrl := range fw.Controls {
		testable := ctrl.IsTestable()
		cr := ControlResult{
			ID:                ctrl.ID,
			Name:              ctrl.Name,
			Domain:            ctrl.Domain,
			Category:          ctrl.Category,
			Testable:          testable,
			Reference:         ctrl.Reference,
			Status:            "untested",
			TechniqueCoverage: []TechniqueCoverage{},
		}

		// Manual controls (governance/process/policy) cannot be validated by
		// running attack techniques — mark them and skip technique matching so
		// they are never scored by unrelated simulations.
		if !testable {
			cr.Status = "manual"
		} else {
			seenTech := make(map[string]bool)
			seen := make(map[string]bool) // deduplicate evidence by result.ID
			for _, raw := range ctrl.Techniques {
				tech := strings.ToUpper(strings.TrimSpace(raw))
				if tech == "" || seenTech[tech] {
					continue
				}
				seenTech[tech] = true

				var matched []models.SimulationResult
				if strings.Contains(tech, ".") {
					// Sub-technique: exact match only
					matched = exactIdx[tech]
				} else {
					// Base technique: match any sub-technique T1003 → T1003, T1003.001…
					matched = baseIdx[tech]
				}

				var tested, techFailed, errored bool
				for _, r := range matched {
					eff := models.EffectiveResult(r)
					if !seen[r.ID] {
						seen[r.ID] = true
						cr.Evidence = append(cr.Evidence, TechniqueEvidence{
							TechniqueID:   r.Technique.ID,
							TechniqueName: r.Technique.Name,
							Result:        string(eff),
							Details:       r.Details,
							Remediation:   r.Remediation,
						})
						// VETOED and ERROR stay in Evidence (we attempted the step) but are not evidence the control
						// was verified, so they never count as tested. A fraud-control SKIPPED also stays out of the
						// tested count: the endpoint result alone is not evidence the step was verified.
						if eff != models.ResultVetoed && eff != models.ResultError && eff != models.ResultSkipped {
							cr.Tested++
							switch eff {
							case models.ResultPass, models.ResultBlocked:
								cr.Passed++
							case models.ResultFail:
								cr.Failed++
							}
						}
					}
					switch r.Result {
					case models.ResultVetoed, models.ResultError:
						errored = true
					case models.ResultFail:
						tested, techFailed = true, true
					case models.ResultPass, models.ResultBlocked:
						tested = true
					}
				}

				state := "untested"
				switch {
				case tested && techFailed:
					state = "failed"
					cr.TechniquesFailed++
				case tested:
					state = "resisted"
				case errored:
					state = "inconclusive"
					cr.TechniquesInconclusive++
				}
				if tested {
					cr.TechniquesTested++
				}
				cr.TechniquesMapped++
				cr.TechniqueCoverage = append(cr.TechniqueCoverage, TechniqueCoverage{ID: tech, State: state})
			}

			switch {
			case cr.TechniquesFailed > 0:
				cr.Status = "failed"
			case cr.TechniquesMapped > 0 && cr.TechniquesTested == cr.TechniquesMapped:
				cr.Status = "resisted"
			case cr.TechniquesTested > 0:
				cr.Status = "partial"
			case cr.TechniquesInconclusive > 0:
				cr.Status = "inconclusive"
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
		case "resisted":
			testableControls++
			resisted++
			d.Passing++
			d.Resisted++
		case "partial":
			testableControls++
			partial++
			d.Passing++
			d.Partial++
		case "failed":
			testableControls++
			failed++
			d.Failing++
		case "inconclusive":
			testableControls++
			inconclusive++
			d.Untested++
			d.Inconclusive++
		case "manual":
			manualControls++
			d.Manual++
		default: // untested (testable, but no BAS evidence yet)
			testableControls++
			d.Untested++
		}
		if testable {
			techMapped += cr.TechniquesMapped
			techTested += cr.TechniquesTested
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

	testedControls := resisted + partial + failed
	passingControls := resisted + partial

	// Coverage and the resistance rate are measured over the BAS-testable subset only — manual-attestation controls
	// are excluded from both denominators.
	coveragePct := 0.0
	if testableControls > 0 {
		coveragePct = round2(float64(testedControls) / float64(testableControls) * 100)
	}
	resistancePct := 0.0
	if testedControls > 0 {
		resistancePct = round2(float64(passingControls) / float64(testedControls) * 100)
	}
	techCoveragePct := 0.0
	if techMapped > 0 {
		techCoveragePct = round2(float64(techTested) / float64(techMapped) * 100)
	}
	sufficient := testedControls > 0 && coveragePct >= MinConclusiveCoveragePercent
	note := ""
	if !sufficient {
		note = InsufficientCoverageNote
	}

	meta := fw.FrameworkMeta

	summary := ComplianceSummary{
		TotalControls:     totalControls,
		TestableControls:  testableControls,
		ManualControls:    manualControls,
		TestedControls:    testedControls,
		PassingControls:   passingControls,
		FailingControls:   failed,
		UntestedControls:  testableControls - testedControls,
		CoveragePercent:   coveragePct,
		CompliancePercent: resistancePct,

		ResistedControls:     resisted,
		PartialControls:      partial,
		InconclusiveControls: inconclusive,

		TechniquesMapped:         techMapped,
		TechniquesTested:         techTested,
		TechniqueCoveragePercent: techCoveragePct,

		SufficientCoverage: sufficient,
		CoverageNote:       note,
	}

	return &ComplianceReport{
		Framework:    meta,
		AgentID:      agentID,
		RunID:        runID,
		ScenarioName: scenarioName,
		GeneratedAt:  time.Now().UTC(),
		Narrative:    buildNarrative(summary, domains, controlResults),
		Summary:      summary,
		Domains:      domains,
		Controls:     controlResults,
	}, nil
}

// buildNarrative turns a compliance report's numbers into one or two plain-
// language sentences explaining what's driving the score. Grounded entirely
// in already-computed data (never fabricates a root cause it can't show
// evidence for).
func buildNarrative(s ComplianceSummary, domains []DomainResult, controls []ControlResult) string {
	if s.TestedControls == 0 {
		return "No controls have been tested yet — run a scenario to generate compliance evidence."
	}

	// The resistance rate is always followed by coverage: a rate over a handful of tested controls says little.
	var b strings.Builder
	fmt.Fprintf(&b, "Resistance rate %.0f%%: %d of %d tested controls resisted the techniques executed.",
		s.CompliancePercent, s.PassingControls, s.TestedControls)
	if s.PartialControls > 0 {
		fmt.Fprintf(&b, " %d of them only partially (not every mapped technique ran).", s.PartialControls)
	}
	fmt.Fprintf(&b, " Control coverage %d of %d testable controls (%.1f%%).",
		s.TestedControls, s.TestableControls, s.CoveragePercent)
	if !s.SufficientCoverage {
		fmt.Fprintf(&b, " %s.", InsufficientCoverageNote)
	}

	if s.FailingControls > 0 {
		// domains is already sorted alphabetically by GenerateReport, so a
		// strict > comparison deterministically picks the alphabetically-first
		// domain on a tie.
		var topDomain string
		topDomainFails := 0
		for _, d := range domains {
			if d.Failing > topDomainFails {
				topDomain = d.Name
				topDomainFails = d.Failing
			}
		}

		// Tally failing techniques across all control evidence, then sort for
		// a deterministic pick -- map iteration order is not stable in Go, so
		// this can't just take the first map entry with the highest count.
		type techFail struct {
			id, name string
			n        int
		}
		byTech := map[string]*techFail{}
		for _, c := range controls {
			for _, ev := range c.Evidence {
				if ev.Result != "fail" {
					continue
				}
				t := byTech[ev.TechniqueID]
				if t == nil {
					t = &techFail{id: ev.TechniqueID, name: ev.TechniqueName}
					byTech[ev.TechniqueID] = t
				}
				t.n++
			}
		}
		techs := make([]*techFail, 0, len(byTech))
		for _, t := range byTech {
			techs = append(techs, t)
		}
		sort.Slice(techs, func(i, j int) bool {
			if techs[i].n != techs[j].n {
				return techs[i].n > techs[j].n
			}
			return techs[i].id < techs[j].id // deterministic tie-break
		})

		fmt.Fprintf(&b, " %d control(s) are failing", s.FailingControls)
		if topDomain != "" {
			fmt.Fprintf(&b, ", most concentrated in %s (%d of %d)", topDomain, topDomainFails, s.FailingControls)
		}
		b.WriteString(".")
		if len(techs) > 0 {
			top := techs[0]
			if top.name != "" {
				fmt.Fprintf(&b, " The most common failing technique is %s (%s).", top.name, top.id)
			} else {
				fmt.Fprintf(&b, " The most common failing technique is %s.", top.id)
			}
		}
	}

	if s.UntestedControls > 0 {
		fmt.Fprintf(&b, " %d control(s) haven't been tested yet — run additional scenarios to close coverage gaps.", s.UntestedControls)
	}

	return b.String()
}

// WriteCSV writes the compliance report as a CSV to w.
func WriteCSV(w io.Writer, r *ComplianceReport) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"Framework", "Version", "Control ID", "Control Name",
		"Domain", "Category", "Validation", "Status", "Tested", "Passed", "Failed", "Failing Techniques",
		"Techniques Tested", "Techniques Mapped", "Reference",
	})
	for _, ctrl := range r.Controls {
		var failing []string
		for _, ev := range ctrl.Evidence {
			if ev.Result == "fail" {
				failing = append(failing, ev.TechniqueID)
			}
		}
		validation := "Automated (BAS)"
		if !ctrl.Testable {
			validation = "Manual attestation"
		}
		_ = cw.Write([]string{
			r.Framework.Name,
			r.Framework.Version,
			ctrl.ID,
			ctrl.Name,
			ctrl.Domain,
			ctrl.Category,
			validation,
			ctrl.Status,
			strconv.Itoa(ctrl.Tested),
			strconv.Itoa(ctrl.Passed),
			strconv.Itoa(ctrl.Failed),
			strings.Join(failing, "; "),
			strconv.Itoa(ctrl.TechniquesTested),
			strconv.Itoa(ctrl.TechniquesMapped),
			ctrl.Reference,
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
