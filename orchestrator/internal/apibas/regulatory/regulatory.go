// Package regulatory holds the regulatory mapping registry for API BAS.
//
// Mapping status and scenario execution status are separate. A scenario can execute correctly while its regulatory mapping
// stays unverified. A passing scenario demonstrates a control outcome; it does not certify compliance.
//
// Each mapping is a candidate until a named reviewer confirms, against the committed source file, the exact clause, its
// applicability, the commencement of the clause, and what each mapped scenario does and does not test. Obligations that no
// scenario tests are recorded in Unmapped, with the reason and the scenario that would be needed.
package regulatory

import (
	_ "embed"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed registry.yaml
var registry []byte

// Status values. A mapping is unverified until a reviewer confirms it.
const (
	StatusUnverified = "unverified"
	StatusVerified   = "verified"
)

// Commencement values. Enactment of an Act and commencement of one of its provisions are separate facts.
const (
	CommencementVerified    = "verified"
	CommencementNotVerified = "not_verified"
)

// Scenario states. A scenario that does not exist is not implemented. One that exists but whose executable test has not passed
// against the lab in both builds is implemented but not validated. Only implemented_validated can support a mapping.
const (
	ScenarioNotImplemented          = "not_implemented"
	ScenarioImplementedNotValidated = "implemented_not_validated"
	ScenarioImplementedValidated    = "implemented_validated"
)

// Coverage records, for one mapped scenario, what it tests against the clause and what it leaves untested.
type Coverage struct {
	ScenarioID         string   `yaml:"scenario_id"`
	ScenarioState      string   `yaml:"scenario_state"`
	ControlRequirement string   `yaml:"control_requirement"`
	ExpectedBehaviour  string   `yaml:"expected_behaviour"`
	Evidence           string   `yaml:"evidence"`
	Gaps               []string `yaml:"gaps"`
}

// Mapping is one control reference and the clause it maps to.
type Mapping struct {
	ControlRef           string     `yaml:"control_ref"`
	Framework            string     `yaml:"framework"`
	IssuingAuthority     string     `yaml:"issuing_authority"`
	DocumentTitle        string     `yaml:"document_title"`
	DocumentDate         string     `yaml:"document_date"`
	Version              string     `yaml:"version"`
	SourceURL            string     `yaml:"source_url"`
	SourceFile           string     `yaml:"source_file"`
	SourceSHA256         string     `yaml:"source_sha256"`
	RetrievedOn          string     `yaml:"retrieved_on"`
	SourceProvision      string     `yaml:"source_provision"`
	ClauseText           string     `yaml:"clause_text"`
	EntityCategory       string     `yaml:"entity_category"`
	Jurisdiction         string     `yaml:"jurisdiction"`
	ApplicabilityConds   []string   `yaml:"applicability_conditions"`
	Exclusions           []string   `yaml:"exclusions"`
	Commencement         string     `yaml:"commencement"`
	CommencementEvidence string     `yaml:"commencement_evidence"`
	EffectiveDate        string     `yaml:"effective_date"`
	MappedScenarios      []string   `yaml:"mapped_scenarios"`
	ScenarioCoverage     []Coverage `yaml:"scenario_coverage"`
	Status               string     `yaml:"status"`
	Reviewer             string     `yaml:"reviewer"`
	ReviewedOn           string     `yaml:"reviewed_on"`
	ReviewedHash         string     `yaml:"reviewed_hash"`
}

// Unmapped is an obligation that no scenario tests yet. It is recorded so the gap stays visible, with the reason and the
// scenario that would be needed to test it.
type Unmapped struct {
	ObligationRef    string `yaml:"obligation_ref"`
	Status           string `yaml:"status"`
	ScenarioState    string `yaml:"scenario_state"`
	Framework        string `yaml:"framework"`
	SourceFile       string `yaml:"source_file"`
	SourceSHA256     string `yaml:"source_sha256"`
	SourceProvision  string `yaml:"source_provision"`
	ClauseText       string `yaml:"clause_text"`
	Reason           string `yaml:"reason"`
	RequiredScenario string `yaml:"required_scenario"`
}

// Registry is the parsed content of the embedded registry.
type Registry struct {
	Mappings []Mapping  `yaml:"mappings"`
	Unmapped []Unmapped `yaml:"unmapped"`
}

var (
	refPattern        = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sourceFilePattern = regexp.MustCompile(`^sources/[a-z0-9][a-z0-9.-]*\.pdf$`)
)

// Load parses the embedded registry and validates it. It fails closed on the first invalid record.
func Load() (Registry, error) {
	return parse(registry)
}

func parse(data []byte) (Registry, error) {
	var r Registry
	if err := yaml.Unmarshal(data, &r); err != nil {
		return Registry{}, fmt.Errorf("regulatory: parse: %w", err)
	}
	seen := map[string]bool{}
	for _, m := range r.Mappings {
		if err := Validate(m); err != nil {
			return Registry{}, err
		}
		if seen[m.ControlRef] {
			return Registry{}, fmt.Errorf("regulatory: duplicate control_ref %s", m.ControlRef)
		}
		seen[m.ControlRef] = true
	}
	for _, u := range r.Unmapped {
		if err := validateUnmapped(u); err != nil {
			return Registry{}, err
		}
		if seen[u.ObligationRef] {
			return Registry{}, fmt.Errorf("regulatory: duplicate ref %s", u.ObligationRef)
		}
		seen[u.ObligationRef] = true
	}
	return r, nil
}

// Validate checks one mapping against the rules in the package comment. A verified mapping must also pass ReadyForReview.
func Validate(m Mapping) error {
	if err := validateRecord(m); err != nil {
		return err
	}
	switch m.Status {
	case StatusUnverified:
		return nil
	case StatusVerified:
		return validateReviewed(m)
	}
	return fmt.Errorf("regulatory: %s: status must be unverified or verified, got %q", m.ControlRef, m.Status)
}

// validateRecord checks every field rule except the status-specific ones, so it cannot recurse into the review gate.
func validateRecord(m Mapping) error {
	ref := m.ControlRef
	required := []struct{ name, value string }{
		{"framework", m.Framework}, {"issuing_authority", m.IssuingAuthority}, {"document_title", m.DocumentTitle},
		{"version", m.Version}, {"source_provision", m.SourceProvision}, {"clause_text", m.ClauseText},
		{"entity_category", m.EntityCategory}, {"jurisdiction", m.Jurisdiction},
	}
	for _, f := range required {
		if strings.TrimSpace(f.value) == "" {
			return fmt.Errorf("regulatory: %s: %s is required", ref, f.name)
		}
	}
	switch {
	case !refPattern.MatchString(ref):
		return fmt.Errorf("regulatory: %q is not a control reference", ref)
	case !httpsURL(m.SourceURL):
		return fmt.Errorf("regulatory: %s: source_url must be an https URL", ref)
	case !sourceFilePattern.MatchString(m.SourceFile):
		return fmt.Errorf("regulatory: %s: source_file must be a PDF under sources/", ref)
	case !sha256Pattern.MatchString(m.SourceSHA256):
		return fmt.Errorf("regulatory: %s: source_sha256 must be 64 lowercase hex characters", ref)
	case !isDate(m.DocumentDate) || !isDate(m.RetrievedOn):
		return fmt.Errorf("regulatory: %s: document_date and retrieved_on must be YYYY-MM-DD", ref)
	case len(m.ApplicabilityConds) == 0:
		return fmt.Errorf("regulatory: %s: applicability_conditions are required", ref)
	case len(m.MappedScenarios) == 0:
		return fmt.Errorf("regulatory: %s: mapped_scenarios must name a scenario; an obligation no scenario tests goes in unmapped", ref)
	}
	if err := validateCoverage(m); err != nil {
		return err
	}
	switch m.Commencement {
	case CommencementVerified:
		if strings.TrimSpace(m.CommencementEvidence) == "" || !isDate(m.EffectiveDate) {
			return fmt.Errorf("regulatory: %s: verified commencement needs commencement_evidence and an effective_date", ref)
		}
	case CommencementNotVerified:
		if m.EffectiveDate != "" {
			return fmt.Errorf("regulatory: %s: effective_date is set but commencement is not verified; the date must not be invented", ref)
		}
	default:
		return fmt.Errorf("regulatory: %s: commencement must be verified or not_verified, got %q", ref, m.Commencement)
	}
	return nil
}

// validateCoverage holds each mapped scenario to a coverage entry that states its gaps. A scenario with no recorded gap is
// not accepted as covering a whole legal obligation.
func validateCoverage(m Mapping) error {
	if len(m.ScenarioCoverage) != len(m.MappedScenarios) {
		return fmt.Errorf("regulatory: %s: scenario_coverage needs one entry per mapped scenario", m.ControlRef)
	}
	for i, c := range m.ScenarioCoverage {
		if c.ScenarioID != m.MappedScenarios[i] {
			return fmt.Errorf("regulatory: %s: scenario_coverage[%d] names %s, expected %s", m.ControlRef, i, c.ScenarioID, m.MappedScenarios[i])
		}
		if strings.TrimSpace(c.ControlRequirement) == "" || strings.TrimSpace(c.ExpectedBehaviour) == "" || strings.TrimSpace(c.Evidence) == "" {
			return fmt.Errorf("regulatory: %s: coverage for %s needs control_requirement, expected_behaviour and evidence", m.ControlRef, c.ScenarioID)
		}
		if len(c.Gaps) == 0 {
			return fmt.Errorf("regulatory: %s: coverage for %s must state what it does not test", m.ControlRef, c.ScenarioID)
		}
		if !validState(c.ScenarioState) {
			return fmt.Errorf("regulatory: %s: coverage for %s has scenario_state %q", m.ControlRef, c.ScenarioID, c.ScenarioState)
		}
	}
	return nil
}

// validateReviewed holds a verified mapping to its review record. The reviewed hash must equal the committed source's hash,
// so the reviewer confirmed the bytes the registry points at.
func validateReviewed(m Mapping) error {
	ref := m.ControlRef
	if err := ReadyForReview(m); err != nil {
		return err
	}
	if strings.TrimSpace(m.Reviewer) == "" {
		return fmt.Errorf("regulatory: %s: verified mapping needs a reviewer", ref)
	}
	if !isDate(m.ReviewedOn) {
		return fmt.Errorf("regulatory: %s: verified mapping needs reviewed_on (YYYY-MM-DD)", ref)
	}
	if m.ReviewedHash != m.SourceSHA256 {
		return fmt.Errorf("regulatory: %s: reviewed_hash does not match source_sha256; the reviewer must confirm the committed bytes", ref)
	}
	if m.Commencement != CommencementVerified {
		return fmt.Errorf("regulatory: %s: verified mapping needs commencement verified", ref)
	}
	return nil
}

func validateUnmapped(u Unmapped) error {
	switch {
	case !refPattern.MatchString(u.ObligationRef):
		return fmt.Errorf("regulatory: unmapped %q is not an obligation reference", u.ObligationRef)
	case strings.TrimSpace(u.Framework) == "" || strings.TrimSpace(u.SourceProvision) == "" || strings.TrimSpace(u.ClauseText) == "":
		return fmt.Errorf("regulatory: unmapped %s: framework, source_provision and clause_text are required", u.ObligationRef)
	case !sourceFilePattern.MatchString(u.SourceFile) || !sha256Pattern.MatchString(u.SourceSHA256):
		return fmt.Errorf("regulatory: unmapped %s: source_file and source_sha256 are required", u.ObligationRef)
	case strings.TrimSpace(u.Reason) == "" || strings.TrimSpace(u.RequiredScenario) == "":
		return fmt.Errorf("regulatory: unmapped %s: reason and required_scenario are required", u.ObligationRef)
	case u.Status != StatusUnverified:
		return fmt.Errorf("regulatory: unmapped %s: status must be unverified", u.ObligationRef)
	case u.ScenarioState != ScenarioNotImplemented && u.ScenarioState != ScenarioImplementedNotValidated:
		return fmt.Errorf("regulatory: unmapped %s: scenario_state must be not_implemented or implemented_not_validated, got %q",
			u.ObligationRef, u.ScenarioState)
	}
	return nil
}

func isDate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// ReadyForReview is the acceptance gate for human verification. A mapping can be considered for verification only once its
// source, applicability, scenario coverage and evidence are recorded, and every mapped scenario is implemented and validated.
// Passing this gate does not verify the mapping; a named reviewer still must.
func ReadyForReview(m Mapping) error {
	if err := validateRecord(m); err != nil {
		return err
	}
	for _, c := range m.ScenarioCoverage {
		if c.ScenarioState != ScenarioImplementedValidated {
			return fmt.Errorf("regulatory: %s: not ready for review: scenario %s is %s", m.ControlRef, c.ScenarioID, c.ScenarioState)
		}
	}
	return nil
}

func validState(s string) bool {
	switch s {
	case ScenarioNotImplemented, ScenarioImplementedNotValidated, ScenarioImplementedValidated:
		return true
	}
	return false
}
