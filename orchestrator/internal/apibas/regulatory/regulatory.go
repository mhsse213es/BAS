// Package regulatory holds the regulatory mapping registry for API BAS. A mapping ties a control reference to a clause of
// an official source. The registry is data with provenance, not a claim: every mapping names its source and version, and
// defaults to unverified. A passing scenario demonstrates a control outcome; it does not certify compliance.
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

//go:embed mappings.yaml
var registry []byte

// Status values. A mapping is unverified until a reviewer confirms its clause against the source.
const (
	StatusUnverified = "unverified"
	StatusVerified   = "verified"
)

// Commencement values. Enactment of an Act and commencement of one of its provisions are separate facts. A provision can be
// law without being in force, so each mapping records the commencement of its own clause.
const (
	CommencementVerified    = "verified"     // confirmed against an official notification, with its source
	CommencementNotVerified = "not_verified" // not yet confirmed; the effective date stays empty
)

// Mapping is one control reference and the clause it maps to. Its scenario execution status is separate: a scenario can
// execute correctly while its regulatory mapping stays unverified.
type Mapping struct {
	ControlRef         string   `yaml:"control_ref"`
	Framework          string   `yaml:"framework"`
	Clause             string   `yaml:"clause"`
	SourceProvision    string   `yaml:"source_provision"`
	Version            string   `yaml:"version"`
	SourceURL          string   `yaml:"source_url"`
	ApplicabilityConds []string `yaml:"applicability_conditions"`
	MappedScenarios    []string `yaml:"mapped_scenarios"`
	// Commencement of the clause. EffectiveDate is set only when Commencement is verified, and then CommencementSource names
	// the official notification it was confirmed from.
	Commencement       string `yaml:"commencement"`
	EffectiveDate      string `yaml:"effective_date"`
	CommencementSource string `yaml:"commencement_source"`
	// Review. A mapping is verified only with a named reviewer and the date of that review.
	Reviewer   string `yaml:"reviewer"`
	ReviewedOn string `yaml:"reviewed_on"`
	Status     string `yaml:"status"`
}

var (
	refPattern      = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$`)
	scenarioPattern = regexp.MustCompile(`^API-BAS-[A-Z]+-[0-9]{3}$`)
)

// Load parses the embedded registry and validates every mapping. It fails closed on the first invalid record.
func Load() ([]Mapping, error) {
	return parse(registry)
}

func parse(data []byte) ([]Mapping, error) {
	var doc struct {
		Mappings []Mapping `yaml:"mappings"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("regulatory: parse: %w", err)
	}
	seen := map[string]bool{}
	for _, m := range doc.Mappings {
		if err := Validate(m); err != nil {
			return nil, err
		}
		if seen[m.ControlRef] {
			return nil, fmt.Errorf("regulatory: duplicate control_ref %s", m.ControlRef)
		}
		seen[m.ControlRef] = true
	}
	return doc.Mappings, nil
}

// Validate checks one mapping. Every mapping names its source and version and cites scenarios. An unverified mapping
// carries no effective date, because the date is not known until its commencement is confirmed. A verified mapping needs
// the full review record: reviewer, review date, exact provision, applicability conditions, and the commencement evidence.
func Validate(m Mapping) error {
	ref := m.ControlRef
	switch {
	case !refPattern.MatchString(ref):
		return fmt.Errorf("regulatory: %q is not a control reference", ref)
	case strings.TrimSpace(m.Framework) == "" || strings.TrimSpace(m.Clause) == "":
		return fmt.Errorf("regulatory: %s: framework and clause are required", ref)
	case strings.TrimSpace(m.Version) == "":
		return fmt.Errorf("regulatory: %s: version is required", ref)
	case !httpsURL(m.SourceURL):
		return fmt.Errorf("regulatory: %s: source_url must be an https URL", ref)
	case len(m.MappedScenarios) == 0:
		return fmt.Errorf("regulatory: %s: mapped_scenarios must name at least one scenario", ref)
	}
	for _, id := range m.MappedScenarios {
		if !scenarioPattern.MatchString(id) {
			return fmt.Errorf("regulatory: %s: %q is not a scenario ID", ref, id)
		}
	}
	switch m.Commencement {
	case CommencementVerified, CommencementNotVerified:
	default:
		return fmt.Errorf("regulatory: %s: commencement must be verified or not_verified, got %q", ref, m.Commencement)
	}
	switch m.Status {
	case StatusUnverified:
		if m.EffectiveDate != "" {
			return fmt.Errorf("regulatory: %s: an unverified mapping must not carry an effective date", ref)
		}
		if m.Commencement == CommencementVerified {
			return fmt.Errorf("regulatory: %s: commencement is verified but the mapping is not reviewed", ref)
		}
		return nil
	case StatusVerified:
		return validateReviewed(m)
	}
	return fmt.Errorf("regulatory: %s: status must be unverified or verified, got %q", ref, m.Status)
}

// validateReviewed holds a verified mapping to its full review record. Source URL alone does not make a mapping verified.
func validateReviewed(m Mapping) error {
	ref := m.ControlRef
	if strings.TrimSpace(m.Reviewer) == "" {
		return fmt.Errorf("regulatory: %s: verified mapping needs a reviewer", ref)
	}
	if _, err := time.Parse("2006-01-02", m.ReviewedOn); err != nil {
		return fmt.Errorf("regulatory: %s: verified mapping needs reviewed_on (YYYY-MM-DD)", ref)
	}
	if strings.TrimSpace(m.SourceProvision) == "" {
		return fmt.Errorf("regulatory: %s: verified mapping needs the exact source provision", ref)
	}
	if len(m.ApplicabilityConds) == 0 {
		return fmt.Errorf("regulatory: %s: verified mapping needs its applicability conditions", ref)
	}
	if m.Commencement != CommencementVerified {
		return fmt.Errorf("regulatory: %s: verified mapping needs its commencement verified", ref)
	}
	if _, err := time.Parse("2006-01-02", m.EffectiveDate); err != nil {
		return fmt.Errorf("regulatory: %s: verified mapping needs an effective_date (YYYY-MM-DD)", ref)
	}
	if !httpsURL(m.CommencementSource) {
		return fmt.Errorf("regulatory: %s: verified mapping needs an https commencement_source", ref)
	}
	return nil
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}
