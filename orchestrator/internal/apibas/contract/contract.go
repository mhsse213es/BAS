// Package contract defines the API BAS scenario contract (api.txt section 6,
// blueprint section 3.1) and validates it at load time.
//
// Scenario files are parsed here and executed by the runner. They are not part
// of the live scenario engine, so they are never loaded from scenarios/ and
// are not subject to its signature gate. They are embedded in the binary by
// the catalog package.
package contract

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Category codes match the blueprint taxonomy (section 1).
var categories = map[string]bool{
	"AUTHN": true, "AUTHZ": true, "GWAY": true, "INJ": true, "BIZ": true,
	"DATA": true, "ABUSE": true, "INTEG": true, "DISC": true, "DET": true,
}

// Side-effect classes from blueprint section 6. Phase 1 supports READ_ONLY only.
var sideEffectClasses = map[string]bool{
	"READ_ONLY": true, "STATE_CHANGE_SANDBOX": true,
	"EXTERNAL_CONSEQUENTIAL": true, "RESOURCE_INTENSIVE": true,
}

// Ground-truth adapters defined so far. Phase 1 requires "state".
var groundTruthAdapters = map[string]bool{"state": true, "response": true}

var idPattern = regexp.MustCompile(`^API-BAS-([A-Z]+)-(\d{3})$`)

// Scenario is one API BAS scenario: a campaign of ordered steps with an
// explicit hypothesis, expected control and ground truth.
type Scenario struct {
	ID                string             `yaml:"id"`
	Name              string             `yaml:"name"`
	Category          string             `yaml:"category"`
	AttackObjective   string             `yaml:"attack_objective"`
	ThreatModel       ThreatModel        `yaml:"threat_model"`
	Preconditions     Preconditions      `yaml:"preconditions"`
	Steps             []Step             `yaml:"steps"`
	ExpectedControl   string             `yaml:"expected_control"`
	GroundTruth       GroundTruth        `yaml:"ground_truth"`
	DetectionAssert   DetectionAssertion `yaml:"detection_assertion"`
	Evidence          []string           `yaml:"evidence"`
	SideEffectClass   string             `yaml:"side_effect_class"`
	Cleanup           []string           `yaml:"cleanup"`
	IndustryMapping   []string           `yaml:"industry_mapping"`
	RegulatoryMapping []string           `yaml:"regulatory_mapping"`
	NegativeTests     []string           `yaml:"negative_tests"`
}

// ThreatModel is the simulated attacker (api.txt section 7, item 1).
type ThreatModel struct {
	Attacker    string `yaml:"attacker"`
	Identity    string `yaml:"identity"`
	AccessLevel string `yaml:"access_level"`
	Objective   string `yaml:"objective"`
}

// Preconditions name the fixture and the object under test.
type Preconditions struct {
	Fixture    string   `yaml:"fixture"`
	Identities []string `yaml:"identities"`
	Object     string   `yaml:"object"`
}

// Step is one request in a campaign. Role is "baseline" for the owner's
// legitimate request and "attack" for the simulated attacker's request.
type Step struct {
	ID         string `yaml:"id"`
	Role       string `yaml:"role"`
	Identity   string `yaml:"identity"`
	Method     string `yaml:"method"`
	Path       string `yaml:"path"`
	Hypothesis string `yaml:"hypothesis"`
}

// GroundTruth declares which independent adapters must verify the outcome.
type GroundTruth struct {
	Adapters []string `yaml:"adapters"`
	Check    string   `yaml:"check"`
}

// DetectionAssertion is a separate assertion (api.txt section 10). Phase 1 can
// only declare it as not evaluated, so it cannot be silently treated as detected.
type DetectionAssertion struct {
	Status string `yaml:"status"`
	Reason string `yaml:"reason"`
}

// Parse decodes and validates one scenario document.
func Parse(data []byte) (Scenario, error) {
	var s Scenario
	if err := yaml.Unmarshal(data, &s); err != nil {
		return Scenario{}, fmt.Errorf("contract: decode: %w", err)
	}
	if err := s.Validate(); err != nil {
		return Scenario{}, err
	}
	return s, nil
}

// Validate enforces the contract. It is strict on purpose: an incomplete
// scenario must fail to load rather than run with a weaker claim.
func (s Scenario) Validate() error {
	m := idPattern.FindStringSubmatch(s.ID)
	if m == nil {
		return fmt.Errorf("contract: id %q must match API-BAS-<CAT>-<NNN>", s.ID)
	}
	if !categories[m[1]] {
		return fmt.Errorf("contract: %s: unknown category %q", s.ID, m[1])
	}
	if s.Category != m[1] {
		return fmt.Errorf("contract: %s: category %q does not match id segment %q", s.ID, s.Category, m[1])
	}
	for field, v := range map[string]string{
		"name": s.Name, "attack_objective": s.AttackObjective, "expected_control": s.ExpectedControl,
		"threat_model.objective": s.ThreatModel.Objective, "preconditions.fixture": s.Preconditions.Fixture,
		"preconditions.object": s.Preconditions.Object,
	} {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("contract: %s: %s is required", s.ID, field)
		}
	}
	if !sideEffectClasses[s.SideEffectClass] {
		return fmt.Errorf("contract: %s: unknown side_effect_class %q", s.ID, s.SideEffectClass)
	}
	if s.SideEffectClass != "READ_ONLY" {
		return fmt.Errorf("contract: %s: side_effect_class %s is not supported in Phase 1", s.ID, s.SideEffectClass)
	}
	if err := s.validateSteps(); err != nil {
		return err
	}
	if len(s.GroundTruth.Adapters) == 0 {
		return fmt.Errorf("contract: %s: ground_truth.adapters is required", s.ID)
	}
	hasState := false
	for _, a := range s.GroundTruth.Adapters {
		if !groundTruthAdapters[a] {
			return fmt.Errorf("contract: %s: unknown ground-truth adapter %q", s.ID, a)
		}
		hasState = hasState || a == "state"
	}
	if !hasState {
		return fmt.Errorf("contract: %s: ground_truth must include the state adapter", s.ID)
	}
	if s.DetectionAssert.Status != "not_evaluated" || strings.TrimSpace(s.DetectionAssert.Reason) == "" {
		return fmt.Errorf("contract: %s: Phase 1 detection_assertion must be status not_evaluated with a reason", s.ID)
	}
	if len(s.RegulatoryMapping) > 0 {
		return fmt.Errorf("contract: %s: regulatory_mapping must stay empty until sources are verified", s.ID)
	}
	return nil
}

func (s Scenario) validateSteps() error {
	if len(s.Steps) != 2 {
		return fmt.Errorf("contract: %s: Phase 1 requires exactly two steps (baseline, attack), got %d", s.ID, len(s.Steps))
	}
	wantRoles := []string{"baseline", "attack"}
	for i, st := range s.Steps {
		if st.ID == "" || st.Identity == "" || st.Method == "" || st.Path == "" {
			return fmt.Errorf("contract: %s: step %d is missing id, identity, method or path", s.ID, i)
		}
		if st.Role != wantRoles[i] {
			return fmt.Errorf("contract: %s: step %d role must be %q, got %q", s.ID, i, wantRoles[i], st.Role)
		}
		if strings.TrimSpace(st.Hypothesis) == "" {
			return fmt.Errorf("contract: %s: step %s has no hypothesis; every step must test one", s.ID, st.ID)
		}
	}
	return nil
}
