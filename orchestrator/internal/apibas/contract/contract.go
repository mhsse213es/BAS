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
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
	"strconv"
)

// Category codes match the blueprint taxonomy (section 1).
var categories = map[string]bool{
	"AUTHN": true, "AUTHZ": true, "GWAY": true, "INJ": true, "BIZ": true,
	"DATA": true, "ABUSE": true, "INTEG": true, "DISC": true, "DET": true,
}

// Side-effect classes from blueprint section 6. Phase 2 supports READ_ONLY and
// STATE_CHANGE_SANDBOX (lab only, with a reset as cleanup).
var sideEffectClasses = map[string]bool{
	"READ_ONLY": true, "STATE_CHANGE_SANDBOX": true,
	"EXTERNAL_CONSEQUENTIAL": true, "RESOURCE_INTENSIVE": true,
}

// Claim types decide which identity relationship the scenario depends on.
//   - cross_identity: the attacker must be a different customer from the owner.
//   - property_level: the attacker must be the owner, and the claim concerns a
//     field they should not be able to change on their own object.
//   - authentication: the claim concerns the credential, so the identity
//     relationship does not matter.
//   - function_level: the claim concerns a privileged function, so ownership
//     does not matter.
var claims = map[string]bool{
	"cross_identity": true, "property_level": true,
	"authentication": true, "function_level": true,
}

// Ground-truth adapters defined so far. Every scenario requires "state".
var groundTruthAdapters = map[string]bool{"state": true, "response": true}

// alg_none sends an unsigned JWT whose subject is the forge_as identity.
var authModes = map[string]bool{"valid": true, "none": true, "revoked": true, "alg_none": true}

var idPattern = regexp.MustCompile(`^API-BAS-([A-Z]+)-(\d{3})$`)

// Scenario is one API BAS scenario: a campaign of ordered steps with an
// explicit hypothesis, expected control and ground truth.
type Scenario struct {
	ID              string        `yaml:"id"`
	Name            string        `yaml:"name"`
	Category        string        `yaml:"category"`
	Claim           string        `yaml:"claim"`
	AttackObjective string        `yaml:"attack_objective"`
	ThreatModel     ThreatModel   `yaml:"threat_model"`
	Preconditions   Preconditions `yaml:"preconditions"`
	Steps           []Step        `yaml:"steps"`
	DeniedStatuses  []int         `yaml:"denied_statuses"`
	CleanIsEnforced bool          `yaml:"clean_is_enforcement"`
	// ForbiddenResponseHeaders lists response headers that, with the given value,
	// count as exposure on the attack response (for example a reflected origin).
	ForbiddenResponseHeaders []HeaderRule `yaml:"forbidden_response_headers"`
	// MaxAcceptedAttempts is how many attack responses may be accepted (neither a
	// declared denial nor a server fault) before the control counts as failed.
	MaxAcceptedAttempts int `yaml:"max_accepted_attempts"`
	// MaxGrantedPageSize is the largest page size the attack response may report in
	// its page_size field. Larger grants are exploitation.
	MaxGrantedPageSize int `yaml:"max_granted_page_size"`
	// MaxAcceptedBytes is the largest body size the attack response may report in its
	// accepted_bytes field. Larger accepted bodies are exploitation.
	MaxAcceptedBytes int `yaml:"max_accepted_bytes"`
	// Latency, when set, makes this a timing scenario graded over repeated rounds.
	Latency *LatencyPolicy `yaml:"latency"`
	// MaxWorkUnits bounds the work_units an attack response may report. It is a
	// resource limit, graded independently of timing.
	MaxWorkUnits int `yaml:"max_work_units"`
	// MaxItemsReturned is the largest items array an attack response may return.
	MaxItemsReturned int `yaml:"max_items_returned"`
	// Protocol names the protocol the scenario drives. Empty and "http" run; other
	// known protocols are declared but reported UNSUPPORTED until an adapter exists.
	Protocol string `yaml:"protocol"`
	// Detection, when set, grades the detection axis against the access-event fixture.
	Detection *DetectionPolicy `yaml:"detection"`
	// Calibration declares the conditions the timing threshold was measured under.
	Calibration       *CalibrationPolicy `yaml:"calibration"`
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
// Auth selects the credential: "valid" (the identity's token), "none" (no
// credential) or "revoked" (the identity's revoked token). Empty means valid.
type Step struct {
	ID       string `yaml:"id"`
	Role     string `yaml:"role"`
	Identity string `yaml:"identity"`
	Auth     string `yaml:"auth"`
	Method   string `yaml:"method"`
	Path     string `yaml:"path"`
	Body     string `yaml:"body"`
	// Headers are extra request headers, for example a method-override header.
	Headers map[string]string `yaml:"headers"`
	// Repeat sends the step this many times. Only the attack step may repeat.
	Repeat int `yaml:"repeat"`
	// ForgeAs names the identity whose subject an alg_none token carries.
	ForgeAs    string `yaml:"forge_as"`
	Hypothesis string `yaml:"hypothesis"`
}

// GroundTruth declares which independent adapters must verify the outcome.
type GroundTruth struct {
	Adapters []string `yaml:"adapters"`
	Check    string   `yaml:"check"`
}

// DetectionAssertion is a separate assertion (api.txt section 10). It can only
// be declared as not evaluated for now, so it cannot be silently treated as
// detected.
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
	if !claims[s.Claim] {
		return fmt.Errorf("contract: %s: unknown claim %q", s.ID, s.Claim)
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
	if s.MaxAcceptedBytes < 0 {
		return fmt.Errorf("contract: %s: max_accepted_bytes cannot be negative", s.ID)
	}
	if s.MaxGrantedPageSize < 0 {
		return fmt.Errorf("contract: %s: max_granted_page_size cannot be negative", s.ID)
	}
	if len(s.DeniedStatuses) == 0 && !s.CleanIsEnforced {
		return fmt.Errorf("contract: %s: denied_statuses must list the enforcement codes, or set clean_is_enforcement", s.ID)
	}
	for _, c := range s.DeniedStatuses {
		if c < 400 || c > 499 {
			return fmt.Errorf("contract: %s: denied status %d must be a 4xx code", s.ID, c)
		}
	}
	if !sideEffectClasses[s.SideEffectClass] {
		return fmt.Errorf("contract: %s: unknown side_effect_class %q", s.ID, s.SideEffectClass)
	}
	if s.SideEffectClass == "EXTERNAL_CONSEQUENTIAL" || s.SideEffectClass == "RESOURCE_INTENSIVE" {
		return fmt.Errorf("contract: %s: side_effect_class %s is not supported yet", s.ID, s.SideEffectClass)
	}
	if err := s.validateSteps(); err != nil {
		return err
	}
	if err := s.validateSideEffects(); err != nil {
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
	for _, h := range s.ForbiddenResponseHeaders {
		if h.Match != "" && h.Match != "exact" && h.Match != "contains" {
			return fmt.Errorf("contract: %s: forbidden_response_headers match must be exact or contains, got %q", s.ID, h.Match)
		}
		if strings.TrimSpace(h.Name) == "" || h.Value == "" {
			return fmt.Errorf("contract: %s: forbidden_response_headers entries need a name and a value", s.ID)
		}
	}
	if s.CleanIsEnforced && !slices.Contains(s.GroundTruth.Adapters, "response") {
		return fmt.Errorf("contract: %s: clean_is_enforcement needs the response adapter to prove no leak", s.ID)
	}
	if s.Detection == nil {
		if s.DetectionAssert.Status != "not_evaluated" || strings.TrimSpace(s.DetectionAssert.Reason) == "" {
			return fmt.Errorf("contract: %s: detection_assertion must be status not_evaluated with a reason", s.ID)
		}
	} else {
		d := s.Detection
		switch {
		case d.Source != "elastic-security":
			return fmt.Errorf("contract: %s: detection source %q is not supported", s.ID, d.Source)
		case d.ExpectRule == "":
			return fmt.Errorf("contract: %s: detection needs expect_rule", s.ID)
		case !slices.Contains([]string{"low", "medium", "high", "critical"}, d.MinSeverity):
			return fmt.Errorf("contract: %s: detection min_severity %q is not a severity", s.ID, d.MinSeverity)
		case s.DetectionAssert.Status != "fixture_validated" || strings.TrimSpace(s.DetectionAssert.Reason) == "":
			return fmt.Errorf("contract: %s: a scenario with detection must set detection_assertion status fixture_validated with a reason", s.ID)
		}
	}
	if len(s.RegulatoryMapping) > 0 {
		return fmt.Errorf("contract: %s: regulatory_mapping must stay empty until sources are verified", s.ID)
	}
	return nil
}

func (s Scenario) validateSteps() error {
	if len(s.Steps) < 2 {
		return fmt.Errorf("contract: %s: at least two steps (baseline, attack) are required, got %d", s.ID, len(s.Steps))
	}
	last := len(s.Steps) - 1
	final := s.Steps[last]
	for i, st := range s.Steps {
		if st.ID == "" || st.Method == "" || st.Path == "" {
			return fmt.Errorf("contract: %s: step %d is missing id, method or path", s.ID, i)
		}
		var want string
		switch {
		case i == 0:
			want = "baseline"
		case i == last:
			want = "attack"
		default:
			want = "setup"
		}
		if st.Role != want {
			return fmt.Errorf("contract: %s: step %d role must be %q, got %q", s.ID, i, want, st.Role)
		}
		for _, m := range FillerToken.FindAllStringSubmatch(st.Body, -1) {
			if n, err := strconv.Atoi(m[1]); err != nil || n > MaxFillerBytes {
				return fmt.Errorf("contract: %s: step %s filler %s must be at most %d bytes", s.ID, st.ID, m[0], MaxFillerBytes)
			}
		}
		if st.Repeat < 0 || st.Repeat > maxRepeat {
			return fmt.Errorf("contract: %s: step %s repeat must be between 0 and %d", s.ID, st.ID, maxRepeat)
		}
		if st.Repeat > 1 && want != "attack" {
			return fmt.Errorf("contract: %s: step %s repeats, but repeat is only supported on the attack step", s.ID, st.ID)
		}
		if strings.TrimSpace(st.Hypothesis) == "" {
			return fmt.Errorf("contract: %s: step %s has no hypothesis; every step must test one", s.ID, st.ID)
		}
		auth := st.Auth
		if auth == "" {
			auth = "valid"
		}
		if !authModes[auth] {
			return fmt.Errorf("contract: %s: step %s has unknown auth %q", s.ID, st.ID, auth)
		}
		switch {
		case auth == "none" && st.Identity != "anonymous":
			return fmt.Errorf("contract: %s: step %s has auth none, so identity must be anonymous", s.ID, st.ID)
		case auth != "none" && st.Identity == "anonymous":
			return fmt.Errorf("contract: %s: step %s names anonymous but auth is %s", s.ID, st.ID, auth)
		case auth != "none" && st.Identity == "":
			return fmt.Errorf("contract: %s: step %s has no identity", s.ID, st.ID)
		}
		if want == "setup" {
			// A setup step is part of the same actor's chain: same identity, valid token.
			if st.Identity != final.Identity || auth != "valid" {
				return fmt.Errorf("contract: %s: setup step %s must use the attacker identity %s with a valid token", s.ID, st.ID, final.Identity)
			}
		}
		if auth == "alg_none" && (st.ForgeAs == "" || st.Identity == "anonymous") {
			return fmt.Errorf("contract: %s: step %s uses alg_none and needs forge_as", s.ID, st.ID)
		}
		if auth != "alg_none" && st.ForgeAs != "" {
			return fmt.Errorf("contract: %s: step %s sets forge_as but auth is %s", s.ID, st.ID, auth)
		}
		if st.Method != "GET" && st.Method != "PATCH" && st.Method != "POST" {
			return fmt.Errorf("contract: %s: step %s method %s is not supported", s.ID, st.ID, st.Method)
		}
		if (st.Method == "PATCH" || st.Method == "POST") && strings.TrimSpace(st.Body) == "" {
			return fmt.Errorf("contract: %s: step %s is %s and needs a body", s.ID, st.ID, st.Method)
		}
		if st.Method == "GET" && st.Body != "" {
			return fmt.Errorf("contract: %s: step %s is GET and must not carry a body", s.ID, st.ID)
		}
	}
	if final.Repeat > 1 {
		if s.MaxAcceptedAttempts < 1 || s.MaxAcceptedAttempts >= final.Repeat {
			return fmt.Errorf("contract: %s: a repeated attack needs max_accepted_attempts between 1 and %d", s.ID, final.Repeat-1)
		}
	} else if s.MaxAcceptedAttempts != 0 {
		return fmt.Errorf("contract: %s: max_accepted_attempts needs a repeated attack step", s.ID)
	}
	if s.Latency != nil {
		p := s.Latency
		switch {
		case p.CeilingMs <= 0:
			return fmt.Errorf("contract: %s: latency ceiling_ms must be set", s.ID)
		case p.MinRatio < 1:
			return fmt.Errorf("contract: %s: latency min_ratio must be at least 1", s.ID)
		case p.MaxCV <= 0:
			return fmt.Errorf("contract: %s: latency max_cv must be set", s.ID)
		case p.Trials < 5 || p.Rounds < 2 || p.Warmup < 0:
			return fmt.Errorf("contract: %s: latency needs at least 5 trials, 2 rounds and a non-negative warm-up", s.ID)
		case final.Repeat > 1 || s.SideEffectClass != "READ_ONLY":
			return fmt.Errorf("contract: %s: a timing scenario must be READ_ONLY with a single attack request", s.ID)
		}
	}
	if s.Calibration != nil {
		switch {
		case s.Latency == nil:
			return fmt.Errorf("contract: %s: calibration applies only to timing scenarios", s.ID)
		case s.Calibration.BaselineMs <= 0:
			return fmt.Errorf("contract: %s: calibration baseline_ms must be set", s.ID)
		case s.Calibration.Tolerance <= 1:
			return fmt.Errorf("contract: %s: calibration tolerance must be greater than 1", s.ID)
		}
	}
	if s.MaxItemsReturned < 0 {
		return fmt.Errorf("contract: %s: max_items_returned cannot be negative", s.ID)
	}
	switch s.Protocol {
	case "", "http", "graphql", "grpc", "soap", "websocket", "async":
	default:
		return fmt.Errorf("contract: %s: protocol %q is not a known protocol", s.ID, s.Protocol)
	}
	if s.MaxWorkUnits < 0 {
		return fmt.Errorf("contract: %s: max_work_units cannot be negative", s.ID)
	}
	return nil
}

// maxRepeat bounds how many times one step may be sent in a run.
const maxRepeat = 50

// validateSideEffects ties the declared class to what the steps actually do,
// so a READ_ONLY label cannot hide a mutating attack.
func (s Scenario) validateSideEffects() error {
	mutates := false
	for _, st := range s.Steps {
		if st.Method != "GET" {
			mutates = true
		}
	}
	switch s.SideEffectClass {
	case "READ_ONLY":
		if mutates {
			return fmt.Errorf("contract: %s: READ_ONLY scenario contains a mutating step", s.ID)
		}
	case "STATE_CHANGE_SANDBOX":
		if !mutates {
			return fmt.Errorf("contract: %s: STATE_CHANGE_SANDBOX scenario has no mutating step", s.ID)
		}
		if len(s.Cleanup) == 0 {
			return fmt.Errorf("contract: %s: STATE_CHANGE_SANDBOX requires a cleanup entry", s.ID)
		}
	}
	return nil
}

// HeaderRule names a response header and the value that counts as exposure.
type HeaderRule struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
	// Match is "exact" (the default) or "contains" (case-insensitive substring).
	Match string `yaml:"match"`
}

// FillerToken is a body placeholder that expands to N bytes of filler, so a
// scenario can send a large body without storing it in the YAML.
var FillerToken = regexp.MustCompile(`\{filler:(\d+)\}`)

// MaxFillerBytes bounds one filler placeholder.
const MaxFillerBytes = 5 << 20

// LatencyPolicy is the frozen timing configuration for a scenario. Every value is
// declared in the scenario file and is never tuned at run time.
type LatencyPolicy struct {
	CeilingMs int     `yaml:"ceiling_ms"`
	MinRatio  float64 `yaml:"min_ratio"`
	MaxCV     float64 `yaml:"max_cv"`
	Warmup    int     `yaml:"warmup"`
	Trials    int     `yaml:"trials"`
	Rounds    int     `yaml:"rounds"`
}

// DetectionPolicy names the detection the scenario expects from the fixture.
type DetectionPolicy struct {
	Source      string `yaml:"source"`
	ExpectRule  string `yaml:"expect_rule"`
	MinSeverity string `yaml:"min_severity"`
}

// CalibrationPolicy records the baseline the frozen timing threshold was measured
// against. A run whose measured baseline falls outside [BaselineMs/Tolerance,
// BaselineMs*Tolerance] is ERROR, never a timing pass or fail.
type CalibrationPolicy struct {
	BaselineMs float64 `yaml:"baseline_ms"`
	Tolerance  float64 `yaml:"tolerance"`
}
