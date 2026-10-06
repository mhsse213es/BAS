package contentregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

const (
	schemaVersion              = 1
	structuralValidator        = "contentregistry.structural"
	structuralValidatorVersion = "1"
	safetyClassifier           = "execclass"
	// safetyClassifierVersion must be bumped whenever scenario/execclass.go's
	// catalog changes meaningfully, so old verdicts stay attributable.
	safetyClassifierVersion = "1"
)

var (
	techniquePattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	contentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type checkResult struct {
	outcome string // PASS | FAIL
	detail  map[string]any
}

type safetyResult struct {
	verdict string
	detail  []map[string]any
}

type analysis struct {
	sc           *scenario.Scenario
	contentID    string
	techniqueIDs []string
	supportedOS  []string
	dynamicScope string
	dynamicModes []string
	structural   checkResult
	safety       safetyResult
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// analyzeArtifact parses stored/intake bytes and derives everything the
// version row records. It never fails on content *quality* -- that becomes a
// STRUCTURAL FAIL row -- only on bytes that cannot identify a scenario.
func analyzeArtifact(raw []byte) (*analysis, error) {
	var sc scenario.Scenario
	if err := yaml.Unmarshal(raw, &sc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if strings.TrimSpace(sc.ID) == "" {
		return nil, errors.New("missing required field 'id'")
	}
	a := &analysis{sc: &sc, contentID: sc.ID, supportedOS: append([]string{}, sc.SupportedOS...)}
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id != "" && !seen[id] {
			seen[id] = true
			a.techniqueIDs = append(a.techniqueIDs, id)
		}
	}
	for _, st := range sc.Steps {
		add(st.TechniqueID)
	}
	for _, t := range sc.ARTTechniques {
		add(t)
	}
	sort.Strings(a.techniqueIDs)
	if a.techniqueIDs == nil {
		a.techniqueIDs = []string{}
	}
	a.dynamicScope = dynamicScope(&sc)
	a.dynamicModes = dynamicModes(&sc)
	a.structural = structuralCheck(&sc, a.techniqueIDs)
	a.safety = safetyVerdict(&sc, a.dynamicModes)
	return a, nil
}

// dynamicScope names modes whose executed steps are only known at dispatch.
func dynamicScope(sc *scenario.Scenario) string {
	switch {
	case sc.LocalCheck:
		return "local_check"
	case sc.CalderaAllWindows:
		return "caldera_all_windows"
	case sc.CalderaAdversaryID != "":
		return "caldera_adversary"
	case len(sc.CalderaAbilities) > 0:
		return "caldera_abilities"
	case sc.ARTAllWindows:
		return "art_all_windows"
	case sc.ARTAllPlatform:
		return "art_all_platform"
	case sc.ARTSelectiveWindows:
		return "art_selective_windows"
	case sc.ARTSelectivePlatform:
		return "art_selective_platform"
	}
	return ""
}

// dynamicModes lists ALL active dynamic execution modes in a fixed order
// (dynamicScope reports only the first); art_techniques is included when set.
func dynamicModes(sc *scenario.Scenario) []string {
	modes := []string{}
	for _, m := range []struct {
		on   bool
		name string
	}{
		{sc.LocalCheck, "local_check"},
		{sc.CalderaAllWindows, "caldera_all_windows"},
		{sc.CalderaAdversaryID != "", "caldera_adversary"},
		{len(sc.CalderaAbilities) > 0, "caldera_abilities"},
		{sc.ARTAllWindows, "art_all_windows"},
		{sc.ARTAllPlatform, "art_all_platform"},
		{sc.ARTSelectiveWindows, "art_selective_windows"},
		{sc.ARTSelectivePlatform, "art_selective_platform"},
		{len(sc.ARTTechniques) > 0, "art_techniques"},
	} {
		if m.on {
			modes = append(modes, m.name)
		}
	}
	return modes
}

func hasExecutionMode(sc *scenario.Scenario) bool {
	return dynamicScope(sc) != "" || len(sc.ARTTechniques) > 0 || len(sc.Steps) > 0
}

func structuralCheck(sc *scenario.Scenario, techniqueIDs []string) checkResult {
	problems := []string{}
	if !contentIDPattern.MatchString(sc.ID) {
		problems = append(problems, "id is not a valid content id")
	}
	if strings.TrimSpace(sc.Name) == "" {
		problems = append(problems, "name is required")
	}
	for _, id := range techniqueIDs {
		if !techniquePattern.MatchString(id) {
			problems = append(problems, "malformed technique id "+id)
		}
	}
	if !hasExecutionMode(sc) {
		problems = append(problems, "no execution mode")
	}
	out := "PASS"
	if len(problems) > 0 {
		out = "FAIL"
	}
	return checkResult{outcome: out, detail: map[string]any{
		"problems": problems, "technique_ids_checked_against_catalog": false,
	}}
}

var classRank = map[scenario.ExecutionClass]int{
	scenario.ClassNonDestructive:         0,
	scenario.ClassPotentiallyDestructive: 1,
	scenario.ClassDestructive:            2,
}

// safetyVerdict stores execclass's native verdict (spec §4.6): worst static
// step wins. Dynamically resolved steps are never assumed safe or unsafe: if
// any dynamic mode exists and the static worst is not destructive (a known
// lower bound), the verdict is "unresolved".
func safetyVerdict(sc *scenario.Scenario, modes []string) safetyResult {
	worst := scenario.ClassNonDestructive
	detail := []map[string]any{}
	for _, st := range sc.Steps {
		c := scenario.ResolveExecutionClass(st.TechniqueID, st.ActionKey)
		detail = append(detail, map[string]any{
			"technique_id": st.TechniqueID, "action_key": st.ActionKey, "class": string(c.Class),
			"destructive_action": c.DestructiveAction, "blast_radius": c.BlastRadius,
		})
		if classRank[c.Class] > classRank[worst] {
			worst = c.Class
		}
	}
	for _, m := range modes {
		detail = append(detail, map[string]any{"dynamic": true, "mode": m})
	}
	verdict := string(worst)
	if len(modes) > 0 && worst != scenario.ClassDestructive {
		verdict = "unresolved"
	}
	return safetyResult{verdict: verdict, detail: detail}
}
