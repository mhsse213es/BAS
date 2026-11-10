package contentimport

import (
	"regexp"
	"strings"

	"github.com/audspect/bas/internal/scenario"
)

var slugClean = regexp.MustCompile(`[^a-z0-9]+`)

// ScenarioID makes a stable, valid scenario id from what the draft was generated from. The marker's digits keep two
// rules with similar titles apart and make re-importing the same rule land on the same id.
func ScenarioID(kind, title, marker string) string {
	slug := strings.Trim(slugClean.ReplaceAllString(strings.ToLower(title), "-"), "-")
	if len(slug) > 36 {
		slug = strings.Trim(slug[:36], "-")
	}
	if slug == "" {
		slug = "item"
	}
	return "imp-" + kind + "-" + slug + "-" + strings.TrimPrefix(marker, "imp-")[:8]
}

// BuildScenario wraps one generated step in a scenario. It is marked executable because a reviewer must approve it
// before it exists as a runnable scenario at all; until then it is only a draft row.
func BuildScenario(kind, title, description, osName string, step scenario.Step) *scenario.Scenario {
	sc := &scenario.Scenario{
		ID:          ScenarioID(kind, title, step.Marker),
		Name:        step.Name,
		Description: description,
		Author:      "content-import",
		Tags:        []string{"imported", kind},
		Executable:  true,
		Steps:       []scenario.Step{step},
	}
	if osName != "" {
		sc.SupportedOS = []string{osName}
	}
	return sc
}
