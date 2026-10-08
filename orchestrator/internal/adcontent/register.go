// Package adcontent bridges AD-M09 ("AD Threat Content Factory")
// registry wiring ONLY into the existing contentregistry intake
// pipeline. It registers a minimal metadata stub (id/name/description,
// always zero Steps) as intel-sourced DRAFT content, referencing a
// future, not-yet-authored scenario artifact. It contains no executable
// commands, no attack steps, and no technique-execution content of any
// kind -- actual scenario authoring is a separate future project.
package adcontent

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/adprimitive"
	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/scenario"
)

// StubIntakeFileFor builds a minimal scenario.IntakeFile for p: a valid
// scenario.Scenario YAML with ID/Name/Description set from p and an
// always-empty Steps field. Returns ok=false when p.ID is empty --
// contentregistry's own intake parser requires a non-empty id, and this
// builder fails the same way before ever reaching the registry.
func StubIntakeFileFor(p adprimitive.Primitive) (scenario.IntakeFile, bool) {
	if p.ID == "" {
		return scenario.IntakeFile{}, false
	}
	desc := fmt.Sprintf("AD-M09 registry stub for primitive %q -- no scenario artifact authored yet.", p.ID)
	sc := scenario.Scenario{
		ID:          p.ID,
		Name:        p.Name,
		Description: desc,
	}
	raw, err := yaml.Marshal(sc)
	if err != nil {
		return scenario.IntakeFile{}, false
	}
	return scenario.IntakeFile{
		Path:     "ad-m09-stub/" + p.ID + ".yaml",
		Source:   string(contentregistry.SourceIntel),
		Artifact: raw,
	}, true
}

// Register builds p's stub intake file and submits it to r, registering
// it as intel-sourced DRAFT content.
func Register(ctx context.Context, r *contentregistry.Registry, p adprimitive.Primitive) (scenario.IntakeDecision, error) {
	f, ok := StubIntakeFileFor(p)
	if !ok {
		return scenario.IntakeDecision{}, fmt.Errorf("adcontent: primitive %+v has no ID, cannot build a stub", p)
	}
	return r.Intake(ctx, f)
}
