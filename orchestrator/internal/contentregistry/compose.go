package contentregistry

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

type loadedComponent struct {
	id           string
	techniqueID  string
	supportedOS  []string
	kind         string
	stepSnapshot []byte // internal only
	framework    string // external only
	abilityID    string
	actionKey    string
	testIndex    int
}

// Compose assembles the given components into a new content_version,
// refusing before any row is created if the components share no common
// supported_os or if the assembled Steps list fails the existing
// safetyVerdict worst-step-wins check (spec §2.3-§2.4).
func (r *Registry) Compose(ctx context.Context, componentIDs []string, threatID, actor string) (string, bool, error) {
	if threatID == "" {
		return "", false, fmt.Errorf("composition requires a target threat id")
	}
	if len(componentIDs) < 2 {
		return "", false, fmt.Errorf("composition requires at least 2 components, got %d", len(componentIDs))
	}
	seen := map[string]bool{}
	for _, id := range componentIDs {
		if seen[id] {
			return "", false, fmt.Errorf("composition refused: duplicate component id %s", id)
		}
		seen[id] = true
	}
	components, err := r.loadComponents(ctx, componentIDs)
	if err != nil {
		return "", false, err
	}

	commonOS := components[0].supportedOS
	for _, c := range components[1:] {
		commonOS = intersect(commonOS, c.supportedOS)
	}
	if len(commonOS) == 0 {
		return "", false, fmt.Errorf("composition refused: components share no common supported_os")
	}

	sc := scenario.Scenario{
		ID:          "composed-" + uuid.New().String(),
		Name:        "Composed candidate",
		SupportedOS: commonOS,
	}
	for _, c := range components {
		step, err := c.toStep()
		if err != nil {
			return "", false, err
		}
		sc.Steps = append(sc.Steps, step)
	}
	artifact, err := yaml.Marshal(&sc)
	if err != nil {
		return "", false, err
	}

	a, err := analyzeArtifact(artifact)
	if err != nil {
		return "", false, err
	}
	if a.structural.outcome != "PASS" {
		return "", false, fmt.Errorf("composition refused: structural check failed: %v", a.structural.detail["problems"])
	}
	if a.safety.verdict == string(scenario.ClassDestructive) {
		return "", false, fmt.Errorf("composition refused: assembled steps classify as destructive")
	}
	tactics, err := combinatorialRisk(components)
	if err != nil {
		return "", false, err
	}

	versionID, created, err := r.createVersion(ctx, newVersion{
		contentID: sc.ID, origin: OriginLocal, source: SourceCustom,
		artifact: artifact, trust: TrustUntrusted, lifecycle: LifecycleDraft, actor: ActorComposer,
		analysis: a, threatID: threatID, generationRef: "composed",
	})
	if err != nil {
		return "", false, err
	}
	if created {
		detail, _ := json.Marshal(map[string]any{"tactics": tactics})
		if _, err := r.pool.Exec(ctx, `INSERT INTO content_safety_verdicts (content_version_id, classifier, classifier_version, verdict, detail)
			VALUES ($1, $2, $3, 'PASS', $4)`,
			versionID, combinatorialClassifier, combinatorialClassifierVersion, detail); err != nil {
			return "", false, err
		}
		for i, c := range components {
			if _, err := r.pool.Exec(ctx, `INSERT INTO content_version_components (content_version_id, component_id, step_order) VALUES ($1, $2, $3)`,
				versionID, c.id, i); err != nil {
				return "", false, err
			}
		}
	}
	return versionID, created, nil
}

func (r *Registry) loadComponents(ctx context.Context, ids []string) ([]loadedComponent, error) {
	out := make([]loadedComponent, 0, len(ids))
	for _, id := range ids {
		var c loadedComponent
		var snapshot []byte
		var framework, abilityID, actionKey *string
		var testIndex *int
		if err := r.pool.QueryRow(ctx, `SELECT id, technique_id, supported_os, kind, step_snapshot, framework, ability_id, action_key, test_index
			FROM content_components WHERE id = $1`, id).
			Scan(&c.id, &c.techniqueID, &c.supportedOS, &c.kind, &snapshot, &framework, &abilityID, &actionKey, &testIndex); err != nil {
			return nil, fmt.Errorf("component %s: %w", id, err)
		}
		c.stepSnapshot = snapshot
		if framework != nil {
			c.framework = *framework
		}
		if abilityID != nil {
			c.abilityID = *abilityID
		}
		if actionKey != nil {
			c.actionKey = *actionKey
		}
		if testIndex != nil {
			c.testIndex = *testIndex
		}
		out = append(out, c)
	}
	return out, nil
}

func (c loadedComponent) toStep() (scenario.Step, error) {
	if c.kind == "internal" {
		var step scenario.Step
		if err := json.Unmarshal(c.stepSnapshot, &step); err != nil {
			return scenario.Step{}, fmt.Errorf("unmarshal snapshot for component %s: %w", c.id, err)
		}
		return step, nil
	}
	return scenario.Step{
		Name:        c.techniqueID + " (external: " + c.framework + ")",
		TechniqueID: c.techniqueID,
		Framework:   c.framework,
		AbilityID:   c.abilityID,
		ActionKey:   c.actionKey,
		TestIndex:   c.testIndex,
	}, nil
}

func intersect(a, b []string) []string {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	var out []string
	for _, x := range b {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}
