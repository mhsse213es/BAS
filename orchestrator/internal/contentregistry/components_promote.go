package contentregistry

import (
	"context"
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// PromoteInternalComponent turns one step of an already-executable
// content_version into a reusable, first-class component (spec §2.2). The
// origin version must currently pass the Executable() gate, and must not
// itself be a composed candidate (spec §2.5, acceptance criterion 7).
func (r *Registry) PromoteInternalComponent(ctx context.Context, contentVersionID string, stepIndex int, actor string) (string, error) {
	var contentID, origin, trust, lifecycle string
	var artifact []byte
	if err := r.pool.QueryRow(ctx,
		`SELECT content_id, origin, trust_level, lifecycle, artifact_bytes FROM content_versions WHERE id = $1`,
		contentVersionID).Scan(&contentID, &origin, &trust, &lifecycle, &artifact); err != nil {
		return "", fmt.Errorf("content_version %s: %w", contentVersionID, err)
	}
	if !Executable(Origin(origin), Trust(trust), Lifecycle(lifecycle), r.devBuild()) {
		return "", fmt.Errorf("content_version %s is not executable (origin=%s trust=%s lifecycle=%s)", contentVersionID, origin, trust, lifecycle)
	}
	var composedCount int
	if err := r.pool.QueryRow(ctx,
		`SELECT count(*) FROM content_version_components WHERE content_version_id = $1`,
		contentVersionID).Scan(&composedCount); err != nil {
		return "", err
	}
	if composedCount > 0 {
		return "", fmt.Errorf("content_version %s is itself a composed candidate -- components can only be promoted from a single-source scenario (spec §2.5)", contentVersionID)
	}

	var sc scenario.Scenario
	if err := yaml.Unmarshal(artifact, &sc); err != nil {
		return "", fmt.Errorf("parse artifact: %w", err)
	}
	if stepIndex < 0 || stepIndex >= len(sc.Steps) {
		return "", fmt.Errorf("step index %d out of range (scenario has %d steps)", stepIndex, len(sc.Steps))
	}
	step := sc.Steps[stepIndex]
	snapshot, err := json.Marshal(step)
	if err != nil {
		return "", err
	}

	var componentID string
	if err := r.pool.QueryRow(ctx, `INSERT INTO content_components
		(kind, technique_id, title, supported_os, origin_content_version_id, step_snapshot, promoted_by)
		VALUES ('internal', $1, $2, $3, $4, $5, $6) RETURNING id`,
		step.TechniqueID, step.Name, nonNil(sc.SupportedOS), contentVersionID, snapshot, actor,
	).Scan(&componentID); err != nil {
		return "", err
	}
	return componentID, nil
}
