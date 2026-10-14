package contentregistry

import (
	"context"
	"errors"
)

// RegisterExternalComponent records a reference to an existing ART/Caldera
// library technique as a reusable external component (spec §2.1). Unlike an
// internal component, there is no origin content_version to validate against
// -- the framework's own catalog is the source of truth for whether the
// reference is real; this registry only records the pointer and the library
// version active at reference time. actionKey is the scenario.
// ResolveExecutionClass action key this reference should carry into a
// composed candidate's pinned Step (empty resolves to the catalog's own
// "enumerate" default, execclass.go:1088-1095).
func (r *Registry) RegisterExternalComponent(ctx context.Context, framework, techniqueID, title, abilityID, actionKey string, testIndex int, libraryVersion string, supportedOS []string, actor string) (string, error) {
	if framework == "" {
		return "", errors.New("framework is required for an external component")
	}
	if techniqueID == "" {
		return "", errors.New("technique_id is required")
	}
	var id string
	if err := r.pool.QueryRow(ctx, `INSERT INTO content_components
		(kind, technique_id, title, supported_os, framework, ability_id, action_key, test_index, library_version, promoted_by)
		VALUES ('external', $1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		techniqueID, title, nonNil(supportedOS), framework, abilityID, actionKey, testIndex, libraryVersion, actor,
	).Scan(&id); err != nil {
		return "", err
	}
	return id, nil
}
