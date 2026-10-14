package contentregistry

import (
	"context"
	"encoding/json"
	"fmt"
)

const (
	dispatchRecheckClassifier = "dispatch-recheck"
	dispatchRecheckVersion    = "1"
)

// DispatchSafetyRecheck re-runs analyzeArtifact (unmodified -- the exact
// entry point Compose/RegisterGenerated already use) against a version's
// stored artifact, immediately before a validation-lab dispatch. It does
// NOT re-run combinatorialRisk: that check's input (loadedComponent) is
// Compose-time-only data not retained in reusable form on a persisted
// version. A refusal here writes an auditable content_safety_verdicts row
// with classifier "dispatch-recheck", distinct from and in addition to the
// original "execclass" row createVersion wrote.
func (r *Registry) DispatchSafetyRecheck(ctx context.Context, v Version) error {
	a, err := analyzeArtifact(v.Artifact)
	if err != nil {
		return fmt.Errorf("dispatch re-check: artifact unreadable: %w", err)
	}
	if a.safety.verdict != "destructive" {
		return nil
	}
	detail, _ := json.Marshal(a.safety.detail)
	_, err = r.pool.Exec(ctx,
		`INSERT INTO content_safety_verdicts (content_version_id, classifier, classifier_version, verdict, detail)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (content_version_id, classifier, classifier_version) DO UPDATE SET detail = EXCLUDED.detail, verdict = EXCLUDED.verdict, evaluated_at = NOW()`,
		v.ID, dispatchRecheckClassifier, dispatchRecheckVersion, a.safety.verdict, detail)
	if err != nil {
		return fmt.Errorf("dispatch re-check: write verdict row: %w", err)
	}
	return fmt.Errorf("dispatch re-check: current safety verdict is destructive")
}
