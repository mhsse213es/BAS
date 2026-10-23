package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/k8sscenario"
)

// K8sScenarioAudit writes engine events to audit_logs. It returns the insert error unchanged, so the engine's
// fail-closed rule holds: an event that cannot be recorded stops the run before any cluster write.
type K8sScenarioAudit struct {
	pool *pgxpool.Pool
}

// NewK8sScenarioAudit returns an audit writer over the pool.
func NewK8sScenarioAudit(pool *pgxpool.Pool) *K8sScenarioAudit {
	return &K8sScenarioAudit{pool: pool}
}

// Write records one engine event. The action is prefixed so scenario events are easy to filter.
func (a *K8sScenarioAudit) Write(ctx context.Context, e k8sscenario.Event) error {
	detail := map[string]any{"run": e.RunID}
	for k, v := range e.Fields {
		detail[k] = v
	}
	raw, err := json.Marshal(detail)
	if err != nil {
		return fmt.Errorf("k8s scenario audit: %w", err)
	}
	actor := e.Fields["requester"]
	_, err = a.pool.Exec(ctx, `
		INSERT INTO audit_logs (actor_id, action, resource, detail, outcome)
		VALUES ($1, $2, $3, $4, $5)`,
		actor, e.Type, e.RunID, raw, outcomeOf(e))
	if err != nil {
		return fmt.Errorf("k8s scenario audit: %w", err)
	}
	return nil
}

// outcomeOf maps an engine event to the audit outcome column. Refusals and any run that did not end cleanly
// are "denied" so they stand out in the audit view.
func outcomeOf(e k8sscenario.Event) string {
	switch {
	case e.Type == k8sscenario.EventRefused:
		return "denied"
	case e.Type == k8sscenario.EventOutcome:
		switch e.Fields["state"] {
		case string(k8sscenario.StateFailed), string(k8sscenario.StateCleanupFailed), string(k8sscenario.StateRefused):
			return "denied"
		}
	}
	return "ok"
}
