package api

import (
	"context"
	"time"

	"github.com/audspect/bas/internal/endpointrisk"
)

// techniqueVerificationFindings reads the latest technique_verification_runs
// row per check_id for agentID (asOf-filtered on completed_at) and emits a
// Finding whenever that latest status is fail or error. Deliberately
// independent of postureCheckInput's pass/fail loop (design spec §2.1): a
// config check that now passes must not silence a technique that still
// gets through, so this never shares a Finding.ID with the config check's
// own Finding -- it uses checkID+":technique" instead. Callers append these
// directly to a category's Findings list; they must never affect Score.
func (h *Handler) techniqueVerificationFindings(ctx context.Context, agentID string, asOf time.Time) []endpointrisk.Finding {
	rows, err := h.db.Query(ctx,
		`SELECT DISTINCT ON (check_id) check_id, technique_id, status, reason, completed_at
		   FROM technique_verification_runs
		  WHERE agent_id = $1 AND completed_at IS NOT NULL AND completed_at <= $2
		  ORDER BY check_id, completed_at DESC`,
		agentID, asOf)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []endpointrisk.Finding
	for rows.Next() {
		var checkID, techniqueID, status, reason string
		var completedAt time.Time
		if err := rows.Scan(&checkID, &techniqueID, &status, &reason, &completedAt); err != nil {
			continue
		}
		if status != "fail" && status != "error" {
			continue
		}
		text := postureCheckFindingText[checkID]
		title := text.Title
		if title == "" {
			title = "Technique verification failed"
		}
		completed := completedAt
		out = append(out, endpointrisk.Finding{
			ID:           checkID + ":technique",
			Title:        title + " (technique verification)",
			Description:  "Re-running technique " + techniqueID + " after remediation showed the control did not stop it.",
			Severity:     "High",
			Risk:         reason,
			Remediation:  "Re-review the control's configuration and re-run technique verification after further changes.",
			Passed:       false,
			LastObserved: &completed,
		})
	}
	return out
}
