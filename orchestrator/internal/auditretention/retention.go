// Package auditretention reports how far back the audit log reaches against the retention minimum.
//
// The audit_logs table is append-only: the application role has no UPDATE or DELETE on it (internal/db/app_role.go).
// So nothing removes an entry before the minimum. This package does not delete anything. It shows whether the
// history meets the minimum, so the claim is checkable and not just documented. Any maximum retention or purge
// would change that append-only guarantee and is a separate decision.
package auditretention

import "time"

// MinimumRetentionDays is the shortest period the audit log must cover. CERT-In's directions require ICT logs
// for 180 days in India, and the RBI CSF mapping cites the same period.
const MinimumRetentionDays = 180

// Status is the audit log's coverage against the minimum.
type Status struct {
	MinimumDays  int        `json:"minimumDays"`
	OldestEntry  *time.Time `json:"oldestEntry"`
	AgeDays      int        `json:"ageDays"`
	MeetsMinimum bool       `json:"meetsMinimum"`
}

// Coverage works out the status from the timestamp of the oldest audit entry, or nil when the log is empty.
func Coverage(oldest *time.Time, now time.Time) Status {
	s := Status{MinimumDays: MinimumRetentionDays, OldestEntry: oldest}
	if oldest == nil {
		return s
	}
	s.AgeDays = int(now.Sub(*oldest).Hours() / 24)
	s.MeetsMinimum = s.AgeDays >= MinimumRetentionDays
	return s
}
