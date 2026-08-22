// Package initiatives is generic infrastructure for grouping related
// internal/jobs.Job rows -- possibly of different types -- into one
// auditable security initiative with an explicit lifecycle and derived
// progress. It knows nothing about what any Job.Type actually does; that
// stays entirely in internal/jobs and internal/api. See
// docs/superpowers/specs/2026-08-22-initiative-layer-design.md.
package initiatives

import "time"

const (
	StateActive   = "active"
	StateClosed   = "closed"
	StateArchived = "archived"
)

// Initiative is a named security initiative that groups one or more Jobs.
type Initiative struct {
	ID          string
	Name        string
	Description string
	State       string
	CreatedBy   string
	CreatedAt   time.Time
	ClosedAt    *time.Time
	ArchivedAt  *time.Time
}
