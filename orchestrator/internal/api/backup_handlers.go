package api

import (
	"net/http"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/go-chi/chi/v5"
)

// backupJobJSON is the wire shape for a backup_jobs row. Pointer fields are
// null until the worker fills them in -- a freshly requested job has none of
// archiveFilename/archiveSizeBytes/sha256/localPath/remotePath/errorMessage.
type backupJobJSON struct {
	ID               string     `json:"id"`
	JobType          string     `json:"jobType"`
	Trigger          string     `json:"trigger"`
	RequestedBy      *string    `json:"requestedBy,omitempty"`
	RequestedAt      time.Time  `json:"requestedAt"`
	StartedAt        *time.Time `json:"startedAt,omitempty"`
	FinishedAt       *time.Time `json:"finishedAt,omitempty"`
	Status           string     `json:"status"`
	ArchiveFilename  *string    `json:"archiveFilename,omitempty"`
	ArchiveSizeBytes *int64     `json:"archiveSizeBytes,omitempty"`
	SHA256           *string    `json:"sha256,omitempty"`
	LocalPath        *string    `json:"localPath,omitempty"`
	RemotePath       *string    `json:"remotePath,omitempty"`
	ErrorMessage     *string    `json:"errorMessage,omitempty"`
	RestoreOfID      *string    `json:"restoreOfId,omitempty"`
}

const backupJobSelectCols = `id, job_type, trigger, requested_by, requested_at, started_at,
	finished_at, status, archive_filename, archive_size_bytes, sha256,
	local_path, remote_path, error_message, restore_of_id`

func scanBackupJob(row interface {
	Scan(dest ...any) error
}) (backupJobJSON, error) {
	var j backupJobJSON
	err := row.Scan(&j.ID, &j.JobType, &j.Trigger, &j.RequestedBy, &j.RequestedAt, &j.StartedAt,
		&j.FinishedAt, &j.Status, &j.ArchiveFilename, &j.ArchiveSizeBytes, &j.SHA256,
		&j.LocalPath, &j.RemotePath, &j.ErrorMessage, &j.RestoreOfID)
	return j, err
}

// POST /api/backups — the console requests a backup; it never performs one.
// A host-side systemd timer (audspect-backup-worker.timer) polls for
// status='requested' rows and executes them. See
// docs/superpowers/specs/2026-08-17-backup-recovery-design.md.
func (h *Handler) CreateBackupJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var requestedBy *string
	if claims, ok := auth.ClaimsFrom(ctx); ok && claims != nil {
		requestedBy = &claims.UserID
	}
	row := h.db.QueryRow(ctx,
		`INSERT INTO backup_jobs (job_type, trigger, requested_by)
		 VALUES ('backup', 'console', $1)
		 RETURNING `+backupJobSelectCols,
		requestedBy,
	)
	job, err := scanBackupJob(row)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonOK(w, job)
}

// GET /api/backups — most recent backup jobs, newest first, for the Settings
// "Available backups" table. Excludes restore_marker rows.
func (h *Handler) ListBackupJobs(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT `+backupJobSelectCols+`
		 FROM backup_jobs WHERE job_type = 'backup'
		 ORDER BY requested_at DESC LIMIT 50`,
	)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := make([]backupJobJSON, 0, 16)
	for rows.Next() {
		job, err := scanBackupJob(rows)
		if err != nil {
			jsonError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out = append(out, job)
	}
	jsonOK(w, out)
}

// GET /api/backups/{id} — single job, for polling status after "Backup Now."
func (h *Handler) GetBackupJob(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	row := h.db.QueryRow(r.Context(),
		`SELECT `+backupJobSelectCols+` FROM backup_jobs WHERE id = $1`, id,
	)
	job, err := scanBackupJob(row)
	if err != nil {
		jsonError(w, "backup job not found", http.StatusNotFound)
		return
	}
	jsonOK(w, job)
}
