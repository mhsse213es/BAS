// Package verification is the independent Verification Store for the Detection
// Validation Pack (SP2). It owns the persistence of analyst attestations and
// their evidence, decoupled from reporting: the Verification Engine and API
// connectors WRITE here, and reporting merely READS the current state. That
// separation is deliberate — SP3's API connectors write into the same store
// with verification_source='api' and touch no reporting code.
//
//	Simulation → Expected Detection → Verification Engine → Verification Store → Reporting
//
// History is append-only (audit-log semantics): a status is never overwritten
// in place. Each attestation supersedes the prior one and the full who/when/
// from-what/to-what chain is preserved. Evidence metadata is separated from the
// bytes so storage can move to filesystem/S3 later with no schema migration.
package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Verification result — what the analyst concluded about detection. Kept
// distinct from workflow state so a review pipeline can gate scoring.
const (
	ResultDetected      = "Detected"
	ResultNotDetected   = "NotDetected"
	ResultNotApplicable = "NotApplicable"
)

// Workflow state — where the attestation sits in the review pipeline. Only an
// Approved attestation feeds Coverage; everything else is treated as unresolved.
const (
	StatePending     = "Pending"
	StateNeedsReview = "NeedsReview"
	StateApproved    = "Approved"
	StateRejected    = "Rejected"
)

// Verification source — how the attestation was created. SP3 inserts
// SourceAPI with no other code changes; SourceMigration is for bulk import of
// historical assessments.
const (
	SourceAutomatic = "automatic"
	SourceManual    = "manual"
	SourceAPI       = "api"
	SourceImported  = "imported"
	SourceMigration = "migration"
)

// Evidence storage backends. Only StorageDatabase is wired today; the rest are
// accepted so a later move needs no schema change — only a new writer branch.
const (
	StorageDatabase   = "database"
	StorageFilesystem = "filesystem"
	StorageS3         = "s3"
	StorageAzureBlob  = "azureblob"
	StorageURL        = "url"
)

// HashSHA256 is the default (and today only) evidence hash algorithm. The
// column stores the algorithm so this can evolve without assuming SHA-256.
const HashSHA256 = "SHA-256"

// ErrConflict is returned when a concurrent attestation already produced the
// active row for this (run_id, expectation_id). The caller should map it to a
// 409 and have the client re-read and retry.
var ErrConflict = errors.New("verification: concurrent attestation conflict")

// Record is one row of verification_history.
type Record struct {
	ID             string    `json:"id"`
	RunID          string    `json:"runId"`
	ExpectationID  string    `json:"expectationId"`
	ProfileName    string    `json:"profileName"`
	ProfileVersion int       `json:"profileVersion"`
	TechniqueID    string    `json:"techniqueId"`
	Domain         string    `json:"domain"`
	Provider       string    `json:"provider"`
	Result         string    `json:"result"`
	WorkflowState  string    `json:"workflowState"`
	Source         string    `json:"source"`
	Note           string    `json:"note"`
	AlertID        string    `json:"alertId"`
	VerifiedBy     string    `json:"verifiedBy"`
	VerifiedAt     time.Time `json:"verifiedAt"`
	SupersedesID   string    `json:"supersedesId,omitempty"`
	Active         bool      `json:"active"`
	RuleIDs        []string  `json:"ruleIds,omitempty"`
}

// Evidence is one row of verification_evidence (metadata only; bytes live in
// the blob table when StorageType==StorageDatabase).
type Evidence struct {
	ID               string     `json:"id"`
	VerificationID   string     `json:"verificationId"`
	StorageType      string     `json:"storageType"`
	StorageKey       string     `json:"-"`
	HashAlgorithm    string     `json:"hashAlgorithm"`
	ContentHash      string     `json:"contentHash"`
	OriginalFilename string     `json:"originalFilename"`
	DisplayFilename  string     `json:"displayFilename"`
	MIME             string     `json:"mime"`
	Size             int64      `json:"size"`
	UploadedBy       string     `json:"uploadedBy"`
	UploadedAt       time.Time  `json:"uploadedAt"`
	Deleted          bool       `json:"deleted"`
	DeletedBy        string     `json:"deletedBy,omitempty"`
	DeletedAt        *time.Time `json:"deletedAt,omitempty"`
}

// AttestInput is the payload for a new attestation.
type AttestInput struct {
	RunID          string
	ExpectationID  string
	ProfileName    string
	ProfileVersion int
	TechniqueID    string
	Domain         string
	Provider       string
	Result         string
	WorkflowState  string
	Source         string
	Note           string
	AlertID        string
	VerifiedBy     string
	RuleIDs        []string
}

// EvidenceInput is the payload for an evidence upload. Bytes are hashed and
// stored; the caller supplies only descriptive metadata.
type EvidenceInput struct {
	VerificationID   string
	OriginalFilename string
	DisplayFilename  string
	MIME             string
	UploadedBy       string
	Bytes            []byte
}

// Store is the Verification Store handle.
type Store struct {
	db *pgxpool.Pool
}

// NewStore returns a Store backed by the given pool.
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const recordCols = `id, run_id, expectation_id, profile_name, profile_version,
	technique_id, domain, provider, result, workflow_state, verification_source,
	note, alert_id, verified_by, verified_at, supersedes_id, active, rule_ids`

func scanRecord(row pgx.Row) (Record, error) {
	var r Record
	err := row.Scan(&r.ID, &r.RunID, &r.ExpectationID, &r.ProfileName, &r.ProfileVersion,
		&r.TechniqueID, &r.Domain, &r.Provider, &r.Result, &r.WorkflowState, &r.Source,
		&r.Note, &r.AlertID, &r.VerifiedBy, &r.VerifiedAt, &r.SupersedesID, &r.Active, &r.RuleIDs)
	return r, err
}

// CurrentForRun returns the active attestation for every expectation in a run,
// keyed by expectation_id. Reporting consumes this to overlay manual/API
// verdicts on top of the automatic (on-host) engine.
func (s *Store) CurrentForRun(ctx context.Context, runID string) (map[string]Record, error) {
	rows, err := s.db.Query(ctx, `SELECT `+recordCols+`
		FROM verification_history WHERE run_id=$1 AND active`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Record{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out[r.ExpectationID] = r
	}
	return out, rows.Err()
}

// CurrentApprovedForRun returns the active, Approved attestation for every
// expectation in a run, as a slice (not a map — callers decide how to key
// or group; a map would bake in "one record per expectation" as an
// assumption this method should not own). Unlike CurrentForRun (all
// workflow states, used by reporting's manual/API overlay), this
// pre-filters to Approved so callers never repeat that filter.
func (s *Store) CurrentApprovedForRun(ctx context.Context, runID string) ([]Record, error) {
	rows, err := s.db.Query(ctx, `SELECT `+recordCols+`
		FROM verification_history WHERE run_id=$1 AND active AND workflow_state=$2`,
		runID, StateApproved)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// History returns the full immutable attestation chain for one expectation,
// newest first.
func (s *Store) History(ctx context.Context, runID, expectationID string) ([]Record, error) {
	rows, err := s.db.Query(ctx, `SELECT `+recordCols+`
		FROM verification_history
		WHERE run_id=$1 AND expectation_id=$2
		ORDER BY verified_at DESC, id DESC`, runID, expectationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns a single attestation by id.
func (s *Store) Get(ctx context.Context, id string) (Record, bool, error) {
	r, err := scanRecord(s.db.QueryRow(ctx, `SELECT `+recordCols+`
		FROM verification_history WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return r, true, nil
}

// Attest records a new attestation. It runs in one transaction: the prior
// active row (if any) is locked, superseded (active=false), then the new row is
// inserted active. The partial unique index on (run_id, expectation_id) WHERE
// active guarantees at most one active row even under concurrent writers; a
// losing writer gets ErrConflict.
func (s *Store) Attest(ctx context.Context, in AttestInput) (Record, error) {
	if in.WorkflowState == "" {
		in.WorkflowState = StateApproved
	}
	if in.Source == "" {
		in.Source = SourceManual
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback(ctx)

	// Lock and read the prior active row to serialize concurrent attestations.
	var priorID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM verification_history
		 WHERE run_id=$1 AND expectation_id=$2 AND active FOR UPDATE`,
		in.RunID, in.ExpectationID).Scan(&priorID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Record{}, err
	}
	if priorID != "" {
		if _, err := tx.Exec(ctx,
			`UPDATE verification_history SET active=false WHERE id=$1`, priorID); err != nil {
			return Record{}, err
		}
	}

	ruleIDs := in.RuleIDs
	if ruleIDs == nil {
		ruleIDs = []string{}
	}

	rec, err := scanRecord(tx.QueryRow(ctx,
		`INSERT INTO verification_history
			(run_id, expectation_id, profile_name, profile_version, technique_id,
			 domain, provider, result, workflow_state, verification_source,
			 note, alert_id, verified_by, supersedes_id, active, rule_ids)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,true,$15)
		 RETURNING `+recordCols,
		in.RunID, in.ExpectationID, in.ProfileName, in.ProfileVersion, in.TechniqueID,
		in.Domain, in.Provider, in.Result, in.WorkflowState, in.Source,
		in.Note, in.AlertID, in.VerifiedBy, priorID, ruleIDs))
	if err != nil {
		if isUniqueViolation(err) {
			return Record{}, ErrConflict
		}
		return Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		if isUniqueViolation(err) {
			return Record{}, ErrConflict
		}
		return Record{}, err
	}
	return rec, nil
}

// AddEvidence hashes the bytes (SHA-256), stores them in the blob table, and
// records the metadata row. Returns the stored metadata.
func (s *Store) AddEvidence(ctx context.Context, in EvidenceInput) (Evidence, error) {
	sum := sha256.Sum256(in.Bytes)
	hash := hex.EncodeToString(sum[:])
	if in.DisplayFilename == "" {
		in.DisplayFilename = in.OriginalFilename
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Evidence{}, err
	}
	defer tx.Rollback(ctx)

	var blobID string
	if err := tx.QueryRow(ctx,
		`INSERT INTO verification_evidence_blob (bytes) VALUES ($1) RETURNING id`,
		in.Bytes).Scan(&blobID); err != nil {
		return Evidence{}, err
	}

	var ev Evidence
	err = tx.QueryRow(ctx,
		`INSERT INTO verification_evidence
			(verification_id, storage_type, storage_key, hash_algorithm, content_hash,
			 original_filename, display_filename, mime, size, uploaded_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING id, verification_id, storage_type, storage_key, hash_algorithm,
			content_hash, original_filename, display_filename, mime, size,
			uploaded_by, uploaded_at, deleted, deleted_by, deleted_at`,
		in.VerificationID, StorageDatabase, blobID, HashSHA256, hash,
		in.OriginalFilename, in.DisplayFilename, in.MIME, int64(len(in.Bytes)), in.UploadedBy).
		Scan(&ev.ID, &ev.VerificationID, &ev.StorageType, &ev.StorageKey, &ev.HashAlgorithm,
			&ev.ContentHash, &ev.OriginalFilename, &ev.DisplayFilename, &ev.MIME, &ev.Size,
			&ev.UploadedBy, &ev.UploadedAt, &ev.Deleted, &ev.DeletedBy, &ev.DeletedAt)
	if err != nil {
		return Evidence{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Evidence{}, err
	}
	return ev, nil
}

const evidenceCols = `id, verification_id, storage_type, storage_key, hash_algorithm,
	content_hash, original_filename, display_filename, mime, size,
	uploaded_by, uploaded_at, deleted, deleted_by, deleted_at`

func scanEvidence(row pgx.Row) (Evidence, error) {
	var ev Evidence
	err := row.Scan(&ev.ID, &ev.VerificationID, &ev.StorageType, &ev.StorageKey, &ev.HashAlgorithm,
		&ev.ContentHash, &ev.OriginalFilename, &ev.DisplayFilename, &ev.MIME, &ev.Size,
		&ev.UploadedBy, &ev.UploadedAt, &ev.Deleted, &ev.DeletedBy, &ev.DeletedAt)
	return ev, err
}

// ListEvidence returns the non-deleted evidence for one verification, oldest
// first.
func (s *Store) ListEvidence(ctx context.Context, verificationID string) ([]Evidence, error) {
	rows, err := s.db.Query(ctx, `SELECT `+evidenceCols+`
		FROM verification_evidence
		WHERE verification_id=$1 AND NOT deleted
		ORDER BY uploaded_at ASC, id ASC`, verificationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		ev, err := scanEvidence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// EvidenceByID returns one evidence row (including deleted, so downloads of a
// just-deleted item 404 cleanly).
func (s *Store) EvidenceByID(ctx context.Context, id string) (Evidence, bool, error) {
	ev, err := scanEvidence(s.db.QueryRow(ctx, `SELECT `+evidenceCols+`
		FROM verification_evidence WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Evidence{}, false, nil
	}
	if err != nil {
		return Evidence{}, false, err
	}
	return ev, true, nil
}

// EvidenceBytes returns the stored bytes for a database-backed evidence item.
func (s *Store) EvidenceBytes(ctx context.Context, ev Evidence) ([]byte, error) {
	if ev.StorageType != StorageDatabase {
		return nil, errors.New("verification: bytes only available for database-backed evidence")
	}
	var b []byte
	if err := s.db.QueryRow(ctx,
		`SELECT bytes FROM verification_evidence_blob WHERE id=$1`, ev.StorageKey).Scan(&b); err != nil {
		return nil, err
	}
	return b, nil
}

// SoftDeleteEvidence marks an evidence item deleted, recording who and when.
// The row and its bytes are retained — evidence is audit material.
func (s *Store) SoftDeleteEvidence(ctx context.Context, id, deletedBy string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE verification_evidence
		 SET deleted=true, deleted_by=$2, deleted_at=NOW()
		 WHERE id=$1 AND NOT deleted`, id, deletedBy)
	return err
}

// EvidenceCountsForRun returns evidence counts keyed by verification_id for all
// active attestations of a run — used by reporting to show an Evidence column.
func (s *Store) EvidenceCountsForRun(ctx context.Context, runID string) (map[string]int, error) {
	rows, err := s.db.Query(ctx,
		`SELECT e.verification_id, COUNT(*)
		 FROM verification_evidence e
		 JOIN verification_history v ON v.id = e.verification_id
		 WHERE v.run_id=$1 AND v.active AND NOT e.deleted
		 GROUP BY e.verification_id`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var vid string
		var n int
		if err := rows.Scan(&vid, &n); err != nil {
			return nil, err
		}
		out[vid] = n
	}
	return out, rows.Err()
}

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505) — the losing side of a concurrent attestation.
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
