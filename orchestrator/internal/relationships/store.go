// Package relationships is the CVE↔ATT&CK Relationship Store: evidence-backed,
// confidence-scored associations between a technique and a CVE, replacing the
// bare technique_cves join as the source of truth for KEV/EPSS scoring.
//
// A relationship records WHY it exists (type, rationale), HOW confident the
// claim is (proposed vs. reviewer-set effective confidence), and its lifecycle
// (status). Relationships are mutable curated content — not an audit ledger —
// so every change is instead written to the caller's audit log (old/new
// confidence + rationale in the detail payload).
package relationships

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Relationship types describe why a technique↔CVE link exists.
const (
	TypeDirectExploitation  = "Direct Exploitation"
	TypeObservedInTheWild   = "Observed In The Wild"
	TypeCommonlyAssociated  = "Commonly Associated"
	TypePostExploitation    = "Post Exploitation"
	TypePrivilegeEscalation = "Privilege Escalation"
	TypePersistence         = "Persistence"
)

// Confidence levels — set by the creator/editor as proposed_confidence; a
// reviewer may promote or demote effective_confidence independently.
const (
	ConfidenceHigh   = "High"   // direct exploitation documented by vendor/advisory
	ConfidenceMedium = "Medium" // widely observed in threat reports
	ConfidenceLow    = "Low"    // analyst hypothesis / illustrative
)

// Source identifies who/what asserted a relationship or evidence item. Text,
// not a DB enum, so a new source needs no migration.
const (
	SourceAnalyst         = "Analyst"
	SourceMicrosoft       = "Microsoft"
	SourceCISA            = "CISA"
	SourceVendorAdvisory  = "Vendor Advisory"
	SourceART             = "ART"
	SourceJointGovtReport = "Joint Government Report"
	SourceMigrated        = "Migrated"
	SourceOther           = "Other"
)

// Evidence reference types.
const (
	ReferenceURL          = "URL"
	ReferenceCVEAdvisory  = "CVE Advisory"
	ReferencePDF          = "PDF"
	ReferenceThreatReport = "Threat Report"
	ReferenceInternalNote = "Internal Note"
)

// Lifecycle status. Only Active relationships (with effective_confidence
// High/Medium) contribute to scoring; the rest remain visible for history.
const (
	StatusActive     = "Active"
	StatusDeprecated = "Deprecated"
	StatusDisputed   = "Disputed"
	StatusRetired    = "Retired"
)

// ErrDuplicate is returned when a (technique_id, cve_id, relationship_type)
// triple already exists.
var ErrDuplicate = errors.New("relationships: a relationship of this type already exists for this technique/CVE pair")

// Relationship is one row of technique_cve_relationships.
type Relationship struct {
	ID                  string     `json:"id"`
	TechniqueID         string     `json:"techniqueId"`
	CVEID               string     `json:"cveId"`
	RelationshipType    string     `json:"relationshipType"`
	ProposedConfidence  string     `json:"proposedConfidence"`
	EffectiveConfidence string     `json:"effectiveConfidence"`
	PrimarySource       string     `json:"primarySource"`
	Rationale           string     `json:"rationale"`
	Status              string     `json:"status"`
	StatusChangedBy     string     `json:"statusChangedBy,omitempty"`
	StatusChangedAt     *time.Time `json:"statusChangedAt,omitempty"`
	StatusReason        string     `json:"statusReason,omitempty"`
	CreatedBy           string     `json:"createdBy"`
	CreatedAt           time.Time  `json:"createdAt"`
	UpdatedBy           string     `json:"updatedBy"`
	UpdatedAt           time.Time  `json:"updatedAt"`
	ReviewedBy          string     `json:"reviewedBy,omitempty"`
	LastReviewedAt      *time.Time `json:"lastReviewedAt,omitempty"`
	ReviewDueAt         *time.Time `json:"reviewDueAt,omitempty"`
}

// Evidence is one row of relationship_evidence.
type Evidence struct {
	ID             string     `json:"id"`
	RelationshipID string     `json:"relationshipId"`
	Source         string     `json:"source"`
	ReferenceType  string     `json:"referenceType"`
	ReferenceValue string     `json:"referenceValue"`
	Note           string     `json:"note"`
	Priority       int        `json:"priority"`
	AddedBy        string     `json:"addedBy"`
	AddedAt        time.Time  `json:"addedAt"`
	Deleted        bool       `json:"deleted"`
	DeletedBy      string     `json:"deletedBy,omitempty"`
	DeletedAt      *time.Time `json:"deletedAt,omitempty"`
}

// CreateInput is the payload for a new relationship.
type CreateInput struct {
	TechniqueID        string
	CVEID              string
	RelationshipType   string
	ProposedConfidence string
	PrimarySource      string
	Rationale          string
	CreatedBy          string
}

// UpdateInput edits the descriptive fields of a relationship (not its
// lifecycle or effective confidence — see Review/SetStatus).
type UpdateInput struct {
	RelationshipType   string
	ProposedConfidence string
	PrimarySource      string
	Rationale          string
	UpdatedBy          string
}

// UpdateResult carries the before/after values so the caller can write a
// precise audit event.
type UpdateResult struct {
	Relationship  Relationship
	OldConfidence string
	OldRationale  string
}

// EvidenceInput is the payload for a new evidence item.
type EvidenceInput struct {
	RelationshipID string
	Source         string
	ReferenceType  string
	ReferenceValue string
	Note           string
	Priority       int
	AddedBy        string
}

// Store is the Relationship Store handle.
type Store struct {
	db *pgxpool.Pool
}

// NewStore returns a Store backed by the given pool.
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

const relCols = `id, technique_id, cve_id, relationship_type, proposed_confidence,
	effective_confidence, primary_source, rationale, status, status_changed_by,
	status_changed_at, status_reason, created_by, created_at, updated_by,
	updated_at, reviewed_by, last_reviewed_at, review_due_at`

func scanRel(row pgx.Row) (Relationship, error) {
	var r Relationship
	err := row.Scan(&r.ID, &r.TechniqueID, &r.CVEID, &r.RelationshipType, &r.ProposedConfidence,
		&r.EffectiveConfidence, &r.PrimarySource, &r.Rationale, &r.Status, &r.StatusChangedBy,
		&r.StatusChangedAt, &r.StatusReason, &r.CreatedBy, &r.CreatedAt, &r.UpdatedBy,
		&r.UpdatedAt, &r.ReviewedBy, &r.LastReviewedAt, &r.ReviewDueAt)
	return r, err
}

// ForTechnique returns all relationships for a technique (any status), newest
// first.
func (s *Store) ForTechnique(ctx context.Context, techniqueID string) ([]Relationship, error) {
	rows, err := s.db.Query(ctx, `SELECT `+relCols+`
		FROM technique_cve_relationships WHERE technique_id=$1
		ORDER BY created_at DESC`, techniqueID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Relationship
	for rows.Next() {
		r, err := scanRel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns a single relationship by id.
func (s *Store) Get(ctx context.Context, id string) (Relationship, bool, error) {
	r, err := scanRel(s.db.QueryRow(ctx, `SELECT `+relCols+`
		FROM technique_cve_relationships WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Relationship{}, false, nil
	}
	if err != nil {
		return Relationship{}, false, err
	}
	return r, true, nil
}

// Create inserts a new relationship. proposed_confidence and
// effective_confidence start identical — a reviewer diverges them later via
// Review. Returns ErrDuplicate if (technique_id, cve_id, relationship_type)
// already exists.
func (s *Store) Create(ctx context.Context, in CreateInput) (Relationship, error) {
	if in.ProposedConfidence == "" {
		in.ProposedConfidence = ConfidenceMedium
	}
	if in.PrimarySource == "" {
		in.PrimarySource = SourceAnalyst
	}
	r, err := scanRel(s.db.QueryRow(ctx, `
		INSERT INTO technique_cve_relationships
			(technique_id, cve_id, relationship_type, proposed_confidence,
			 effective_confidence, primary_source, rationale, created_by, updated_by)
		VALUES ($1,$2,$3,$4,$4,$5,$6,$7,$7)
		RETURNING `+relCols,
		in.TechniqueID, in.CVEID, in.RelationshipType, in.ProposedConfidence,
		in.PrimarySource, in.Rationale, in.CreatedBy))
	if err != nil {
		if isUniqueViolation(err) {
			return Relationship{}, ErrDuplicate
		}
		return Relationship{}, err
	}
	return r, nil
}

// Update edits the descriptive fields (type/proposed confidence/source/
// rationale). It does NOT touch effective_confidence or status. Returns the
// prior confidence/rationale so the caller can audit the delta.
func (s *Store) Update(ctx context.Context, id string, in UpdateInput) (UpdateResult, error) {
	prior, ok, err := s.Get(ctx, id)
	if err != nil {
		return UpdateResult{}, err
	}
	if !ok {
		return UpdateResult{}, pgx.ErrNoRows
	}
	r, err := scanRel(s.db.QueryRow(ctx, `
		UPDATE technique_cve_relationships
		SET relationship_type=$2, proposed_confidence=$3, primary_source=$4,
		    rationale=$5, updated_by=$6, updated_at=NOW()
		WHERE id=$1
		RETURNING `+relCols,
		id, in.RelationshipType, in.ProposedConfidence, in.PrimarySource, in.Rationale, in.UpdatedBy))
	if err != nil {
		if isUniqueViolation(err) {
			return UpdateResult{}, ErrDuplicate
		}
		return UpdateResult{}, err
	}
	return UpdateResult{Relationship: r, OldConfidence: prior.ProposedConfidence, OldRationale: prior.Rationale}, nil
}

// Review lets a reviewer promote or demote effective_confidence independently
// of the creator's proposed_confidence, recording the review timestamp.
func (s *Store) Review(ctx context.Context, id, effectiveConfidence, reviewedBy string) (Relationship, error) {
	return scanRel(s.db.QueryRow(ctx, `
		UPDATE technique_cve_relationships
		SET effective_confidence=$2, reviewed_by=$3, last_reviewed_at=NOW()
		WHERE id=$1
		RETURNING `+relCols, id, effectiveConfidence, reviewedBy))
}

// SetStatus transitions the relationship's lifecycle (Active → Deprecated /
// Disputed / Retired, or back to Active). Deprecated/Disputed/Retired
// relationships are excluded from scoring but remain visible for history.
func (s *Store) SetStatus(ctx context.Context, id, status, changedBy, reason string) (Relationship, error) {
	return scanRel(s.db.QueryRow(ctx, `
		UPDATE technique_cve_relationships
		SET status=$2, status_changed_by=$3, status_changed_at=NOW(), status_reason=$4
		WHERE id=$1
		RETURNING `+relCols, id, status, changedBy, reason))
}

const evCols = `id, relationship_id, source, reference_type, reference_value,
	note, priority, added_by, added_at, deleted, deleted_by, deleted_at`

func scanEv(row pgx.Row) (Evidence, error) {
	var e Evidence
	err := row.Scan(&e.ID, &e.RelationshipID, &e.Source, &e.ReferenceType, &e.ReferenceValue,
		&e.Note, &e.Priority, &e.AddedBy, &e.AddedAt, &e.Deleted, &e.DeletedBy, &e.DeletedAt)
	return e, err
}

// AddEvidence attaches a supporting reference to a relationship.
func (s *Store) AddEvidence(ctx context.Context, in EvidenceInput) (Evidence, error) {
	if in.Source == "" {
		in.Source = SourceAnalyst
	}
	if in.ReferenceType == "" {
		in.ReferenceType = ReferenceURL
	}
	return scanEv(s.db.QueryRow(ctx, `
		INSERT INTO relationship_evidence
			(relationship_id, source, reference_type, reference_value, note, priority, added_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING `+evCols,
		in.RelationshipID, in.Source, in.ReferenceType, in.ReferenceValue, in.Note, in.Priority, in.AddedBy))
}

// ListEvidence returns non-deleted evidence for a relationship, highest
// priority (lowest number) first, then oldest first.
func (s *Store) ListEvidence(ctx context.Context, relationshipID string) ([]Evidence, error) {
	rows, err := s.db.Query(ctx, `SELECT `+evCols+`
		FROM relationship_evidence
		WHERE relationship_id=$1 AND NOT deleted
		ORDER BY priority ASC, added_at ASC`, relationshipID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Evidence
	for rows.Next() {
		e, err := scanEv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// EvidenceByID returns one evidence row (including deleted).
func (s *Store) EvidenceByID(ctx context.Context, id string) (Evidence, bool, error) {
	e, err := scanEv(s.db.QueryRow(ctx, `SELECT `+evCols+`
		FROM relationship_evidence WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Evidence{}, false, nil
	}
	if err != nil {
		return Evidence{}, false, err
	}
	return e, true, nil
}

// SoftDeleteEvidence marks an evidence item deleted, recording who and when.
func (s *Store) SoftDeleteEvidence(ctx context.Context, id, deletedBy string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE relationship_evidence
		 SET deleted=true, deleted_by=$2, deleted_at=NOW()
		 WHERE id=$1 AND NOT deleted`, id, deletedBy)
	return err
}

// EvidenceCounts returns evidence counts keyed by relationship_id for a set of
// relationship ids.
func (s *Store) EvidenceCounts(ctx context.Context, relationshipIDs []string) (map[string]int, error) {
	if len(relationshipIDs) == 0 {
		return map[string]int{}, nil
	}
	rows, err := s.db.Query(ctx,
		`SELECT relationship_id, COUNT(*) FROM relationship_evidence
		 WHERE relationship_id = ANY($1) AND NOT deleted
		 GROUP BY relationship_id`, relationshipIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
