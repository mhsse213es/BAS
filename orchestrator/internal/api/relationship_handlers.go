package api

// CVE↔ATT&CK Relationship Store API — evidence-backed, confidence-scored
// technique-CVE relationships. Curation (CanCurateThreatIntel) creates/edits
// relationships and evidence; review (CanReviewThreatIntel) promotes/demotes
// effective confidence and changes lifecycle status. Every mutation is written
// to the existing audit log, capturing old/new confidence and rationale on edits.

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/relationships"
)

// WithRelationshipStore attaches the Relationship Store to the handler.
func (h *Handler) WithRelationshipStore(s *relationships.Store) *Handler {
	h.relationships = s
	return h
}

// ListTechniqueRelationships returns every relationship (any status) for a
// technique, with evidence counts.
// GET /api/techniques/{id}/relationships
func (h *Handler) ListTechniqueRelationships(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	techID := chi.URLParam(r, "id")
	list, err := h.relationships.ForTechnique(r.Context(), techID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ids := make([]string, len(list))
	for i, rel := range list {
		ids[i] = rel.ID
	}
	counts, _ := h.relationships.EvidenceCounts(r.Context(), ids)
	type withCount struct {
		relationships.Relationship
		EvidenceCount int `json:"evidenceCount"`
	}
	out := make([]withCount, len(list))
	for i, rel := range list {
		out[i] = withCount{Relationship: rel, EvidenceCount: counts[rel.ID]}
	}
	respond(w, map[string]any{"techniqueId": techID, "relationships": out})
}

// GetRelationship returns one relationship.
// GET /api/relationships/{id}
func (h *Handler) GetRelationship(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	rel, ok, err := h.relationships.Get(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		jsonError(w, "relationship not found", http.StatusNotFound)
		return
	}
	respond(w, rel)
}

// CreateRelationship creates a new technique↔CVE relationship. Requires
// CanCurateThreatIntel. Rejects a duplicate (technique,cve,type) triple.
// POST /api/relationships
func (h *Handler) CreateRelationship(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		TechniqueID        string `json:"techniqueId"`
		CVEID              string `json:"cveId"`
		RelationshipType   string `json:"relationshipType"`
		ProposedConfidence string `json:"proposedConfidence"`
		PrimarySource      string `json:"primarySource"`
		Rationale          string `json:"rationale"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.TechniqueID == "" || body.CVEID == "" {
		jsonError(w, "techniqueId and cveId are required", http.StatusBadRequest)
		return
	}
	if !validRelationshipType(body.RelationshipType) {
		jsonError(w, "invalid relationshipType", http.StatusBadRequest)
		return
	}
	if body.ProposedConfidence != "" && !validConfidence(body.ProposedConfidence) {
		jsonError(w, "invalid proposedConfidence", http.StatusBadRequest)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	rel, err := h.relationships.Create(r.Context(), relationships.CreateInput{
		TechniqueID: body.TechniqueID, CVEID: body.CVEID, RelationshipType: body.RelationshipType,
		ProposedConfidence: body.ProposedConfidence, PrimarySource: body.PrimarySource,
		Rationale: body.Rationale, CreatedBy: claims.UserID,
	})
	if errors.Is(err, relationships.ErrDuplicate) {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Relationship Created", "relationship:"+rel.ID, map[string]any{
		"techniqueId": body.TechniqueID, "cveId": body.CVEID,
		"relationshipType": body.RelationshipType, "confidence": rel.ProposedConfidence,
	}, "ok")
	respondStatus(w, rel, http.StatusCreated)
}

// UpdateRelationship edits the descriptive fields (type/proposed confidence/
// source/rationale). Requires CanCurateThreatIntel. Audits old/new confidence
// and rationale.
// PUT /api/relationships/{id}
func (h *Handler) UpdateRelationship(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		RelationshipType   string `json:"relationshipType"`
		ProposedConfidence string `json:"proposedConfidence"`
		PrimarySource      string `json:"primarySource"`
		Rationale          string `json:"rationale"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !validRelationshipType(body.RelationshipType) {
		jsonError(w, "invalid relationshipType", http.StatusBadRequest)
		return
	}
	if !validConfidence(body.ProposedConfidence) {
		jsonError(w, "invalid proposedConfidence", http.StatusBadRequest)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	res, err := h.relationships.Update(r.Context(), id, relationships.UpdateInput{
		RelationshipType: body.RelationshipType, ProposedConfidence: body.ProposedConfidence,
		PrimarySource: body.PrimarySource, Rationale: body.Rationale, UpdatedBy: claims.UserID,
	})
	if errors.Is(err, relationships.ErrDuplicate) {
		jsonError(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Relationship Updated", "relationship:"+id, map[string]any{
		"oldConfidence": res.OldConfidence, "newConfidence": res.Relationship.ProposedConfidence,
		"oldRationale": res.OldRationale, "newRationale": res.Relationship.Rationale,
	}, "ok")
	respond(w, res.Relationship)
}

// ReviewRelationship promotes or demotes effective_confidence independently of
// the creator's proposed_confidence. Requires CanReviewThreatIntel.
// POST /api/relationships/{id}/review
func (h *Handler) ReviewRelationship(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		EffectiveConfidence string `json:"effectiveConfidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !validConfidence(body.EffectiveConfidence) {
		jsonError(w, "valid effectiveConfidence is required", http.StatusBadRequest)
		return
	}
	prior, ok, err := h.relationships.Get(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		jsonError(w, "relationship not found", http.StatusNotFound)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	rel, err := h.relationships.Review(r.Context(), id, body.EffectiveConfidence, claims.UserID)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Relationship Reviewed", "relationship:"+id, map[string]any{
		"oldEffectiveConfidence": prior.EffectiveConfidence, "newEffectiveConfidence": rel.EffectiveConfidence,
	}, "ok")
	respond(w, rel)
}

// SetRelationshipStatus transitions the relationship lifecycle (retire,
// deprecate, dispute, or reactivate). Requires CanReviewThreatIntel.
// POST /api/relationships/{id}/status
func (h *Handler) SetRelationshipStatus(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !validStatus(body.Status) {
		jsonError(w, "valid status is required", http.StatusBadRequest)
		return
	}
	prior, ok, err := h.relationships.Get(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		jsonError(w, "relationship not found", http.StatusNotFound)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	rel, err := h.relationships.SetStatus(r.Context(), id, body.Status, claims.UserID, body.Reason)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Relationship Status Changed", "relationship:"+id, map[string]any{
		"oldStatus": prior.Status, "newStatus": rel.Status, "reason": body.Reason,
	}, "ok")
	respond(w, rel)
}

// AddRelationshipEvidence attaches a supporting reference to a relationship.
// Requires CanCurateThreatIntel.
// POST /api/relationships/{id}/evidence
func (h *Handler) AddRelationshipEvidence(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	if _, ok, err := h.relationships.Get(r.Context(), id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	} else if !ok {
		jsonError(w, "relationship not found", http.StatusNotFound)
		return
	}
	var body struct {
		Source         string `json:"source"`
		ReferenceType  string `json:"referenceType"`
		ReferenceValue string `json:"referenceValue"`
		Note           string `json:"note"`
		Priority       int    `json:"priority"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	ev, err := h.relationships.AddEvidence(r.Context(), relationships.EvidenceInput{
		RelationshipID: id, Source: body.Source, ReferenceType: body.ReferenceType,
		ReferenceValue: body.ReferenceValue, Note: body.Note, Priority: body.Priority,
		AddedBy: claims.UserID,
	})
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Relationship Evidence Added", "relationship:"+id, map[string]any{
		"evidenceId": ev.ID, "source": ev.Source, "referenceType": ev.ReferenceType,
	}, "ok")
	respondStatus(w, ev, http.StatusCreated)
}

// ListRelationshipEvidence lists non-deleted evidence for a relationship.
// GET /api/relationships/{id}/evidence
func (h *Handler) ListRelationshipEvidence(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	list, err := h.relationships.ListEvidence(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []relationships.Evidence{}
	}
	respond(w, map[string]any{"relationshipId": id, "evidence": list})
}

// DeleteRelationshipEvidence soft-deletes an evidence item. Requires
// CanCurateThreatIntel.
// DELETE /api/relationship-evidence/{id}
func (h *Handler) DeleteRelationshipEvidence(w http.ResponseWriter, r *http.Request) {
	if h.relationships == nil {
		jsonError(w, "relationship store unavailable", http.StatusServiceUnavailable)
		return
	}
	id := chi.URLParam(r, "id")
	ev, ok, err := h.relationships.EvidenceByID(r.Context(), id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || ev.Deleted {
		jsonError(w, "evidence not found", http.StatusNotFound)
		return
	}
	claims, _ := auth.ClaimsFrom(r.Context())
	if err := h.relationships.SoftDeleteEvidence(r.Context(), id, claims.UserID); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "Relationship Evidence Deleted", "relationship:"+ev.RelationshipID, map[string]any{
		"evidenceId": id,
	}, "ok")
	respond(w, map[string]any{"deleted": true})
}

// ── validation helpers ──────────────────────────────────────────────────────

func validRelationshipType(s string) bool {
	switch s {
	case relationships.TypeDirectExploitation, relationships.TypeObservedInTheWild,
		relationships.TypeCommonlyAssociated, relationships.TypePostExploitation,
		relationships.TypePrivilegeEscalation, relationships.TypePersistence:
		return true
	}
	return false
}

func validConfidence(s string) bool {
	switch s {
	case relationships.ConfidenceHigh, relationships.ConfidenceMedium, relationships.ConfidenceLow:
		return true
	}
	return false
}

func validStatus(s string) bool {
	switch s {
	case relationships.StatusActive, relationships.StatusDeprecated,
		relationships.StatusDisputed, relationships.StatusRetired:
		return true
	}
	return false
}
