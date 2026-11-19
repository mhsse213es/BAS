package lab

import (
	"encoding/json"
	"net/http"
	"sort"
)

// Healthcare pack: patient records, prescriptions, laboratory results, medical images, FHIR observations and consents
// (fixture.HealthcareTwoPatient). Records live in the shared pack store (nbfcStore), which holds any fixture object that has a
// Kind; a fixture seeds one pack at a time. The vulnerable build trusts any authenticated caller on each route. The fixed build
// applies the treating relationship (owner or assigned clinician or registered device), honours a delegate's consent scope,
// and never discloses a protected field outside the caller's entitlement.

func (s *Server) registerHealthcare(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/health/records/{id}", s.hlGetRecord)
	mux.HandleFunc("GET /api/health/prescriptions/{id}", s.hlGetOwned("prescription"))
	mux.HandleFunc("PATCH /api/health/prescriptions/{id}", s.hlPatchPrescription)
	mux.HandleFunc("GET /api/health/lab-results/{id}", s.hlGetOwned("lab_result"))
	mux.HandleFunc("PATCH /api/health/lab-results/{id}", s.hlPatchLabResult)
	mux.HandleFunc("GET /api/health/images/{id}/download", s.hlDownloadImage)
	mux.HandleFunc("GET /api/health/fhir/Observation/{id}", s.hlFHIRObservation)
	mux.HandleFunc("GET /api/health/export", s.hlExport)
}

// hlBody is a record as a caller may see it. Protected fields go to the owner and the treating assignee in the fixed build; the
// vulnerable build returns them to anyone who names the record.
func (s *Server) hlBody(r nbfcRecord, caller string) map[string]any {
	body := map[string]any{"id": r.ID, "owner_id": r.OwnerID, "status": r.Status, "assignee": r.Assignee}
	for k, v := range r.Public {
		body[k] = v
	}
	if s.vulnerable() || caller == r.OwnerID || (r.Assignee != "" && caller == r.Assignee) {
		for k, v := range r.Protected {
			body[k] = v
		}
	}
	return body
}

// hasConsent reports whether the caller holds an active consent for the record. A consent here is summary-only.
func (n *nbfcStore) hasConsent(record, caller string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, c := range n.recs {
		if c.Kind == "consent" && c.Parent == record && c.Assignee == caller && c.Status == "active" {
			return true
		}
	}
	return false
}

// hlGetRecord reads a patient record. The vulnerable build ignores the treating relationship and consent scope. The fixed build
// answers the patient and the treating clinician in full, and a delegate with an active consent the public summary only.
func (s *Server) hlGetRecord(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "patient_record" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() && !visibleTo(rec, caller) {
		if s.nbfc.hasConsent(rec.ID, caller) {
			// A delegate sees the summary the consent allows, never the protected clinical fields.
			summary := map[string]any{"id": rec.ID, "status": rec.Status}
			for k, v := range rec.Public {
				summary[k] = v
			}
			writeNBFCJSON(w, r, http.StatusOK, summary)
			return
		}
		notFound(w, r)
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.hlBody(rec, caller))
}

// hlGetOwned reads a prescription or laboratory result. The vulnerable build answers any authenticated caller. The fixed build
// answers the owner and the assigned clinician or device.
func (s *Server) hlGetOwned(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := s.requireCaller(w, r)
		if !ok {
			return
		}
		rec, found := s.nbfc.get(r.PathValue("id"))
		if !found || rec.Kind != kind || (!s.vulnerable() && !visibleTo(rec, caller)) {
			notFound(w, r)
			return
		}
		writeNBFCJSON(w, r, http.StatusOK, s.hlBody(rec, caller))
	}
}

// hlPatchPrescription changes a prescription's dose. The vulnerable build lets any authenticated caller change it. The fixed
// build lets only the treating clinician change an active prescription.
func (s *Server) hlPatchPrescription(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["amount"] == "" {
		writeNBFCJSON(w, r, http.StatusBadRequest, map[string]string{"error": "amount is required"})
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "prescription" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() {
		if !visibleToLocked(rec, caller) {
			notFound(w, r)
			return
		}
		if caller != rec.Assignee || rec.Status != "active" {
			writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "only the treating clinician can change an active prescription"})
			return
		}
	}
	rec.Public["amount"] = req["amount"]
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

// hlPatchLabResult posts or amends a laboratory result value. The vulnerable build accepts it from any authenticated caller. The
// fixed build accepts it only from the device registered to the result, and only while the result is preliminary.
func (s *Server) hlPatchLabResult(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["amount"] == "" {
		writeNBFCJSON(w, r, http.StatusBadRequest, map[string]string{"error": "amount is required"})
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "lab_result" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() {
		if !visibleToLocked(rec, caller) {
			notFound(w, r)
			return
		}
		if caller != rec.Assignee || rec.Status != "preliminary" {
			writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "only the registered device can post a preliminary result"})
			return
		}
	}
	rec.Public["amount"] = req["amount"]
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

// hlDownloadImage returns the storage reference for a medical image. The vulnerable build serves any authenticated caller. The
// fixed build serves the patient and the treating clinician.
func (s *Server) hlDownloadImage(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "image" || (!s.vulnerable() && !visibleTo(rec, caller)) {
		notFound(w, r)
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.hlBody(rec, caller))
}

// hlFHIRObservation serves a laboratory result as a FHIR Observation. The vulnerable build skips resource-level authorization.
// The fixed build answers the subject patient and the registered device.
func (s *Server) hlFHIRObservation(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "lab_result" || (!s.vulnerable() && !visibleTo(rec, caller)) {
		notFound(w, r)
		return
	}
	obs := map[string]any{
		"resourceType": "Observation", "id": rec.ID, "status": rec.Status,
		"subject":       map[string]string{"reference": "Patient/" + rec.OwnerID},
		"code":          map[string]string{"text": rec.Public["test"]},
		"valueQuantity": map[string]string{"value": rec.Public["amount"]},
	}
	if s.vulnerable() || caller == rec.OwnerID || caller == rec.Assignee {
		obs["identifier"] = rec.Protected["report_ref"]
	}
	writeNBFCJSON(w, r, http.StatusOK, obs)
}

// hlExport is the records export. The vulnerable build exports every patient's record with its diagnosis. The fixed build
// exports only the records the caller owns or treats.
func (s *Server) hlExport(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.nbfc.mu.Lock()
	ids := make([]string, 0, len(s.nbfc.recs))
	for id, rec := range s.nbfc.recs {
		if rec.Kind != "patient_record" {
			continue
		}
		if s.vulnerable() || visibleToLocked(rec, caller) {
			ids = append(ids, id)
		}
	}
	s.nbfc.mu.Unlock()
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	disclosed := make([]string, 0, len(ids))
	for _, id := range ids {
		rec, _ := s.nbfc.get(id)
		out = append(out, s.hlBody(rec, caller))
		disclosed = append(disclosed, rec.OwnerID)
	}
	noteResponseOwners(r, disclosed...)
	writeNBFCJSON(w, r, http.StatusOK, map[string]any{"records": out})
}
