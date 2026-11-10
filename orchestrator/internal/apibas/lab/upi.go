package lab

import (
	"net/http"
)

// UPI / open-banking pack: VPA-linked accounts, UPI transactions, standing-instruction mandates and Account Aggregator
// consent artifacts (fixture.UPITwoCustomer). Records live in the shared pack store (nbfcStore), the same way the healthcare
// and manufacturing packs do. The vulnerable build trusts any authenticated caller on each route, and never checks a
// consent's status. The fixed build checks ownership (or, for a mandate, the assigned merchant), and refuses a fetch against
// a consent that is not active.

func (s *Server) registerUPI(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/upi/transactions/{id}", s.upiGetTransaction)
	mux.HandleFunc("GET /api/upi/vpa/{id}", s.upiGetVPA)
	mux.HandleFunc("GET /api/upi/mandates/{id}", s.upiGetMandate)
	mux.HandleFunc("POST /api/upi/mandates/{id}/execute", s.upiExecuteMandate)
	mux.HandleFunc("GET /api/upi/consent/{id}/fetch", s.upiConsentFetch)
	mux.HandleFunc("GET /api/upi/vpa/validate", s.upiValidateVPA)
}

// upiBody is a pack record as a caller may see it. Protected fields go to the owner in the fixed build; the vulnerable
// build returns them to anyone who names the record.
func (s *Server) upiBody(r nbfcRecord, caller string) map[string]any {
	body := map[string]any{"id": r.ID, "owner_id": r.OwnerID, "status": r.Status}
	for k, v := range r.Public {
		body[k] = v
	}
	if s.vulnerable() || caller == r.OwnerID {
		for k, v := range r.Protected {
			body[k] = v
		}
	}
	return body
}

// upiGetTransaction answers a transaction read. The vulnerable build ignores ownership. The fixed build answers the owner
// only, and refuses with 404 otherwise, disclosing nothing about a transaction that belongs to someone else.
func (s *Server) upiGetTransaction(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "transaction" || (!s.vulnerable() && caller != rec.OwnerID) {
		writeNBFCJSON(w, r, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.upiBody(rec, caller))
}

// upiGetVPA answers a VPA read. The vulnerable build returns the linked account to anyone who names the VPA. The fixed
// build returns it to the VPA's owner alone.
func (s *Server) upiGetVPA(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "vpa" || (!s.vulnerable() && caller != rec.OwnerID) {
		writeNBFCJSON(w, r, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.upiBody(rec, caller))
}

// upiGetMandate answers a mandate read. The vulnerable build returns the debit account and the cap to anyone who names the
// mandate. The fixed build answers the owner and the assigned merchant, but discloses the protected fields to the owner
// alone.
func (s *Server) upiGetMandate(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	visible := found && rec.Kind == "mandate" && (s.vulnerable() || visibleTo(rec, caller))
	if !visible {
		writeNBFCJSON(w, r, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.upiBody(rec, caller))
}

// upiExecuteMandate executes one debit under a standing instruction. The vulnerable build lets any authenticated caller
// trigger it. The fixed build requires the merchant assigned to the mandate (API-BAS-AUTHZ-503): the counterparty entitled
// to collect, not an arbitrary caller and not the customer themselves.
func (s *Server) upiExecuteMandate(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "mandate" {
		writeNBFCJSON(w, r, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !s.vulnerable() && (rec.Assignee == "" || caller != rec.Assignee) {
		writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "not the assigned merchant"})
		return
	}
	rec.Status = "executed"
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "executed"})
}

// upiConsentFetch answers an Account Aggregator financial-information fetch against a named consent artifact. The
// vulnerable build serves the linked financial data whatever the consent's status, including a revoked one (API-BAS-
// DATA-501). The fixed build refuses the fetch unless the consent's status is "active", and never discloses the linked
// accounts of a consent that is not.
func (s *Server) upiConsentFetch(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "consent" || (!s.vulnerable() && caller != rec.OwnerID) {
		writeNBFCJSON(w, r, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !s.vulnerable() && rec.Status != "active" {
		writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "consent is not active"})
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.upiBody(rec, caller))
}

// upiValidateVPA answers a VPA-existence check. It is the endpoint a UPI app calls before paying a handle, and the one an
// attacker hammers to enumerate valid VPAs. It shares the gateway's rate counter (gateway.go): the vulnerable build keys
// the limit on a client-supplied source address, so rotating that header never reaches the threshold (API-BAS-GWAY-501);
// the fixed build keys it on the authenticated caller.
func (s *Server) upiValidateVPA(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	if s.gwOverLimit(s.gwRateKey(r)) {
		writeNBFCJSON(w, r, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
		return
	}
	handle := r.URL.Query().Get("handle")
	s.nbfc.mu.Lock()
	exists := false
	for _, rec := range s.nbfc.recs {
		if rec.Kind == "vpa" && rec.Public["handle"] == handle {
			exists = true
			break
		}
	}
	s.nbfc.mu.Unlock()
	writeNBFCJSON(w, r, http.StatusOK, map[string]any{"handle": handle, "valid": exists})
}
