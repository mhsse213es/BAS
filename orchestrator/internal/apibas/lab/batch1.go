package lab

// Phase 3 batch 1: AUTHN-010 (step-up for a sensitive action) and DATA-007 (export leaks protected fields).
// Both are in-process HTTP routes. Their oracles are in Flaws(); expectations are in the catalog and runner tests.

import "net/http"

// stepUpCode is the step-up verification the fixed build requires before a sensitive action (AUTHN-010). It is the
// same proof the beneficiary change uses (biz.go), so one verification path covers both.
const stepUpCode = bizStepUpCode

func (s *Server) registerBatch1(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/orders/{id}/close", s.closeOrder)
	mux.HandleFunc("GET /api/orders/{id}/export", s.exportOrder)
}

func batch1Flaws() []Flaw {
	return []Flaw{
		{ID: "LAB-AUTHN-STEPUP-001", ScenarioID: "API-BAS-AUTHN-010", Description: "POST /api/orders/{id}/close is a sensitive action that needs a step-up verification; the vulnerable build does not check it.", Oracle: "the order is closed without the step-up code"},
		{ID: "LAB-DATA-EXPORT-001", ScenarioID: "API-BAS-DATA-007", Description: "GET /api/orders/{id}/export includes protected fields (card and account references) that the export must never carry.", Oracle: "a protected field value appears in the export response"},
	}
}

// closeOrder closes an order. A sensitive action needs step-up in the fixed build (AUTHN-010).
func (s *Server) closeOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	if !s.vulnerable() && r.Header.Get("X-Step-Up") != stepUpCode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "step-up verification required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	o.Status = "closed"
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// exportOrder returns an order for download. The fixed build exports public fields only (DATA-007).
func (s *Server) exportOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	out := map[string]any{"id": o.ID, "status": o.Status, "public": o.Public}
	if s.vulnerable() {
		out["protected"] = o.Protected
	}
	writeJSON(w, http.StatusOK, out)
}
