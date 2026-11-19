package lab

import (
	"encoding/json"
	"net/http"
	"sort"
)

// Retail, logistics and telecom pack: retail orders, shipments, subscribers, SIMs, usage records, partner API keys and the
// carrier delivery callback (fixture.CommerceTelecomTwoTenant). Records live in the shared pack store (nbfcStore), which holds
// any fixture object that has a Kind; a fixture seeds one pack at a time. The vulnerable build trusts any authenticated caller
// on each route. The fixed build checks ownership and, where a route is staff- or carrier-only, the caller's role.
//
// A SIM swap and a partner scope change are recorded as a status change in the lab. Nothing is provisioned.

func (s *Server) registerCommerce(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/retail/shipments/{id}", s.mfgGetOwned("shipment"))
	mux.HandleFunc("PATCH /api/retail/shipments/{id}", s.comRedirectShipment)
	mux.HandleFunc("POST /api/retail/shipments/{id}/callback", s.comCarrierCallback)
	mux.HandleFunc("GET /api/retail/orders/{id}", s.mfgGetOwned("retail_order"))
	mux.HandleFunc("PATCH /api/retail/orders/{id}", s.comPatchOrder)
	mux.HandleFunc("GET /api/telecom/subscribers/{id}", s.mfgGetOwned("subscriber"))
	mux.HandleFunc("POST /api/telecom/sims/{id}/swap", s.comSwapSIM)
	mux.HandleFunc("GET /api/telecom/usage", s.comListUsage)
	mux.HandleFunc("GET /api/retail/partner-keys/{id}", s.mfgGetOwned("partner_key"))
	mux.HandleFunc("POST /api/retail/partner-keys/{id}/escalate", s.comEscalateKey)
}

// comRedirectShipment changes a shipment's delivery address. The vulnerable build lets any authenticated caller redirect any
// shipment. The fixed build lets only the owner redirect a shipment that has not been delivered.
func (s *Server) comRedirectShipment(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["address"] == "" {
		writeNBFCJSON(w, r, http.StatusBadRequest, map[string]string{"error": "address is required"})
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "shipment" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() && (caller != rec.OwnerID || rec.Status == "delivered") {
		notFound(w, r)
		return
	}
	rec.Status = "redirected"
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "redirected"})
}

// comCarrierCallback is the carrier's delivery callback. The vulnerable build accepts a delivery report from any authenticated
// caller, including the shopper whose shipment it is. The fixed build accepts it only from a caller whose role is carrier.
func (s *Server) comCarrierCallback(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["status"] == "" {
		writeNBFCJSON(w, r, http.StatusBadRequest, map[string]string{"error": "status is required"})
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "shipment" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() && s.actorRole(caller) != "carrier" {
		writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "only the carrier can report delivery"})
		return
	}
	rec.Status = req["status"]
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": rec.Status})
}

// comPatchOrder changes a retail order's amount. The vulnerable build lets the owner set the price of their own order. The
// fixed build refuses the owner and allows only a support agent (property-level authorization on the price).
func (s *Server) comPatchOrder(w http.ResponseWriter, r *http.Request) {
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
	if !found || rec.Kind != "retail_order" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() {
		if caller != rec.OwnerID && s.actorRole(caller) != "agent" {
			notFound(w, r)
			return
		}
		if s.actorRole(caller) != "agent" {
			writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "only support staff can change an order price"})
			return
		}
	}
	rec.Public["amount"] = req["amount"]
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

// comSwapSIM requests a SIM replacement. The vulnerable build accepts it from any authenticated caller for any line. The fixed
// build accepts it only from the line's owner and only while the SIM is active. The swap is recorded as a status; nothing is
// provisioned.
func (s *Server) comSwapSIM(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "sim" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() && (caller != rec.OwnerID || rec.Status != "active") {
		notFound(w, r)
		return
	}
	rec.Status = "swap_requested"
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "swap_requested"})
}

// comListUsage lists usage records. The vulnerable build returns every subscriber's usage with their call logs. The fixed build
// returns only the caller's own records.
func (s *Server) comListUsage(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.nbfc.mu.Lock()
	ids := make([]string, 0, len(s.nbfc.recs))
	for id, rec := range s.nbfc.recs {
		if rec.Kind != "usage" {
			continue
		}
		if s.vulnerable() || caller == rec.OwnerID {
			ids = append(ids, id)
		}
	}
	s.nbfc.mu.Unlock()
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	owners := make([]string, 0, len(ids))
	for _, id := range ids {
		rec, _ := s.nbfc.get(id)
		out = append(out, s.mfgBody(rec, caller))
		owners = append(owners, rec.OwnerID)
	}
	noteResponseOwners(r, owners...)
	writeNBFCJSON(w, r, http.StatusOK, map[string]any{"usage": out})
}

// comEscalateKey changes a partner API key's scope to write. The vulnerable build lets any authenticated caller escalate,
// including the partner whose key it is. The fixed build allows only a support agent.
func (s *Server) comEscalateKey(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "partner_key" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() && s.actorRole(caller) != "agent" {
		if caller != rec.OwnerID {
			notFound(w, r)
			return
		}
		writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "only support staff can change a key scope"})
		return
	}
	rec.Status = "write_scope"
	rec.Public["scope"] = "write"
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "write_scope"})
}
