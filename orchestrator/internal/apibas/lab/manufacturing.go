package lab

import (
	"encoding/json"
	"net/http"
	"sort"
)

// Manufacturing pack: production orders, bills of materials, purchase orders, machine assets, IoT devices and the OT
// management configuration (fixture.ManufacturingTwoPlant). Records live in the same pack store as the NBFC records
// (nbfcStore), which holds any fixture object that has a Kind; a fixture seeds one pack at a time. The vulnerable build trusts
// any authenticated caller on each route. The fixed build checks ownership or assignment, the caller's role, and never
// discloses a field outside the caller's projection.
//
// Machine commands are recorded as a status change in the lab. Nothing here drives real equipment.

func (s *Server) registerManufacturing(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/mfg/orders/{id}", s.mfgGetOrder)
	mux.HandleFunc("POST /api/mfg/orders/{id}/release", s.mfgReleaseOrder)
	mux.HandleFunc("GET /api/mfg/bom/{id}", s.mfgGetBOM)
	mux.HandleFunc("GET /api/mfg/purchase-orders/{id}", s.mfgGetOwned("purchase_order"))
	mux.HandleFunc("PATCH /api/mfg/purchase-orders/{id}", s.mfgPatchPurchaseOrder)
	mux.HandleFunc("GET /api/mfg/devices/{id}", s.mfgGetOwned("device"))
	mux.HandleFunc("GET /api/mfg/assets", s.mfgListAssets)
	mux.HandleFunc("POST /api/mfg/devices/{id}/command", s.mfgDeviceCommand)
	mux.HandleFunc("GET /api/mfg/ot/config/{id}", s.mfgOTConfig)
}

// mfgBody is a record as a caller may see it. Protected fields go to the owner only in the fixed build; the vulnerable build
// returns them to anyone who names the record.
func (s *Server) mfgBody(r nbfcRecord, caller string) map[string]any {
	body := map[string]any{"id": r.ID, "owner_id": r.OwnerID, "status": r.Status, "assignee": r.Assignee}
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

func notFound(w http.ResponseWriter, r *http.Request) {
	writeNBFCJSON(w, r, http.StatusNotFound, map[string]string{"error": "not found"})
}

// mfgGetOwned reads a record of one kind that only its owner may read: a purchase order or an IoT device record. The vulnerable
// build answers any authenticated caller. The fixed build answers the owner alone.
func (s *Server) mfgGetOwned(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, ok := s.requireCaller(w, r)
		if !ok {
			return
		}
		rec, found := s.nbfc.get(r.PathValue("id"))
		if !found || rec.Kind != kind || (!s.vulnerable() && caller != rec.OwnerID) {
			notFound(w, r)
			return
		}
		writeNBFCJSON(w, r, http.StatusOK, s.mfgBody(rec, caller))
	}
}

// mfgGetOrder reads a production order. The vulnerable build ignores plant ownership (cross-plant read). The fixed build
// answers the owning planner and the assigned operator only.
func (s *Server) mfgGetOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "production_order" || (!s.vulnerable() && !visibleTo(rec, caller)) {
		notFound(w, r)
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.mfgBody(rec, caller))
}

// mfgReleaseOrder releases a production order to the shop floor. The vulnerable build releases it for any authenticated caller,
// including an operator. The fixed build requires the owning planner (function-level authorization).
func (s *Server) mfgReleaseOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "production_order" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() {
		if !visibleToLocked(rec, caller) {
			notFound(w, r)
			return
		}
		if caller != rec.OwnerID || s.actorRole(caller) != "planner" {
			writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "only the owning planner can release an order"})
			return
		}
	}
	rec.Status = "released"
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "released"})
}

// visibleToLocked is visibleTo for a record the caller already holds under the store lock.
func visibleToLocked(r *nbfcRecord, caller string) bool {
	return caller == r.OwnerID || (r.Assignee != "" && caller == r.Assignee)
}

// mfgGetBOM reads a bill of materials. The vulnerable build returns the CAD reference and supplier cost to anyone who names
// the record. The fixed build answers the owning planner and the assigned operator of the parent order, and only the planner
// sees the CAD reference and cost.
func (s *Server) mfgGetBOM(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "bom" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() {
		parent, _ := s.nbfc.get(rec.Parent)
		if caller != rec.OwnerID && !(parent.Assignee != "" && caller == parent.Assignee) {
			notFound(w, r)
			return
		}
	}
	writeNBFCJSON(w, r, http.StatusOK, s.mfgBody(rec, caller))
}

// mfgPatchPurchaseOrder changes a purchase order's amount. The vulnerable build lets any authenticated caller change it,
// including another supplier. The fixed build lets only the owning supplier change it, and only while it is open.
func (s *Server) mfgPatchPurchaseOrder(w http.ResponseWriter, r *http.Request) {
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
	if !found || rec.Kind != "purchase_order" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() && (caller != rec.OwnerID || rec.Status != "open") {
		notFound(w, r)
		return
	}
	rec.Public["amount"] = req["amount"]
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

// mfgListAssets is the asset inventory and telemetry listing. The vulnerable build returns every plant's assets with their
// telemetry keys. The fixed build returns only the assets the caller owns or is assigned to, without telemetry keys for an
// operator.
func (s *Server) mfgListAssets(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.nbfc.mu.Lock()
	ids := make([]string, 0, len(s.nbfc.recs))
	for id, rec := range s.nbfc.recs {
		if rec.Kind != "asset" {
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
		out = append(out, s.mfgBody(rec, caller))
		disclosed = append(disclosed, rec.OwnerID)
	}
	noteResponseOwners(r, disclosed...)
	writeNBFCJSON(w, r, http.StatusOK, map[string]any{"assets": out})
}

// mfgDeviceCommand records a command to an IoT device. The vulnerable build accepts a command from any authenticated device or
// user for any device. The fixed build accepts it only from the device's own identity. The command is recorded as the device's
// status in the lab; no equipment is driven.
func (s *Server) mfgDeviceCommand(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["command"] == "" {
		writeNBFCJSON(w, r, http.StatusBadRequest, map[string]string{"error": "command is required"})
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "device" {
		notFound(w, r)
		return
	}
	if !s.vulnerable() && caller != rec.OwnerID {
		writeNBFCJSON(w, r, http.StatusForbidden, map[string]string{"error": "a device can command only itself"})
		return
	}
	rec.Status = req["command"] + "_requested"
	writeNBFCJSON(w, r, http.StatusOK, map[string]string{"id": id, "status": rec.Status})
}

// mfgOTConfig reads the OT management configuration. The vulnerable build serves it to any authenticated caller, so a plant IT
// identity reaches the OT management plane (IT/OT trust-boundary failure). The fixed build serves it only to the OT engineer
// who owns it.
func (s *Server) mfgOTConfig(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "ot_config" || (!s.vulnerable() && caller != rec.OwnerID) {
		notFound(w, r)
		return
	}
	writeNBFCJSON(w, r, http.StatusOK, s.mfgBody(rec, caller))
}
