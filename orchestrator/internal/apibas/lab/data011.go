package lab

import "net/http"

// eraseOrder handles a customer's erasure request for their own order (DATA-011). The vulnerable build acknowledges the
// request and removes nothing, so the record stays readable. The fixed build removes the record, so a later read is 404.
func (s *Server) eraseOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.mu.Lock()
	order, found := s.orders[id]
	owned := found && order.OwnerID == caller
	if owned && !s.vulnerable() {
		delete(s.orders, id)
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !owned {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	if s.vulnerable() {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "erasure requested"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "erased"})
}
