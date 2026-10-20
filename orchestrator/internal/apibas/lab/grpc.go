package lab

// gRPC route for Phase 28, in JSON transcoding form (see protocol.GRPC). OrderService/GetOrder is
// served on the same record as the REST route. The REST route checks ownership; the gRPC method does
// not in the vulnerable build (LAB-DISC-GRPC-001). The fixed build applies the REST check and returns
// PERMISSION_DENIED (403) to a caller who does not own the order.

import (
	"net/http"
	"strings"
)

func (s *Server) registerGRPC(mux *http.ServeMux) {
	mux.HandleFunc("POST /pkg.orders.v1.OrderService/GetOrder", s.grpcGetOrder)
}

// grpcFlaws lists the gRPC flaws.
func grpcFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-DISC-GRPC-001", ScenarioID: "API-BAS-DISC-009", Description: "pkg.orders.v1.OrderService/GetOrder returns the full record for any authenticated caller, where the REST route refuses another customer's order.", Oracle: "protected values of another customer's order appear in the gRPC response"},
	}
}

// grpcGetOrder answers GetOrder. The request is a JSON object with order_id.
func (s *Server) grpcGetOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		OrderID string `json:"order_id"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.OrderID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"code": "INVALID_ARGUMENT", "message": "order_id is required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[req.OrderID]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"code": "NOT_FOUND", "message": "order not found"})
		return
	}
	if s.vulnerable() {
		writeJSON(w, http.StatusOK, orderBody(o))
		return
	}
	if o.OwnerID != caller {
		writeJSON(w, http.StatusForbidden, map[string]string{"code": "PERMISSION_DENIED", "message": "order is not owned by the caller"})
		return
	}
	writeJSON(w, http.StatusOK, publicView(o))
}
