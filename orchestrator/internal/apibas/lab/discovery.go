package lab

// Discovery tranche (API-BAS-DISC-001, 004, 007, 008). Each route carries a vulnerable branch
// with a LAB-DISC-* flaw and a fixed branch that enforces the control. The OpenAPI document is
// served in both builds, because publishing a specification is normal. The findings are the
// gaps between the specification and the deployed behaviour, and the documentation and error
// exposure around it.

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// drift routes and the orphaned route are documented or not as the spec below says.
const driftPath = "/api/drift/orders/{id}"

// openAPISpec describes the API. It declares /api/drift/orders/{id} as requiring a bearer
// token. It does not declare the orphaned route.
func openAPISpec() map[string]any {
	bearer := []map[string][]string{{"bearerAuth": {}}}
	return map[string]any{
		"openapi": "3.0.3",
		"info":    map[string]any{"title": "Orders API", "version": "1.0.0"},
		"components": map[string]any{
			"securitySchemes": map[string]any{
				"bearerAuth": map[string]any{"type": "http", "scheme": "bearer"},
			},
		},
		"paths": map[string]any{
			"/api/orders/{id}": map[string]any{
				"get": map[string]any{"security": bearer, "responses": map[string]any{"200": map[string]any{"description": "order"}}},
			},
			"/api/drift/orders/{id}": map[string]any{
				"get": map[string]any{"security": bearer, "responses": map[string]any{"200": map[string]any{"description": "order"}}},
			},
		},
	}
}

func (s *Server) registerDiscovery(mux *http.ServeMux) {
	mux.HandleFunc("GET /openapi.json", s.discOpenAPI)
	mux.HandleFunc("GET /api/disc/orders/{id}", s.discOrder)
	mux.HandleFunc("GET "+driftPath, s.discDrift)
	if s.vulnerable() {
		// LAB-DISC-ORPHAN-001: a retired route still served, not in the specification.
		mux.HandleFunc("GET /api/orphan/orders/{id}", s.discOrphan)
		// LAB-DISC-DOCS-001: interactive documentation with a real record as its example.
		mux.HandleFunc("GET /docs", s.discDocs)
	}
}

func (s *Server) discOpenAPI(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, openAPISpec())
}

// discOrder returns the owner's public view. An unknown order returns a generic 404. The
// vulnerable build also sends the backend host in a header (LAB-DISC-ERR-001).
func (s *Server) discOrder(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	o, found := s.orders[r.PathValue("id")]
	owned := found && o.OwnerID == caller
	var view map[string]any
	if owned {
		view = publicView(o)
	}
	s.mu.Unlock()
	if !owned {
		if s.vulnerable() {
			w.Header().Set("X-Backend-Host", "orders-db-03.internal")
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// discDrift is the route the specification says needs a bearer token. The fixed build
// enforces that token and ownership. The vulnerable build serves the full record with no
// credential (LAB-DISC-DRIFT-001).
func (s *Server) discDrift(w http.ResponseWriter, r *http.Request) {
	if s.vulnerable() {
		s.mu.Lock()
		o, found := s.orders[r.PathValue("id")]
		var body map[string]any
		if found {
			body = orderBody(o)
		}
		s.mu.Unlock()
		if !found {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
			return
		}
		writeJSON(w, http.StatusOK, body)
		return
	}
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	o, found := s.orders[r.PathValue("id")]
	owned := found && o.OwnerID == caller
	var view map[string]any
	if owned {
		view = publicView(o)
	}
	s.mu.Unlock()
	if !owned {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// discOrphan is the retired route, served in the vulnerable build only. It requires a token
// but does not check ownership.
func (s *Server) discOrphan(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	s.mu.Lock()
	o, found := s.orders[r.PathValue("id")]
	var body map[string]any
	if found {
		body = orderBody(o)
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// discDocs serves interactive documentation. Its example is a real record, protected values
// included (LAB-DISC-DOCS-001).
func (s *Server) discDocs(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	example, _ := json.MarshalIndent(orderBody(s.orders["ORD-2001"]), "", "  ")
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "<!doctype html><title>Orders API docs</title><h1>GET /api/orders/{id}</h1><p>Example response:</p><pre>%s</pre>", example)
}

// discFlaws names the planted discovery flaws. Each is present only in ModeVulnerable.
func discFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-DISC-ORPHAN-001", ScenarioID: "API-BAS-DISC-001", Description: "GET /api/orphan/orders/{id} is served but absent from the specification, and does not check ownership.", Oracle: "protected values of another customer's order appear in the response"},
		{ID: "LAB-DISC-DRIFT-001", ScenarioID: "API-BAS-DISC-004", Description: "GET /api/drift/orders/{id} is declared as requiring a bearer token in the specification and serves the full record with none.", Oracle: "protected values of an order appear with no credential"},
		{ID: "LAB-DISC-DOCS-001", ScenarioID: "API-BAS-DISC-007", Description: "GET /docs is served publicly, with a real record as its example.", Oracle: "protected values of an order appear in the documentation"},
		{ID: "LAB-DISC-ERR-001", ScenarioID: "API-BAS-DISC-008", Description: "A not-found response carries the backend host in X-Backend-Host.", Oracle: "the internal backend host appears in a response header"},
	}
}
