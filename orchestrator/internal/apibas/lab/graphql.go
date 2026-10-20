package lab

// GraphQL route for Phase 28. The route is POST /graphql and resolves a single root field, order(id).
// It uses the same parser as the GraphQL protocol adapter, so the lab and the adapter agree on what
// a query is. Each behaviour has a vulnerable branch with a LAB-* flaw and a fixed branch with the
// control.

import (
	"net/http"

	"github.com/audspect/bas/internal/apibas/protocol"
)

// graphqlMaxDepth is the deepest selection the fixed build executes. Deeper queries are refused
// with 400 before any resolver runs.
const graphqlMaxDepth = 3

func (s *Server) registerGraphQL(mux *http.ServeMux) {
	mux.HandleFunc("POST /graphql", s.graphqlQuery)
}

// graphqlFlaws lists the GraphQL flaws. The resolver's owner check is the flaw.
func graphqlFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-GQL-RESOLVER-001", ScenarioID: "API-BAS-INJ-007", Description: "POST /graphql resolves order(id) for any authenticated caller and returns the protected fields of the order, which the REST route refuses.", Oracle: "protected values of another customer's order appear in the GraphQL response"},
	}
}

// graphqlQuery resolves one root field. The vulnerable build returns the full record to any
// authenticated caller. The fixed build returns the public view to the owner only, and refuses
// a query deeper than graphqlMaxDepth.
func (s *Server) graphqlQuery(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		Query string `json:"query"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be a JSON object"})
		return
	}
	doc, err := protocol.ParseGraphQL(req.Query)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"message": err.Error()}}})
		return
	}
	if !s.vulnerable() && doc.Depth() > graphqlMaxDepth {
		writeJSON(w, http.StatusBadRequest, map[string]any{"errors": []map[string]string{{"message": "query depth exceeds the limit"}}})
		return
	}
	if len(doc.Fields) != 1 || doc.Fields[0].Name != "order" {
		writeJSON(w, http.StatusOK, map[string]any{"errors": []map[string]string{{"message": "only the order field is resolved"}}})
		return
	}
	field := doc.Fields[0]

	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[field.Args["id"]]
	if !found || (!s.vulnerable() && o.OwnerID != caller) {
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"order": nil}, "errors": []map[string]string{{"message": "order not found"}}})
		return
	}
	full := publicView(o)
	if s.vulnerable() {
		full = orderBody(o)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"order": resolveOrderObj(o, full, field.Sub)}})
}

// graphqlItemsPerOrder is the number of items each order's items relation returns. Each item points
// back to its order, so a selection that nests items nests the response by the same depth.
const graphqlItemsPerOrder = 2

// resolveOrderObj returns the selected fields of an order. The items relation is resolved only when it
// is selected, and each item resolves its own order back-reference. The resolver does not limit the
// depth it follows, which is the flaw in the vulnerable build; the fixed build refuses deep queries
// before a resolver runs.
func resolveOrderObj(o *Order, full map[string]any, sel []protocol.Field) map[string]any {
	if len(sel) == 0 {
		return full
	}
	out := map[string]any{}
	for _, f := range sel {
		if f.Name == "items" {
			items := make([]any, 0, graphqlItemsPerOrder)
			for i := 0; i < graphqlItemsPerOrder; i++ {
				items = append(items, resolveItemObj(o, full, f.Sub))
			}
			out["items"] = items
			continue
		}
		if v, ok := full[f.Name]; ok {
			out[f.Name] = v
		}
	}
	return out
}

// resolveItemObj returns the selected fields of one item. The only item field is order, which resolves
// the order the item belongs to.
func resolveItemObj(o *Order, full map[string]any, sel []protocol.Field) map[string]any {
	out := map[string]any{}
	for _, f := range sel {
		if f.Name == "order" {
			out["order"] = resolveOrderObj(o, full, f.Sub)
		}
	}
	return out
}
