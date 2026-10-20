package lab

// SOAP route for Phase 28. POST /soap/orders takes an XML request naming an order. The vulnerable
// build resolves external entities declared in the DOCTYPE in-process: an entity whose SYSTEM
// identifier names an internal order record is replaced by that record, protected values included
// (LAB-INJ-XXE-001). The fixed build refuses any document that declares an external entity with 400.

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/audspect/bas/internal/apibas/protocol"
)

func (s *Server) registerSOAP(mux *http.ServeMux) {
	mux.HandleFunc("POST /soap/orders", s.soapOrders)
}

// soapFlaws lists the SOAP flaws.
func soapFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-INJ-XXE-001", ScenarioID: "API-BAS-INJ-005", Description: "POST /soap/orders resolves an external entity declared in the DOCTYPE, so an internal order record is returned to any authenticated caller.", Oracle: "protected values of an internal record appear in the SOAP response"},
	}
}

// soapOrders answers an order request. The envelope is parsed by the protocol package, which is the
// same parser the SOAP adapter uses.
func (s *Server) soapOrders(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		soapFault(w, http.StatusBadRequest, "request body could not be read")
		return
	}
	env, err := protocol.ParseSOAP(string(raw))
	if err != nil {
		soapFault(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(env.External) > 0 && !s.vulnerable() {
		soapFault(w, http.StatusBadRequest, "external entities are not permitted")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if name, ok := strings.CutPrefix(env.Order, "{{entity:"); ok {
		// The vulnerable build expands the entity: the SYSTEM identifier's last two path
		// segments name an internal order record.
		name = strings.TrimSuffix(name, "}}")
		o := internalOrderFor(env.External[name], s.orders)
		if o == nil {
			soapFault(w, http.StatusBadRequest, "entity could not be resolved")
			return
		}
		soapResponse(w, recordText(o))
		return
	}

	o, found := s.orders[strings.TrimSpace(env.Order)]
	if !found || (!s.vulnerable() && o.OwnerID != caller) {
		soapFault(w, http.StatusNotFound, "order not found")
		return
	}
	if s.vulnerable() {
		soapResponse(w, recordText(o))
		return
	}
	soapResponse(w, fmt.Sprint(publicView(o)))
}

// internalOrderFor returns the order named by an internal SYSTEM identifier of the form
// .../internal/orders/{id}, or nil when the identifier names nothing internal.
func internalOrderFor(sys string, orders map[string]*Order) *Order {
	id := path.Base(sys)
	if !strings.HasSuffix(path.Dir(sys), "/internal/orders") {
		return nil
	}
	return orders[id]
}

func soapResponse(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<?xml version=\"1.0\"?><response><order>%s</order></response>", body)
}

func soapFault(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<?xml version=\"1.0\"?><fault><reason>%s</reason></fault>", msg)
}
