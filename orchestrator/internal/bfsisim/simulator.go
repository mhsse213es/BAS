// Package bfsisim is a deterministic BFSI service-discovery stub for the
// cobalt-group-bfsi-discovery scenarios (bfsi-01..04). It is a test target,
// not part of the orchestrator server, and returns only synthetic service
// names -- never credentials, account numbers or other sensitive data.
package bfsisim

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
)

// Service is one synthetic entry returned by a discovery endpoint.
type Service struct {
	ID string `json:"id"`
}

// Simulator serves the four discovery endpoints the cobalt-group-bfsi-discovery
// scenarios query: banking apps, payment gateways, ATM switches and
// cardholder-data locations.
type Simulator struct {
	srv *http.Server
	ln  net.Listener

	bankingApps  []Service
	gateways     []Service
	atmSwitches  []Service
	cardholderDS []Service

	ledger *Ledger
}

// NewSimulator builds a Simulator with a fixed synthetic catalog. addr is the
// listen address, e.g. "127.0.0.1:9999" or ":9999".
func NewSimulator(addr string) *Simulator {
	s := &Simulator{
		bankingApps:  []Service{{ID: "corebanking-prod-01"}, {ID: "corebanking-dr-01"}},
		gateways:     []Service{{ID: "paymentgateway-us-east"}, {ID: "paymentgateway-eu-west"}},
		atmSwitches:  []Service{{ID: "atmswitch-region1"}, {ID: "atmswitch-region2"}},
		cardholderDS: []Service{{ID: "cardholder-vault-primary"}},
		ledger:       newLedger(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/banking/apps", s.handle(s.bankingApps))
	mux.HandleFunc("/api/payments/gateways", s.handle(s.gateways))
	mux.HandleFunc("/api/atm/switches", s.handle(s.atmSwitches))
	mux.HandleFunc("/api/data/cardholder-locations", s.handle(s.cardholderDS))
	s.registerLedgerRoutes(mux)
	s.srv = &http.Server{Addr: addr, Handler: mux}
	return s
}

func (s *Simulator) handle(list []Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	}
}

// Start begins listening and serving in a background goroutine. It returns
// once the listener is bound, so callers can query Addr() right after.
func (s *Simulator) Start() error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go func() { _ = s.srv.Serve(ln) }()
	return nil
}

// Addr returns the bound address, including the actual port when the
// Simulator was constructed with a ":0" port.
func (s *Simulator) Addr() string {
	if s.ln == nil {
		return s.srv.Addr
	}
	return s.ln.Addr().String()
}

// Stop shuts the simulator down gracefully.
func (s *Simulator) Stop(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// RegisteredServices returns every synthetic service ID the simulator can
// return, across all four endpoints, for test assertions.
func (s *Simulator) RegisteredServices() []string {
	var out []string
	for _, l := range [][]Service{s.bankingApps, s.gateways, s.atmSwitches, s.cardholderDS} {
		for _, svc := range l {
			out = append(out, svc.ID)
		}
	}
	return out
}
