package bfsisim

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// Transaction is one synthetic ledger entry used by the cobalt-group-bfsi-financial-impact
// scenarios (fin-01..07). Amount and Account are synthetic test values only.
type Transaction struct {
	ID      string  `json:"id"`
	Amount  float64 `json:"amount"`
	Account string  `json:"account"`
	Status  string  `json:"status,omitempty"`
}

// Ledger is an in-memory, mutex-guarded store of synthetic transactions. It exists only to give
// the financial-impact scenarios a deterministic, stateful target to mutate and verify against --
// it is never connected to a real core-banking, payment-gateway or ATM-switch system.
type Ledger struct {
	mu           sync.Mutex
	transactions map[string]Transaction
}

func newLedger() *Ledger {
	return &Ledger{transactions: make(map[string]Transaction)}
}

func (l *Ledger) create(tx Transaction) (created bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, exists := l.transactions[tx.ID]; exists {
		return false
	}
	l.transactions[tx.ID] = tx
	return true
}

func (l *Ledger) get(id string) (Transaction, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tx, ok := l.transactions[id]
	return tx, ok
}

func (l *Ledger) delete(id string) (existed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.transactions[id]; !ok {
		return false
	}
	delete(l.transactions, id)
	return true
}

func (l *Ledger) list() []Transaction {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Transaction, 0, len(l.transactions))
	for _, tx := range l.transactions {
		out = append(out, tx)
	}
	return out
}

func (l *Ledger) total() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	var sum float64
	for _, tx := range l.transactions {
		sum += tx.Amount
	}
	return sum
}

// registerLedgerRoutes wires the five ledger endpoints onto mux:
//
//	POST   /api/ledger/transactions          create (409 if the id already exists)
//	GET    /api/ledger/transactions           list all
//	GET    /api/ledger/transactions/{id}      fetch one (404 if absent)
//	DELETE /api/ledger/transactions/{id}      remove one (404 if absent; undo scripts tolerate this)
//	POST   /api/ledger/reconcile              body {"expectedTotal": float64} -> {"balanced": bool, "actualTotal": float64}
func (s *Simulator) registerLedgerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/ledger/transactions", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			var tx Transaction
			if err := json.NewDecoder(r.Body).Decode(&tx); err != nil || tx.ID == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if !s.ledger.create(tx) {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(s.ledger.list())
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/ledger/transactions/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/ledger/transactions/")
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			tx, ok := s.ledger.get(id)
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tx)
		case http.MethodDelete:
			if !s.ledger.delete(id) {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/ledger/reconcile", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			ExpectedTotal float64 `json:"expectedTotal"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		actual := s.ledger.total()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Balanced    bool    `json:"balanced"`
			ActualTotal float64 `json:"actualTotal"`
		}{Balanced: actual == req.ExpectedTotal, ActualTotal: actual})
	})
}

// Ledger returns the simulator's current transaction set, for test assertions.
func (s *Simulator) Ledger() []Transaction {
	return s.ledger.list()
}
