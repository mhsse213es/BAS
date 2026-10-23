// Package bank is a synthetic bank API used as a benchmark target. It is never
// a real banking system and holds no real data. Every authorization and
// state-transition decision is delegated to a Policy.
package bank

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
)

//go:embed openapi.json
var openAPI []byte

const (
	RoleCustomer = "customer"
	RoleApprover = "approver"

	StateInitiated = "initiated"
	StateApproved  = "approved"
	StateSettled   = "settled"
)

// Principal is the authenticated caller.
type Principal struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

// Config configures a bank. Tokens maps bearer tokens to principals.
type Config struct {
	Policy Policy
	Tokens map[string]Principal
}

type Account struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Balance int64  `json:"balance"`
}

type Transaction struct {
	ID          string `json:"id"`
	AccountID   string `json:"account_id"`
	OwnerID     string `json:"owner_id"`
	Amount      int64  `json:"amount"`
	Description string `json:"description"`
}

type Beneficiary struct {
	ID            string `json:"id"`
	OwnerID       string `json:"owner_id"`
	Name          string `json:"name"`
	AccountNumber string `json:"account_number"`
}

type Payment struct {
	ID                string   `json:"id"`
	OwnerID           string   `json:"owner_id"`
	AccountID         string   `json:"account_id"`
	BeneficiaryID     string   `json:"beneficiary_id"`
	Amount            int64    `json:"amount"`
	State             string   `json:"state"`
	DualControl       bool     `json:"dual_control"`
	RequiredApprovals int      `json:"required_approvals"`
	Approvals         []string `json:"approvals"`
}

type Document struct {
	ID      string `json:"id"`
	OwnerID string `json:"owner_id"`
	Name    string `json:"name"`
}

// Server is the bank. Create with New.
type Server struct {
	pol    Policy
	tokens map[string]Principal

	mu       sync.Mutex
	seq      int
	accounts map[string]*Account
	txns     map[string]*Transaction
	idem     map[string]string
	bens     map[string]*Beneficiary
	pays     map[string]*Payment
	docs     map[string]*Document
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	p := cfg.Policy
	if p.CanReadAccount == nil || p.CanReadBeneficiary == nil || p.CanReadPayment == nil ||
		p.CanUseAccount == nil || p.CanReferenceBeneficiary == nil || p.CanModifyBeneficiary == nil ||
		p.CanModifyPayment == nil || p.CanRequestSettle == nil || p.ApprovalStillValid == nil ||
		p.DedupeIdempotency == nil || p.CanSettle == nil || p.CanApprove == nil ||
		p.CanReadDocument == nil || p.LegacyAuthorize == nil {
		return nil, errors.New("bank: every Policy function must be set")
	}
	return &Server{
		pol: p, tokens: cfg.Tokens,
		accounts: map[string]*Account{}, txns: map[string]*Transaction{}, idem: map[string]string{},
		bens: map[string]*Beneficiary{}, pays: map[string]*Payment{}, docs: map[string]*Document{},
	}, nil
}

func (s *Server) nextID(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s_%d", prefix, s.seq)
}

// AddAccount seeds an account.
func (s *Server) AddAccount(ownerID string, balance int64) Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := &Account{ID: s.nextID("acc"), OwnerID: ownerID, Balance: balance}
	s.accounts[a.ID] = a
	return *a
}

// AddDocument seeds a KYC document.
func (s *Server) AddDocument(ownerID, name string) Document {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := &Document{ID: s.nextID("doc"), OwnerID: ownerID, Name: name}
	s.docs[d.ID] = d
	return *d
}

// TransactionCount reports the number of stored transactions.
func (s *Server) TransactionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.txns)
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(openAPI)
	})
	legacy := func(kind string) func(Principal, string) bool {
		return func(p Principal, owner string) bool { return s.pol.LegacyAuthorize(p, kind, owner) }
	}
	mux.HandleFunc("GET /v1/accounts/{id}", s.auth(s.getAccount(legacy("account"))))
	mux.HandleFunc("GET /v1/transactions/{id}", s.auth(s.getTransaction(legacy("transaction"))))
	legacyDoc := func(p Principal, d Document, _ DocRoute) bool { return s.pol.LegacyAuthorize(p, "document", d.OwnerID) }
	mux.HandleFunc("GET /v1/kyc/documents/{id}", s.auth(s.getDocument(legacyDoc, DocRoutePrimary)))
	mux.HandleFunc("GET /v1/customers/{cid}/documents/{id}", s.auth(s.getDocument(legacyDoc, DocRouteAlternate)))

	mux.HandleFunc("GET /v2/accounts/{id}", s.auth(s.getAccount(func(p Principal, o string) bool { return s.pol.CanReadAccount(p, o) })))
	mux.HandleFunc("GET /v2/transactions/{id}", s.auth(s.getTransaction(func(p Principal, o string) bool { return s.pol.CanReadAccount(p, o) })))
	mux.HandleFunc("GET /v2/kyc/documents/{id}", s.auth(s.getDocument(func(p Principal, d Document, r DocRoute) bool { return s.pol.CanReadDocument(p, d, r) }, DocRoutePrimary)))
	mux.HandleFunc("GET /v2/customers/{cid}/documents/{id}", s.auth(s.getDocument(func(p Principal, d Document, r DocRoute) bool { return s.pol.CanReadDocument(p, d, r) }, DocRouteAlternate)))
	mux.HandleFunc("POST /v2/transactions", s.auth(s.createTransaction))
	mux.HandleFunc("POST /v2/beneficiaries", s.auth(s.createBeneficiary))
	mux.HandleFunc("GET /v2/beneficiaries/{id}", s.auth(s.getBeneficiary))
	mux.HandleFunc("PATCH /v2/beneficiaries/{id}", s.auth(s.patchBeneficiary))
	mux.HandleFunc("POST /v2/payments", s.auth(s.createPayment))
	mux.HandleFunc("GET /v2/payments/{id}", s.auth(s.getPayment))
	mux.HandleFunc("PATCH /v2/payments/{id}", s.auth(s.patchPayment))
	mux.HandleFunc("POST /v2/payments/{id}/approve", s.auth(s.approvePayment))
	mux.HandleFunc("POST /v2/payments/{id}/settle", s.auth(s.settlePayment))
	return mux
}

type handler func(w http.ResponseWriter, r *http.Request, p Principal)

// auth resolves the bearer token and serialises access to the in-memory state.
func (s *Server) auth(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		p, ok := s.tokens[tok]
		if tok == "" || !ok {
			writeErr(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		h(w, r, p)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v) == nil
}

func (s *Server) getAccount(read func(Principal, string) bool) handler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		a, ok := s.accounts[r.PathValue("id")]
		if !ok {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if !read(p, a.OwnerID) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(w, http.StatusOK, a)
	}
}

func (s *Server) getTransaction(read func(Principal, string) bool) handler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		t, ok := s.txns[r.PathValue("id")]
		if !ok {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if !read(p, t.OwnerID) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(w, http.StatusOK, t)
	}
}

// getDocument serves the primary endpoint and the alternate endpoint that
// addresses the document through its customer. The handler resolves the
// document by id only; the policy decides access for the given route.
func (s *Server) getDocument(read func(Principal, Document, DocRoute) bool, route DocRoute) handler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		d, ok := s.docs[r.PathValue("id")]
		if !ok {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if !read(p, *d, route) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		writeJSON(w, http.StatusOK, d)
	}
}

func (s *Server) createTransaction(w http.ResponseWriter, r *http.Request, p Principal) {
	var req struct {
		AccountID   string `json:"account_id"`
		Amount      int64  `json:"amount"`
		Description string `json:"description"`
	}
	if !decode(w, r, &req) || req.Amount <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	acct, ok := s.accounts[req.AccountID]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.pol.CanUseAccount(p, acct.OwnerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	var prior *Transaction
	if id, found := s.idem[key]; found {
		prior = s.txns[id]
	}
	if s.pol.DedupeIdempotency(p, key, prior) && prior != nil {
		writeJSON(w, http.StatusOK, prior)
		return
	}
	t := &Transaction{ID: s.nextID("txn"), AccountID: acct.ID, OwnerID: acct.OwnerID, Amount: req.Amount, Description: req.Description}
	s.txns[t.ID] = t
	if key != "" {
		s.idem[key] = t.ID
	}
	writeJSON(w, http.StatusCreated, t)
}

func (s *Server) createBeneficiary(w http.ResponseWriter, r *http.Request, p Principal) {
	var req struct {
		Name          string `json:"name"`
		AccountNumber string `json:"account_number"`
	}
	if !decode(w, r, &req) || req.Name == "" || req.AccountNumber == "" {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	b := &Beneficiary{ID: s.nextID("ben"), OwnerID: p.ID, Name: req.Name, AccountNumber: req.AccountNumber}
	s.bens[b.ID] = b
	writeJSON(w, http.StatusCreated, b)
}

func (s *Server) getBeneficiary(w http.ResponseWriter, r *http.Request, p Principal) {
	b, ok := s.bens[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.pol.CanReadBeneficiary(p, b.OwnerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) patchBeneficiary(w http.ResponseWriter, r *http.Request, p Principal) {
	b, ok := s.bens[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.pol.CanModifyBeneficiary(p, b.OwnerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req struct {
		Name          *string `json:"name"`
		AccountNumber *string `json:"account_number"`
	}
	if !decode(w, r, &req) {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Name != nil {
		b.Name = *req.Name
	}
	if req.AccountNumber != nil {
		b.AccountNumber = *req.AccountNumber
	}
	writeJSON(w, http.StatusOK, b)
}

func (s *Server) createPayment(w http.ResponseWriter, r *http.Request, p Principal) {
	var req struct {
		AccountID     string `json:"account_id"`
		BeneficiaryID string `json:"beneficiary_id"`
		Amount        int64  `json:"amount"`
		DualControl   bool   `json:"dual_control"`
	}
	if !decode(w, r, &req) || req.Amount <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	acct, aok := s.accounts[req.AccountID]
	ben, bok := s.bens[req.BeneficiaryID]
	if !aok || !bok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.pol.CanUseAccount(p, acct.OwnerID) || !s.pol.CanReferenceBeneficiary(p, ben.OwnerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	pay := &Payment{
		ID: s.nextID("pay"), OwnerID: p.ID, AccountID: acct.ID, BeneficiaryID: ben.ID, Amount: req.Amount,
		State: StateInitiated, DualControl: req.DualControl, RequiredApprovals: 1, Approvals: []string{},
	}
	if req.DualControl {
		pay.RequiredApprovals = 2
	}
	s.pays[pay.ID] = pay
	writeJSON(w, http.StatusCreated, pay)
}

func (s *Server) getPayment(w http.ResponseWriter, r *http.Request, p Principal) {
	pay, ok := s.pays[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.pol.CanReadPayment(p, pay.OwnerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, pay)
}

func (s *Server) patchPayment(w http.ResponseWriter, r *http.Request, p Principal) {
	pay, ok := s.pays[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.pol.CanModifyPayment(p, pay.OwnerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	var req struct {
		Amount        *int64  `json:"amount"`
		BeneficiaryID *string `json:"beneficiary_id"`
	}
	if !decode(w, r, &req) || (req.Amount != nil && *req.Amount <= 0) {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	if pay.State == StateSettled {
		writeErr(w, http.StatusConflict, "payment already settled")
		return
	}
	amt, benID := pay.Amount, pay.BeneficiaryID
	if req.Amount != nil {
		amt = *req.Amount
	}
	if req.BeneficiaryID != nil {
		nb, found := s.bens[*req.BeneficiaryID]
		if !found {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if !s.pol.CanReferenceBeneficiary(p, nb.OwnerID) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		benID = nb.ID
	}
	revoked := false
	if len(pay.Approvals) > 0 && !s.pol.ApprovalStillValid(*pay, amt, benID) {
		pay.Approvals = []string{}
		pay.State = StateInitiated
		revoked = true
	}
	pay.Amount, pay.BeneficiaryID = amt, benID
	if revoked {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "approval invalidated by change", "payment": pay})
		return
	}
	writeJSON(w, http.StatusOK, pay)
}

func (s *Server) approvePayment(w http.ResponseWriter, r *http.Request, p Principal) {
	pay, ok := s.pays[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if pay.State == StateSettled {
		writeErr(w, http.StatusConflict, "payment already settled")
		return
	}
	if !s.pol.CanApprove(p, *pay) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	pay.Approvals = append(pay.Approvals, p.ID)
	if len(pay.Approvals) >= pay.RequiredApprovals {
		pay.State = StateApproved
	}
	writeJSON(w, http.StatusOK, pay)
}

func (s *Server) settlePayment(w http.ResponseWriter, r *http.Request, p Principal) {
	pay, ok := s.pays[r.PathValue("id")]
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	if !s.pol.CanRequestSettle(p, pay.OwnerID) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if pay.State == StateSettled || !s.pol.CanSettle(*pay) {
		writeErr(w, http.StatusConflict, "payment not authorized for settlement")
		return
	}
	pay.State = StateSettled
	writeJSON(w, http.StatusOK, pay)
}
