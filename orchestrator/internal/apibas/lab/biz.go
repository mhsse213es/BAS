package lab

// Phase 3 business-logic routes (BIZ-001, 003 to 011). Each route has a vulnerable branch with a planted flaw and
// a fixed branch with the control. Per-run counters are keyed by the run tag, so one run does not affect another.
// The oracles are in Flaws(); the expectations are in the catalog and the runner tests.

import (
	"io"
	"net/http"
	"time"
)

// bizRaceWindow is how long the vulnerable withdrawal holds between its balance check and its update. Concurrent
// requests that arrive inside it all pass the check (BIZ-005).
const bizRaceWindow = 100 * time.Millisecond

// bizTransferLimit is the transfers one caller may make in a run in the fixed build (BIZ-008).
const bizTransferLimit = 3

// bizStepUpCode is the verification code the fixed build requires for a beneficiary change (BIZ-009).
const bizStepUpCode = "BAS-STEPUP-OK"

// bizNextStatus is the only transition the fixed build allows from each status (BIZ-006).
var bizNextStatus = map[string]string{"pending": "approved", "approved": "shipped"}

func (s *Server) registerBiz(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/biz/orders/{id}/refund", s.bizRefund)
	mux.HandleFunc("POST /api/biz/orders/{id}/credit", s.bizCredit)
	mux.HandleFunc("POST /api/biz/payments", s.bizPayment)
	mux.HandleFunc("POST /api/biz/orders/{id}/withdraw", s.bizWithdraw)
	mux.HandleFunc("PATCH /api/biz/orders/{id}/status", s.bizStatus)
	mux.HandleFunc("POST /api/biz/orders/{id}/approve-payout", s.bizApprovePayout)
	mux.HandleFunc("POST /api/biz/transfers", s.bizTransfer)
	mux.HandleFunc("PATCH /api/biz/orders/{id}/beneficiary", s.bizBeneficiary)
	mux.HandleFunc("POST /api/biz/coupons/redeem", s.bizCoupon)
	mux.HandleFunc("POST /api/biz/reservations", s.bizReserve)
}

// bizFlaws names the planted flaws of the Phase 3 business routes. Each names the scenario that must detect it.
func bizFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-BIZ-REFUND-001", ScenarioID: "API-BAS-BIZ-001", Description: "POST /api/biz/orders/{id}/refund lets any authenticated customer refund an order; refunds need a support role.", Oracle: "the order status becomes refunded for a caller who is not support staff"},
		{ID: "LAB-BIZ-REPLAY-001", ScenarioID: "API-BAS-BIZ-003", Description: "POST /api/biz/orders/{id}/credit applies a credit for every request and ignores the transaction id.", Oracle: "more credits are accepted for one transaction id in a run than the declared maximum"},
		{ID: "LAB-BIZ-IDEM-001", ScenarioID: "API-BAS-BIZ-004", Description: "POST /api/biz/payments ignores Idempotency-Key, so a reused key with a different body is processed again.", Oracle: "more payments are accepted for one idempotency key in a run than the declared maximum"},
		{ID: "LAB-BIZ-RACE-001", ScenarioID: "API-BAS-BIZ-005", Description: "POST /api/biz/orders/{id}/withdraw checks the balance and updates it in two steps with a window between them.", Oracle: "more withdrawals than the balance allows are accepted from concurrent requests in one run"},
		{ID: "LAB-BIZ-FLOW-001", ScenarioID: "API-BAS-BIZ-006", Description: "PATCH /api/biz/orders/{id}/status accepts any status, so an order can skip approval.", Oracle: "the order moves from pending to shipped without approval"},
		{ID: "LAB-BIZ-MAKER-001", ScenarioID: "API-BAS-BIZ-007", Description: "POST /api/biz/orders/{id}/approve-payout does not refuse the maker approving their own payout.", Oracle: "the payout is approved by the customer who owns the order"},
		{ID: "LAB-BIZ-VELOCITY-001", ScenarioID: "API-BAS-BIZ-008", Description: "POST /api/biz/transfers has no limit on transfers per run and caller.", Oracle: "more transfers are accepted for one caller in a run than the declared maximum"},
		{ID: "LAB-BIZ-BENEF-001", ScenarioID: "API-BAS-BIZ-009", Description: "PATCH /api/biz/orders/{id}/beneficiary changes the beneficiary without a verification step.", Oracle: "the beneficiary reference changes without the verification code"},
		{ID: "LAB-BIZ-COUPON-001", ScenarioID: "API-BAS-BIZ-010", Description: "POST /api/biz/coupons/redeem allows the same coupon to be redeemed again by the same customer.", Oracle: "the same coupon is redeemed more than once by one customer in a run"},
		{ID: "LAB-BIZ-STOCK-001", ScenarioID: "API-BAS-BIZ-011", Description: "POST /api/biz/reservations does not check stock, so a limited item is oversold.", Oracle: "more reservations are accepted for a limited item in a run than its stock allows"},
	}
}

// bizRefund refunds an order. Only the fixed build checks the caller's role (BIZ-001).
func (s *Server) bizRefund(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	if !s.vulnerable() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "refunds need a support role"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	o.Status = "refunded"
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// bizCredit applies a credit for a transaction. The fixed build applies each transaction id once (BIZ-003).
func (s *Server) bizCredit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	var req struct {
		Txn string `json:"txn"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Txn == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "txn is required"})
		return
	}
	s.mu.Lock()
	_, found := s.orders[r.PathValue("id")]
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	key := "txn|" + r.Header.Get("X-BAS-Run") + "|" + r.PathValue("id") + "|" + req.Txn
	if !s.vulnerable() && !s.countUnder(key, 1) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "transaction already processed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "credited"})
}

// bizKeyed records the body each idempotency key was first used with, in the fixed build. Reuse with a different
// body is refused with 422 (BIZ-004). The key includes the run tag and the caller, so runs and callers are isolated.
func (s *Server) bizKeyed(key, body string) int {
	s.gwMu.Lock()
	defer s.gwMu.Unlock()
	if s.bizKeys == nil {
		s.bizKeys = map[string]string{}
	}
	prev, seen := s.bizKeys[key]
	switch {
	case !seen:
		s.bizKeys[key] = body
		return http.StatusOK
	case prev == body:
		return http.StatusOK
	default:
		return http.StatusUnprocessableEntity
	}
}

func (s *Server) bizPayment(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	idem := r.Header.Get("Idempotency-Key")
	if idem == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Idempotency-Key is required"})
		return
	}
	if !s.vulnerable() {
		key := r.Header.Get("X-BAS-Run") + "|" + caller + "|" + idem
		if status := s.bizKeyed(key, string(raw)); status != http.StatusOK {
			writeJSON(w, status, map[string]string{"error": "idempotency key reused with a different body"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "paid"})
}

// bizWithdraw is a check-then-act withdrawal. The fixed build takes the unit atomically. The vulnerable build
// checks, waits, then updates, so concurrent requests all pass the check (BIZ-005).
func (s *Server) bizWithdraw(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	s.mu.Lock()
	_, found := s.orders[r.PathValue("id")]
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	key := "withdraw|" + r.Header.Get("X-BAS-Run") + "|" + r.PathValue("id")
	if !s.vulnerable() {
		if !s.countUnder(key, 1) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "insufficient balance"})
			return
		}
	} else {
		s.gwMu.Lock()
		used := s.gwCounts[key]
		s.gwMu.Unlock()
		if used >= 1 {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "insufficient balance"})
			return
		}
		time.Sleep(bizRaceWindow)
		s.bizBump(key)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "withdrawn"})
}

// bizBump records one accepted request under key. It is the unconditional increment the vulnerable build makes
// after its window. The counter map is created on first use.
func (s *Server) bizBump(key string) {
	s.gwMu.Lock()
	defer s.gwMu.Unlock()
	if s.gwCounts == nil {
		s.gwCounts = map[string]int{}
	}
	s.gwCounts[key]++
}

// bizStatus moves an order to a new status. The fixed build allows only the next step (BIZ-006).
func (s *Server) bizStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Status == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status is required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if !s.vulnerable() && bizNextStatus[o.Status] != req.Status {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "invalid status transition"})
		return
	}
	o.Status = req.Status
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// bizApprovePayout approves a payout. The fixed build refuses the maker approving their own payout. The maker of an
// order's payout is its owner (BIZ-007).
func (s *Server) bizApprovePayout(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if !s.vulnerable() && caller == o.OwnerID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "maker cannot approve their own payout"})
		return
	}
	o.Status = "payout_approved"
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// bizTransfer accepts a transfer. The fixed build limits transfers per run and caller (BIZ-008).
func (s *Server) bizTransfer(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	key := "transfer|" + r.Header.Get("X-BAS-Run") + "|" + caller
	if !s.vulnerable() && !s.countUnder(key, bizTransferLimit) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "transfer limit reached for this run"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// bizBeneficiary changes an order's payout beneficiary. The fixed build needs the verification code (BIZ-009).
func (s *Server) bizBeneficiary(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	var req struct {
		Ref string `json:"beneficiary_ref"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Ref == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "beneficiary_ref is required"})
		return
	}
	if !s.vulnerable() && r.Header.Get("X-Verification-Code") != bizStepUpCode {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "verification required"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	o.Beneficiary = req.Ref
	writeJSON(w, http.StatusOK, map[string]string{"beneficiary_ref": o.Beneficiary})
}

// bizCoupon redeems a coupon. The fixed build redeems each coupon once per caller and run (BIZ-010).
func (s *Server) bizCoupon(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "code is required"})
		return
	}
	key := "coupon|" + r.Header.Get("X-BAS-Run") + "|" + caller + "|" + req.Code
	if !s.vulnerable() && !s.countUnder(key, 1) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "coupon already redeemed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "redeemed"})
}

// bizReserve reserves a limited item. The fixed build has one unit of each SKU per run (BIZ-011).
func (s *Server) bizReserve(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	var req struct {
		SKU string `json:"sku"`
	}
	if err := decodeJSON(r, &req); err != nil || req.SKU == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "sku is required"})
		return
	}
	key := "stock|" + r.Header.Get("X-BAS-Run") + "|" + req.SKU
	if !s.vulnerable() && !s.countUnder(key, 1) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "out of stock"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reserved"})
}
