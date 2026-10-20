package lab

// Phase 37: ABUSE-006 (expensive downstream validation) and ABUSE-007 (paid-service consumption).
//
// Each route calls a downstream boundary once per accepted request. The boundary is a function inside the lab
// process with its own per-run counter, standing in for a second service: the product's request is what
// triggers the downstream work. It is not a separate listener, so network-level behaviour is not tested.
// The fixed build limits the downstream-triggering requests per run and caller, and refuses the rest with 429
// before any downstream call is made.

import "net/http"

const (
	validatorLimit = 5 // downstream validations per run and caller in the fixed build
	smsLimit       = 3 // paid SMS sends per run and caller in the fixed build
)

func (s *Server) registerPaid(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/validate/order-lines", s.validateOrderLines)
	mux.HandleFunc("POST /api/auth/otp/send", s.otpSend)
}

// countUnder records one downstream-triggering request under key and reports whether it is within limit.
// It is separate from gwOverLimit, which uses the gateway's fixed limit.
func (s *Server) countUnder(key string, limit int) bool {
	s.gwMu.Lock()
	defer s.gwMu.Unlock()
	if s.gwCounts == nil {
		s.gwCounts = map[string]int{}
	}
	s.gwCounts[key]++
	return s.gwCounts[key] <= limit
}

// downstreamValidator is the validation boundary: each call does one unit of downstream work for the run.
// It returns the number of calls made so far for that run.
func (s *Server) downstreamValidator(run string) int {
	s.gwMu.Lock()
	defer s.gwMu.Unlock()
	if s.validatorCalls == nil {
		s.validatorCalls = map[string]int{}
	}
	s.validatorCalls[run]++
	return s.validatorCalls[run]
}

// validateOrderLines checks an order line against the downstream validator. The vulnerable build calls the
// validator for every request, with no limit (LAB-ABUSE-VALIDATE-001). The fixed build refuses the request
// with 429 once the caller passes validatorLimit in a run, before any downstream call.
func (s *Server) validateOrderLines(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	run := r.Header.Get("X-BAS-Run")
	if !s.vulnerable() && !s.countUnder("validate|"+run+"|"+caller, validatorLimit) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "validation limit reached for this run"})
		return
	}
	s.downstreamValidator(run)
	writeJSON(w, http.StatusOK, map[string]string{"status": "valid"})
}

// otpSend sends a one-time code by SMS. Each send consumes a paid unit at the provider. The vulnerable build
// sends for every request, with no limit (LAB-ABUSE-OTP-001). The fixed build refuses sends above smsLimit in
// a run and caller with 429, so no paid unit is consumed.
func (s *Server) otpSend(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		Phone string `json:"phone"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Phone == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "phone is required"})
		return
	}
	run := r.Header.Get("X-BAS-Run")
	if !s.vulnerable() && !s.countUnder("otp|"+run+"|"+caller, smsLimit) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "send limit reached for this run"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
}
