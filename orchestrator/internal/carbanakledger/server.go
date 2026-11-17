package carbanakledger

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"
)

type session struct {
	identity string
	host     string
	created  time.Time
}

type txn struct {
	id        string
	runID     string
	initiator string
	amount    int64
	approved  bool
}

// Server is the ledger HTTP API. Identity and the caller host come from the
// ledger's own config and the connection, never from request bodies.
type Server struct {
	cfg Config
	win Window
	log *Log
	now func() time.Time
	mux *http.ServeMux

	mu       sync.Mutex
	ids      map[string]*Identity
	sessions map[string]session
	txns     map[string]*txn
	nextTxn  int
}

func NewServer(cfg Config, log *Log, now func() time.Time) (*Server, error) {
	win, err := cfg.Window.Build()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		win:      win,
		log:      log,
		now:      now,
		mux:      http.NewServeMux(),
		ids:      make(map[string]*Identity, len(cfg.Identities)),
		sessions: make(map[string]session),
		txns:     make(map[string]*txn),
	}
	for i := range cfg.Identities {
		id := cfg.Identities[i]
		s.ids[id.ID] = &id
	}
	s.mux.HandleFunc("POST /session", s.handleSession)
	s.mux.HandleFunc("POST /beneficiary", s.handleBeneficiary)
	s.mux.HandleFunc("POST /transfer", s.handleTransfer)
	s.mux.HandleFunc("POST /approve", s.handleApprove)
	s.mux.HandleFunc("PUT /limit", s.handleLimit)
	s.mux.HandleFunc("GET /audit", s.handleAudit)
	s.mux.HandleFunc("GET /audit/verify", s.handleVerify)
	s.mux.HandleFunc("GET /alerts", s.handleAlerts)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

type request struct {
	SessionID       string `json:"session_id"`
	SecondSessionID string `json:"second_session_id"`
	Identity        string `json:"identity"`
	Token           string `json:"token"`
	RunID           string `json:"run_id"`
	Step            string `json:"step"`
	TxnID           string `json:"txn_id"`
	Amount          int64  `json:"amount"`
	Limit           int64  `json:"limit"`
}

type result struct {
	Decision  Decision `json:"decision"`
	RuleFired string   `json:"rule_fired"`
	AuditHash string   `json:"audit_hash"`
	SessionID string   `json:"session_id,omitempty"`
	TxnID     string   `json:"txn_id,omitempty"`
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failure is not recoverable
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func hasRole(id *Identity, role string) bool {
	return slices.Contains(id.Roles, role)
}

// record evaluates an action, appends it to the audit log, and returns the result.
func (s *Server) record(runID, step, actor, action string, a Action) (result, error) {
	d, rule := Evaluate(a, s.win)
	row, err := s.log.Append(runID, step, actor, action, d, rule, a.At)
	if err != nil {
		return result{}, err
	}
	return result{Decision: d, RuleFired: rule, AuditHash: row.Hash}, nil
}

// callerFor returns the caller's identity and the action context derived from
// the session and the connection. ok is false when the session is unknown.
func (s *Server) callerFor(r *http.Request, sessionID string) (*Identity, Action, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, Action{}, false
	}
	id := s.ids[sess.identity]
	now := s.now()
	ttl := time.Duration(s.cfg.SessionTTLSeconds) * time.Second
	return id, Action{
		Actor:             id.ID,
		At:                now,
		ApproverRole:      hasRole(id, "approver"),
		PrivilegedRole:    hasRole(id, "privileged"),
		Limit:             id.Limit,
		SameHostAsSession: remoteHost(r) == sess.host,
		SessionExpired:    ttl > 0 && now.Sub(sess.created) > ttl,
	}, true
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	s.mu.Lock()
	id, known := s.ids[req.Identity]
	valid := known && id.Token == req.Token
	s.mu.Unlock()

	if !valid {
		row, err := s.log.Append(req.RunID, req.Step, req.Identity, "session", Rejected, "invalid_credential", s.now())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result{Decision: Rejected, RuleFired: "invalid_credential", AuditHash: row.Hash})
		return
	}

	sid := newID()
	now := s.now()
	s.mu.Lock()
	s.sessions[sid] = session{identity: id.ID, host: remoteHost(r), created: now}
	s.mu.Unlock()

	res, err := s.record(req.RunID, req.Step, id.ID, "session", Action{
		Kind: "session", Actor: id.ID, At: now, SameHostAsSession: true,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	res.SessionID = sid
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleBeneficiary(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	id, a, ok := s.callerFor(r, req.SessionID)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unknown session")
		return
	}
	a.Kind = "beneficiary"
	if req.SecondSessionID != "" {
		second, _, ok := s.callerFor(r, req.SecondSessionID)
		a.SecondApproverPresent = ok && hasRole(second, "approver")
	}
	res, err := s.record(req.RunID, req.Step, id.ID, "beneficiary", a)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleTransfer(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	id, a, ok := s.callerFor(r, req.SessionID)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unknown session")
		return
	}
	a.Kind = "transfer"
	a.Amount = req.Amount
	res, err := s.record(req.RunID, req.Step, id.ID, "transfer", a)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.mu.Lock()
	s.nextTxn++
	tid := fmt.Sprintf("txn-%d", s.nextTxn)
	s.txns[tid] = &txn{id: tid, runID: req.RunID, initiator: id.ID, amount: req.Amount}
	s.mu.Unlock()
	res.TxnID = tid
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	approver, a, ok := s.callerFor(r, req.SessionID)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unknown session")
		return
	}
	s.mu.Lock()
	t, found := s.txns[req.TxnID]
	s.mu.Unlock()
	if !found {
		writeErr(w, http.StatusNotFound, "unknown transaction")
		return
	}

	a.Kind = "approve"
	a.Actor = t.initiator
	a.Approver = approver.ID
	res, err := s.record(req.RunID, req.Step, approver.ID, "approve", a)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.Decision == Approved {
		s.mu.Lock()
		t.approved = true
		s.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleLimit(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	caller, a, ok := s.callerFor(r, req.SessionID)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unknown session")
		return
	}
	a.Kind = "limit"
	res, err := s.record(req.RunID, req.Step, caller.ID, "limit", a)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if res.Decision == Approved {
		s.mu.Lock()
		caller.Limit = req.Limit
		s.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rows": s.log.Rows(r.URL.Query().Get("run_id"))})
}

func (s *Server) handleVerify(w http.ResponseWriter, _ *http.Request) {
	intact, bad := s.log.Verify()
	writeJSON(w, http.StatusOK, map[string]any{"intact": intact, "bad_index": bad})
}

// handleAlerts lists every non-approved decision in a run. Rejections and flags
// both count, because either one is a control firing.
func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	type alert struct {
		Step      string   `json:"step"`
		Decision  Decision `json:"decision"`
		RuleFired string   `json:"rule_fired"`
		AuditHash string   `json:"audit_hash"`
	}
	alerts := []alert{}
	for _, row := range s.log.Rows(r.URL.Query().Get("run_id")) {
		if row.Decision != Approved {
			alerts = append(alerts, alert{row.Step, row.Decision, row.RuleFired, row.Hash})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": alerts})
}
