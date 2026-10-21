package lab

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/audspect/bas/internal/apibas/fixture"
)

// NBFC pack: borrowers, loans, KYC records and repayments (fixture.NBFCTwoBorrower). Each route reads and writes a record
// kept in nbfcStore. The vulnerable build trusts any authenticated caller on each route. The fixed build checks ownership, or
// assignment to the record's loan officer, and never discloses a field outside the caller's projection.

// nbfcRecord is one domain record of the pack.
type nbfcRecord struct {
	ID        string
	Kind      string
	OwnerID   string
	Parent    string
	Assignee  string
	Status    string
	Public    map[string]string
	Protected map[string]string
	// PreparedBy is the officer who prepared a loan decision. The fixed build refuses approval by the same officer.
	PreparedBy string
}

// nbfcStore holds the pack's records. It is separate from the orders store, so pack records are served only by pack routes.
type nbfcStore struct {
	mu   sync.Mutex
	recs map[string]*nbfcRecord
	// auditLog records every administrative attempt on the pack, in both builds. See AuditRecord.
	auditLog []AuditRecord
	auditSeq int
}

// AuditRecord is one administrative attempt on the pack. Outcome is what the build did: the vulnerable build records "allowed"
// for a caller the policy refuses, so the audit shows the weakness as it happened. Reason is set when the attempt is denied.
type AuditRecord struct {
	Seq        int       `json:"seq"`
	Identity   string    `json:"identity"`
	Role       string    `json:"role"`
	Action     string    `json:"action"`
	Target     string    `json:"target"`
	Permission string    `json:"permission"`
	Outcome    string    `json:"outcome"`
	Reason     string    `json:"reason,omitempty"`
	At         time.Time `json:"at"`
}

// audit appends one attempt.
func (n *nbfcStore) audit(rec AuditRecord) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.auditSeq++
	rec.Seq = n.auditSeq
	rec.At = time.Now().UTC()
	n.auditLog = append(n.auditLog, rec)
}

// auditSnapshot returns a copy of the audit log.
func (n *nbfcStore) auditSnapshot() []AuditRecord {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]AuditRecord(nil), n.auditLog...)
}

// seed loads every fixture object that belongs to the pack.
func (n *nbfcStore) seed(objects []fixture.Object) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.auditLog = nil
	n.auditSeq = 0
	n.recs = make(map[string]*nbfcRecord)
	for _, o := range objects {
		if o.Kind == "" {
			continue
		}
		n.recs[o.ID] = &nbfcRecord{
			ID: o.ID, Kind: o.Kind, OwnerID: o.OwnerID, Parent: o.Parent, Assignee: o.Assignee, Status: o.Status,
			Public: copyMap(o.Public), Protected: copyMap(o.Protected),
		}
	}
}

// get returns a copy of the record, so a handler never holds the store's lock while it writes a response.
func (n *nbfcStore) get(id string) (nbfcRecord, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, ok := n.recs[id]
	if !ok {
		return nbfcRecord{}, false
	}
	return copyRecord(r), true
}

func copyRecord(r *nbfcRecord) nbfcRecord {
	c := *r
	c.Public = copyMap(r.Public)
	c.Protected = copyMap(r.Protected)
	return c
}

// owners returns the owner of every pack record whose ID the request path names. Access events attribute a pack request
// through this, the same way they attribute an order request.
func (n *nbfcStore) owners(path string) []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	var ids []string
	for id := range n.recs {
		if strings.Contains(path, id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var out []string
	for _, id := range ids {
		out = appendOwner(out, n.recs[id].OwnerID)
	}
	return out
}

// stateRecords returns the pack's records in the shape the state adapter compares: status, owner, and the amount.
func (n *nbfcStore) stateRecords() []OrderState {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]OrderState, 0, len(n.recs))
	for _, r := range n.recs {
		out = append(out, OrderState{ID: r.ID, OwnerID: r.OwnerID, Status: r.Status, Quantity: r.Public["amount"]})
	}
	return out
}

// visibleTo reports whether the caller may see the record at all: its owner, or the officer it is assigned to.
func visibleTo(r nbfcRecord, caller string) bool {
	return caller == r.OwnerID || (r.Assignee != "" && caller == r.Assignee)
}

func (s *Server) registerNBFC(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/nbfc/loans", s.nbfcListLoans)
	mux.HandleFunc("GET /api/nbfc/loans/{id}", s.nbfcGetLoan)
	mux.HandleFunc("PATCH /api/nbfc/loans/{id}", s.nbfcPatchLoan)
	mux.HandleFunc("GET /api/nbfc/loans/{id}/statement", s.nbfcStatement)
	mux.HandleFunc("POST /api/nbfc/loans/{id}/prepare", s.nbfcPrepare)
	mux.HandleFunc("POST /api/nbfc/loans/{id}/decision", s.nbfcDecision)
	mux.HandleFunc("GET /api/nbfc/kyc/{id}", s.nbfcGetKYC)
	mux.HandleFunc("PATCH /api/nbfc/repayments/{id}", s.nbfcPatchRepayment)
	mux.HandleFunc("GET /api/nbfc/admin/loans/{id}", s.nbfcAdminLoan)
	mux.HandleFunc("GET /api/nbfc/admin/kyc/{id}", s.nbfcAdminKYC)
	mux.HandleFunc("GET /lab/nbfc/audit", s.adminOnly(s.nbfcAuditLog))
}

// identityOf returns the fixture identity a caller ID names.
func (s *Server) identityOf(caller string) (fixture.Identity, bool) {
	for _, id := range s.cfg.Fixture.Identities {
		if id.CustomerID == caller {
			return id, true
		}
	}
	return fixture.Identity{}, false
}

// actorRole is the role the access event records for an identity: the fixture role for a named identity, "customer" for any
// other authenticated identity, and empty for a request that was not authenticated.
func (s *Server) actorRole(identity string) string {
	switch identity {
	case "", "anonymous", "unknown":
		return ""
	}
	if id, ok := s.identityOf(identity); ok && id.Role != "" {
		return id.Role
	}
	return "customer"
}

// hasGrant reports whether a caller holds an explicit grant. A role alone is not a grant.
func (s *Server) hasGrant(caller, permission string) bool {
	id, ok := s.identityOf(caller)
	if !ok {
		return false
	}
	for _, p := range id.Permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// nbfcAdminLoan is the administrative loan read. It needs the administrator role and the loans:read grant.
func (s *Server) nbfcAdminLoan(w http.ResponseWriter, r *http.Request) {
	s.nbfcAdminRead(w, r, "loan", "loans:read")
}

// nbfcAdminKYC is the administrative KYC read. It needs the administrator role and the kyc:read grant. The fixture does not
// grant kyc:read to the administrator, so the fixed build refuses it.
func (s *Server) nbfcAdminKYC(w http.ResponseWriter, r *http.Request) {
	s.nbfcAdminRead(w, r, "kyc", "kyc:read")
}

// nbfcAdminRead answers an administrative read of a pack record. The fixed build allows it only to the administrator role
// holding the route's grant, and returns the public projection to that administrator. The vulnerable build skips the role and
// the grant, and returns the protected fields to whoever asks. Both builds audit every attempt.
func (s *Server) nbfcAdminRead(w http.ResponseWriter, r *http.Request, kind, permission string) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	role := s.actorRole(caller)
	id := r.PathValue("id")
	rec, found := s.nbfc.get(id)
	found = found && rec.Kind == kind
	allowed := s.vulnerable() || (role == "administrator" && s.hasGrant(caller, permission))
	outcome, reason := "allowed", ""
	switch {
	case !found:
		outcome, reason = "denied", "not_found"
	case !allowed:
		outcome, reason = "denied", "policy"
	}
	s.nbfc.audit(AuditRecord{Identity: caller, Role: role, Action: r.Method + " " + r.URL.Path, Target: id,
		Permission: permission, Outcome: outcome, Reason: reason})
	switch reason {
	case "not_found":
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	case "policy":
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "administrative access not granted"})
		return
	}
	if kind == "kyc" {
		writeJSON(w, http.StatusOK, kycBody(rec, s.vulnerable()))
		return
	}
	writeJSON(w, http.StatusOK, s.loanBody(rec, caller))
}

// nbfcAuditLog returns the administrative audit trail for the run. It is a lab administration route.
func (s *Server) nbfcAuditLog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.nbfc.auditSnapshot())
}

// loanBody is the loan a caller may see. Protected fields go to the owner only in the fixed build; the vulnerable build
// returns them to anyone who names the loan.
func (s *Server) loanBody(r nbfcRecord, caller string) map[string]any {
	body := map[string]any{"id": r.ID, "owner_id": r.OwnerID, "status": r.Status, "assignee": r.Assignee}
	for k, v := range r.Public {
		body[k] = v
	}
	if s.vulnerable() || caller == r.OwnerID {
		for k, v := range r.Protected {
			body[k] = v
		}
	}
	return body
}

// nbfcGetLoan answers the loan read. The vulnerable build ignores ownership, and it honours ?expand=kyc by returning the
// borrower's KYC record with the identity evidence (NBFC-007). The fixed build never returns KYC through the loan read.
func (s *Server) nbfcGetLoan(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "loan" || (!s.vulnerable() && !visibleTo(rec, caller)) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	body := s.loanBody(rec, caller)
	if s.vulnerable() && r.URL.Query().Get("expand") == "kyc" {
		if kyc, ok := s.nbfc.findKYC(rec.Parent); ok {
			body["kyc"] = kycBody(kyc, true)
		}
	}
	writeJSON(w, http.StatusOK, body)
}

// findKYC returns the KYC record of a borrower.
func (n *nbfcStore) findKYC(borrower string) (nbfcRecord, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, r := range n.recs {
		if r.Kind == "kyc" && r.Parent == borrower {
			return copyRecord(r), true
		}
	}
	return nbfcRecord{}, false
}

func kycBody(r nbfcRecord, withProtected bool) map[string]any {
	body := map[string]any{"id": r.ID, "borrower_id": r.Parent, "status": r.Status}
	for k, v := range r.Public {
		body[k] = v
	}
	if withProtected {
		for k, v := range r.Protected {
			body[k] = v
		}
	}
	return body
}

// nbfcListLoans is the lookup and enumeration route. The vulnerable build returns every loan. The fixed build returns only
// the loans the caller owns or is assigned to.
func (s *Server) nbfcListLoans(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	s.nbfc.mu.Lock()
	ids := make([]string, 0, len(s.nbfc.recs))
	for id, rec := range s.nbfc.recs {
		if rec.Kind != "loan" {
			continue
		}
		if s.vulnerable() || visibleTo(*rec, caller) {
			ids = append(ids, id)
		}
	}
	s.nbfc.mu.Unlock()
	sort.Strings(ids)
	out := make([]map[string]any, 0, len(ids))
	disclosed := make([]string, 0, len(ids))
	for _, id := range ids {
		rec, _ := s.nbfc.get(id)
		out = append(out, map[string]any{"id": rec.ID, "owner_id": rec.OwnerID, "status": rec.Status})
		disclosed = append(disclosed, rec.OwnerID)
	}
	// The list discloses these owners' records, so the access event names them (REL-004 reads the owners a request reaches).
	noteResponseOwners(r, disclosed...)
	writeJSON(w, http.StatusOK, map[string]any{"loans": out})
}

// nbfcPatchLoan changes a loan's amount. The vulnerable build lets any authenticated caller change it. The fixed build lets
// only the owner change it, and only while the application is still submitted.
func (s *Server) nbfcPatchLoan(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["amount"] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "amount is required"})
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "loan" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !s.vulnerable() && (caller != rec.OwnerID || rec.Status != "submitted") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	rec.Public["amount"] = req["amount"]
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

// nbfcGetKYC answers the KYC read. The vulnerable build returns the identity evidence to anyone who names the record. The
// fixed build returns it to the borrower alone.
func (s *Server) nbfcGetKYC(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "kyc" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !s.vulnerable() && caller != rec.OwnerID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, kycBody(rec, true))
}

// nbfcPrepare records the officer who prepares a loan decision. The fixed build lets only the assigned officer prepare it.
func (s *Server) nbfcPrepare(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "loan" || (!s.vulnerable() && (rec.Assignee == "" || caller != rec.Assignee)) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	rec.PreparedBy = caller
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "prepared"})
}

// nbfcDecision approves a loan. The vulnerable build approves for any caller. The fixed build requires the assigned officer
// (NBFC-004), requires a prepared decision, and refuses approval by the officer who prepared it (NBFC-005).
func (s *Server) nbfcDecision(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "loan" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !s.vulnerable() {
		if rec.Assignee == "" || caller != rec.Assignee {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		if rec.PreparedBy == "" {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "decision not prepared"})
			return
		}
		if rec.PreparedBy == caller {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "an officer cannot approve their own decision"})
			return
		}
	}
	rec.Status = "approved"
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "approved", "approver": caller})
}

// nbfcPatchRepayment changes a repayment's status or amount. The vulnerable build lets any authenticated caller change it.
// The fixed build refuses the borrower (NBFC-006): only the officer assigned to the parent loan may change a repayment.
func (s *Server) nbfcPatchRepayment(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req["status"] == "" && req["amount"] == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status or amount is required"})
		return
	}
	id := r.PathValue("id")
	s.nbfc.mu.Lock()
	defer s.nbfc.mu.Unlock()
	rec, found := s.nbfc.recs[id]
	if !found || rec.Kind != "repayment" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !s.vulnerable() {
		parent := s.nbfc.recs[rec.Parent]
		if caller == rec.OwnerID {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "borrowers cannot change repayments"})
			return
		}
		if parent == nil || parent.Assignee == "" || caller != parent.Assignee {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
	}
	if req["status"] != "" {
		rec.Status = req["status"]
	}
	if req["amount"] != "" {
		rec.Public["amount"] = req["amount"]
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "updated"})
}

// nbfcStatement is the loan statement: the loan and its repayments, with the debit mandate on each repayment. It is a fixture
// capability for a later scenario; the vulnerable build returns the mandates to anyone who names the loan. The fixed build
// answers the owner and the assigned officer with public fields only.
func (s *Server) nbfcStatement(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	rec, found := s.nbfc.get(r.PathValue("id"))
	if !found || rec.Kind != "loan" || (!s.vulnerable() && !visibleTo(rec, caller)) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	reps := []map[string]any{}
	s.nbfc.mu.Lock()
	for _, rp := range s.nbfc.recs {
		if rp.Kind != "repayment" || rp.Parent != rec.ID {
			continue
		}
		item := map[string]any{"id": rp.ID, "status": rp.Status, "amount": rp.Public["amount"]}
		if s.vulnerable() || caller == rp.OwnerID {
			item["debit_mandate"] = rp.Protected["debit_mandate"]
		}
		reps = append(reps, item)
	}
	s.nbfc.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"loan": s.loanBody(rec, caller), "repayments": reps})
}
