package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/audspect/bas/internal/apibas/reporting"
)

// reportingState is the fixture-backed reporting receiver. It never sends anything outside the lab. Every dispatch is recorded
// as simulated, so a run against it can never show a genuine receipt. It is identical in both builds: the scenarios test the
// workflow under these fixture conditions, and they do not seed a defect.
type reportingState struct {
	mu         sync.Mutex
	incidents  []reporting.Incident
	dispatches []reporting.Dispatch
	faults     reportingFaults
	receipts   int
}

// reportingFaults are set by the harness before a run, through the admin route. A reset keeps them.
type reportingFaults struct {
	// DelaySeconds moves each dispatch this many seconds after the incident's awareness time.
	DelaySeconds int `json:"delay_seconds"`
	// FailRecipient makes dispatch to this recipient fail.
	FailRecipient string `json:"fail_recipient"`
	// OmitReceipt returns no receipt for a successful dispatch.
	OmitReceipt bool `json:"omit_receipt"`
	// MisrouteTo sends every dispatch to this recipient instead of the one requested.
	MisrouteTo string `json:"misroute_to"`
}

// seededIncidents is the fixture's reporting record. The awareness times are fixed, so the deadline clock is deterministic.
// A reset restores them.
func seededIncidents() []reporting.Incident {
	noticed := time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)
	return []reporting.Incident{
		{ID: "INC-2026-0001", Category: "cybersecurity_incident", NoticedAt: noticed, Eligible: true},
		{ID: "BRE-2026-0001", Category: "personal_data_breach", NoticedAt: noticed, Eligible: true},
	}
}

// reset clears the run's records and restores the seed. It keeps the faults: they are the harness's configuration, set
// before a run. The runner resets the lab before every sandbox run, so clearing faults here would drop them. The harness
// clears them with an empty fault set.
func (r *reportingState) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.incidents = seededIncidents()
	r.dispatches = nil
	r.receipts = 0
}

type incidentRequest struct {
	ID        string    `json:"id"`
	Category  string    `json:"category"`
	NoticedAt time.Time `json:"noticed_at"`
	Eligible  bool      `json:"eligible"`
}

type reportRequest struct {
	Recipients []string `json:"recipients"`
}

func (s *Server) registerReporting(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/incidents/{id}", s.getIncident)
	mux.HandleFunc("POST /api/incidents", s.createIncident)
	mux.HandleFunc("POST /api/incidents/{id}/report", s.reportIncident)
	mux.HandleFunc("GET /lab/reporting", s.adminOnly(s.reportingEvidence))
	mux.HandleFunc("POST /lab/reporting/faults", s.adminOnly(s.setReportingFaults))
}

// getIncident is the intake read a scenario's baseline makes: the incident exists and carries its awareness time.
func (s *Server) getIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	s.rpt.mu.Lock()
	defer s.rpt.mu.Unlock()
	for _, inc := range s.rpt.incidents {
		if inc.ID == id {
			writeJSON(w, http.StatusOK, inc)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such incident"})
}

// createIncident records the awareness time the fixture supplies. The deadline clock starts there.
func (s *Server) createIncident(w http.ResponseWriter, r *http.Request) {
	var req incidentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.NoticedAt.IsZero() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id and noticed_at are required"})
		return
	}
	s.rpt.mu.Lock()
	defer s.rpt.mu.Unlock()
	for _, inc := range s.rpt.incidents {
		if inc.ID == req.ID {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "incident already exists"})
			return
		}
	}
	s.rpt.incidents = append(s.rpt.incidents, reporting.Incident{
		ID: req.ID, Category: req.Category, NoticedAt: req.NoticedAt.UTC(), Eligible: req.Eligible,
	})
	writeJSON(w, http.StatusCreated, map[string]string{"id": req.ID, "status": "recorded"})
}

// reportIncident dispatches the incident to each requested recipient. The grader never reads this response. It reads the
// dispatches from the reporting evidence, so the HTTP reply cannot stand in for proof of dispatch.
func (s *Server) reportIncident(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unreadable body"})
		return
	}
	var req reportRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.Recipients) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "recipients are required"})
		return
	}
	sum := sha256.Sum256(body)
	hash := "sha256:" + hex.EncodeToString(sum[:])

	s.rpt.mu.Lock()
	defer s.rpt.mu.Unlock()
	var inc *reporting.Incident
	for i := range s.rpt.incidents {
		if s.rpt.incidents[i].ID == id {
			inc = &s.rpt.incidents[i]
		}
	}
	if inc == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such incident"})
		return
	}
	at := inc.NoticedAt.Add(time.Duration(s.rpt.faults.DelaySeconds) * time.Second)
	out := make([]map[string]string, 0, len(req.Recipients))
	for _, want := range req.Recipients {
		to := want
		if s.rpt.faults.MisrouteTo != "" {
			to = s.rpt.faults.MisrouteTo
		}
		d := reporting.Dispatch{
			IncidentID: id, Recipient: to, DispatchedAt: at, ReportHash: hash, Mode: reporting.ModeSimulated,
			Status: reporting.StatusDispatched,
		}
		if to == s.rpt.faults.FailRecipient {
			d.Status = reporting.StatusFailed
			d.DispatchedAt = time.Time{}
			d.ReportHash = ""
		} else if !s.rpt.faults.OmitReceipt {
			s.rpt.receipts++
			d.ReceiptRef = fmt.Sprintf("SIM-RCPT-%s-%d", id, s.rpt.receipts)
		}
		s.rpt.dispatches = append(s.rpt.dispatches, d)
		out = append(out, map[string]string{"recipient": to, "status": d.Status, "mode": string(d.Mode)})
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"incident": id, "dispatches": out})
}

func (s *Server) reportingEvidence(w http.ResponseWriter, _ *http.Request) {
	s.rpt.mu.Lock()
	defer s.rpt.mu.Unlock()
	writeJSON(w, http.StatusOK, reporting.Evidence{
		Incidents:  append([]reporting.Incident(nil), s.rpt.incidents...),
		Dispatches: append([]reporting.Dispatch(nil), s.rpt.dispatches...),
	})
}

func (s *Server) setReportingFaults(w http.ResponseWriter, r *http.Request) {
	var f reportingFaults
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil || f.DelaySeconds < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "faults must be valid, with a non-negative delay"})
		return
	}
	s.rpt.mu.Lock()
	defer s.rpt.mu.Unlock()
	s.rpt.faults = f
	writeJSON(w, http.StatusOK, map[string]string{"status": "set"})
}
