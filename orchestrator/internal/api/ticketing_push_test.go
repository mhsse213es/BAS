package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newWebhookMock returns an httptest.Server that always responds with the
// given status/body — enough for webhookConnector.TestConnection/
// CreateTicket/AddComment/CloseTicket/ReopenTicket (all just POST and check
// the status code / try to unmarshal {ticketId,ticketUrl}).
func newWebhookMock(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

// recordingWebhookMock captures every POSTed payload's "action" field so
// tests can assert which ticket operations actually fired.
type recordingWebhookMock struct {
	*httptest.Server
	mu      sync.Mutex
	actions []string
}

func newRecordingWebhookMock(t *testing.T, ticketID string) *recordingWebhookMock {
	t.Helper()
	m := &recordingWebhookMock{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload struct {
			Action string `json:"action"`
		}
		json.Unmarshal(raw, &payload)
		m.mu.Lock()
		m.actions = append(m.actions, payload.Action)
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ticketId": ticketID, "ticketUrl": "http://ticket/" + ticketID})
	}))
	return m
}

func (m *recordingWebhookMock) Actions() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.actions))
	copy(out, m.actions)
	return out
}

func ticketingWebhookConfig(t *testing.T, pool *pgxpool.Pool, h *Handler, url string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.CreateTicketingConfig(rec, ticketingConfigReq(map[string]any{
		"name": "wh", "provider": "webhook", "enabled": true, "autoCreate": "all",
		"autoUpdate": true, "autoClose": true,
		"settings": map[string]string{"url": url},
	}))
	var out struct {
		ID string `json:"id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

// seedFindingForTicketing seeds an active agent + a findings row directly
// (not via upsertFindingsForRun — ticketing.PushFinding only needs the
// findings row + agent, not the full run/state-machine lineage).
func seedFindingForTicketing(t *testing.T, pool *pgxpool.Pool, agentID, techID, severity string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (agent_id, hostname, state) VALUES ($1,$2,'active') ON CONFLICT (agent_id) DO NOTHING`,
		agentID, "host-"+agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO findings (agent_id, technique_id, control_class, technique_name, tactic, severity,
		        exposure_state, status, source_type, occurrence_count, first_seen, last_seen)
		 VALUES ($1,$2,'Endpoint',$3,'execution',$4,'missed','open','custom',1,NOW(),NOW())
		 RETURNING id`,
		agentID, techID, "Test Technique", severity,
	).Scan(&id); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return id
}

func TestListTicketCandidates_NilTicketingReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.ListTicketCandidates(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("expected empty candidates, got %d", len(out))
		}
	})
}

func TestListTicketCandidates_ExcludesFindingsWithOpenTickets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		mock := newRecordingWebhookMock(t, "wh-1")
		defer mock.Close()
		cfgID := ticketingWebhookConfig(t, pool, h, mock.URL)

		openFinding := seedFindingForTicketing(t, pool, "ltc-agent-a", "T1059.001", "Critical")
		ticketedFinding := seedFindingForTicketing(t, pool, "ltc-agent-b", "T1003.001", "High")

		pushRec := httptest.NewRecorder()
		h.PushFindingToITSM(pushRec, ticketingConfigReq(map[string]any{"findingId": ticketedFinding, "configId": cfgID}))
		if pushRec.Code != http.StatusOK {
			t.Fatalf("push: status = %d, body = %s", pushRec.Code, pushRec.Body.String())
		}

		rec := httptest.NewRecorder()
		h.ListTicketCandidates(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out []struct {
			ID string `json:"id"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		var ids []string
		for _, c := range out {
			ids = append(ids, c.ID)
		}
		found, ticketed := false, false
		for _, id := range ids {
			if id == openFinding {
				found = true
			}
			if id == ticketedFinding {
				ticketed = true
			}
		}
		if !found {
			t.Errorf("candidates = %v, want %s (no ticket yet) present", ids, openFinding)
		}
		if ticketed {
			t.Errorf("candidates = %v, want %s (already ticketed) absent", ids, ticketedFinding)
		}
	})
}

func TestPushFindingToITSM_NilTicketing503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.PushFindingToITSM(rec, ticketingConfigReq(map[string]any{"findingId": "f1", "configId": "c1"}))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestPushFindingToITSM_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		cases := []map[string]any{
			{"configId": "c1"},
			{"findingId": "f1"},
		}
		for _, body := range cases {
			rec := httptest.NewRecorder()
			h.PushFindingToITSM(rec, ticketingConfigReq(body))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("body %v: status = %d, want 400", body, rec.Code)
			}
		}
	})
}

func TestPushFindingToITSM_InvalidRecordType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		rec := httptest.NewRecorder()
		h.PushFindingToITSM(rec, ticketingConfigReq(map[string]any{
			"findingId": "f1", "configId": "c1", "recordType": "bogus",
		}))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})
}

func TestPushFindingToITSM_UnknownConnector(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		findingID := seedFindingForTicketing(t, pool, "puc-agent", "T1059.001", "Critical")
		rec := httptest.NewRecorder()
		h.PushFindingToITSM(rec, ticketingConfigReq(map[string]any{"findingId": findingID, "configId": "no-such-config"}))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want 502", rec.Code)
		}
	})
}

// TestPushFindingToITSM_CreatesTicketAndIsIdempotent pins the core flow:
// pushing creates a finding_tickets row (visible via GetFindingTickets), and
// pushing the SAME finding again returns the existing ticket rather than
// creating a duplicate (dedup logic in ticketing.Manager.PushFinding).
func TestPushFindingToITSM_CreatesTicketAndIsIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		mock := newRecordingWebhookMock(t, "wh-42")
		defer mock.Close()
		cfgID := ticketingWebhookConfig(t, pool, h, mock.URL)
		findingID := seedFindingForTicketing(t, pool, "cti-agent", "T1059.001", "Critical")

		rec1 := httptest.NewRecorder()
		h.PushFindingToITSM(rec1, ticketingConfigReq(map[string]any{"findingId": findingID, "configId": cfgID}))
		if rec1.Code != http.StatusOK {
			t.Fatalf("first push: status = %d, body = %s", rec1.Code, rec1.Body.String())
		}
		var out1 struct {
			TicketID string `json:"ticketId"`
		}
		json.Unmarshal(rec1.Body.Bytes(), &out1)
		if out1.TicketID != "wh-42" {
			t.Fatalf("ticketId = %q, want wh-42", out1.TicketID)
		}

		rec2 := httptest.NewRecorder()
		h.PushFindingToITSM(rec2, ticketingConfigReq(map[string]any{"findingId": findingID, "configId": cfgID}))
		var out2 struct {
			TicketID string `json:"ticketId"`
		}
		json.Unmarshal(rec2.Body.Bytes(), &out2)
		if out2.TicketID != "wh-42" {
			t.Fatalf("second push ticketId = %q, want the same wh-42 (dedup)", out2.TicketID)
		}

		if got := len(mock.Actions()); got != 1 {
			t.Fatalf("webhook received %d requests, want exactly 1 create (second push should be a DB-only dedup, no new webhook call)", got)
		}

		ticketsRec := httptest.NewRecorder()
		h.GetFindingTickets(ticketsRec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", findingID))
		var tickets []struct {
			TicketID string `json:"ticketId"`
			Provider string `json:"provider"`
		}
		json.Unmarshal(ticketsRec.Body.Bytes(), &tickets)
		if len(tickets) != 1 || tickets[0].TicketID != "wh-42" || tickets[0].Provider != "webhook" {
			t.Fatalf("tickets = %+v, want 1 entry for wh-42/webhook", tickets)
		}
	})
}

func TestGetFindingTickets_NilTicketingReturnsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.GetFindingTickets(rec, withURLParam(httptest.NewRequest(http.MethodGet, "/x", nil), "id", "f1"))
		var out []map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 0 {
			t.Fatalf("expected empty, got %d", len(out))
		}
	})
}

func TestBulkPushToITSM_NilTicketing503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.BulkPushToITSM(rec, ticketingConfigReq(map[string]any{"findingIds": []string{"f1"}, "configId": "c1"}))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

// TestBulkPushToITSM_PerFindingResultsIncludeErrors pins the partial-failure
// contract: bulk push reports success/error per finding rather than failing
// the whole batch when one finding is bad.
func TestBulkPushToITSM_PerFindingResultsIncludeErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		mock := newRecordingWebhookMock(t, "wh-bulk")
		defer mock.Close()
		cfgID := ticketingWebhookConfig(t, pool, h, mock.URL)
		goodFinding := seedFindingForTicketing(t, pool, "bulk-agent", "T1059.001", "Critical")

		rec := httptest.NewRecorder()
		h.BulkPushToITSM(rec, ticketingConfigReq(map[string]any{
			"findingIds": []string{goodFinding, "does-not-exist"}, "configId": cfgID,
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
		var out []struct {
			FindingID string `json:"findingId"`
			TicketID  string `json:"ticketId,omitempty"`
			Error     string `json:"error,omitempty"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if len(out) != 2 {
			t.Fatalf("expected 2 results, got %d", len(out))
		}
		byID := map[string]string{}
		for _, r := range out {
			if r.Error != "" {
				byID[r.FindingID] = "error"
			} else {
				byID[r.FindingID] = r.TicketID
			}
		}
		if byID[goodFinding] != "wh-bulk" {
			t.Errorf("good finding result = %q, want ticket wh-bulk", byID[goodFinding])
		}
		if byID["does-not-exist"] != "error" {
			t.Errorf("bad finding result = %q, want error", byID["does-not-exist"])
		}
	})
}

func TestReceiveTicketingWebhook_MalformedBodyStillReturns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("not-json")), "configId", "c1")
		rec := httptest.NewRecorder()
		h.ReceiveTicketingWebhook(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (never reveal parse errors to external systems)", rec.Code)
		}
	})
}

// TestReceiveTicketingWebhook_UpdatesFindingTicketStatus pins the resolved
// and reopened state transitions on finding_tickets, including
// revalidation_required.
func TestReceiveTicketingWebhook_UpdatesFindingTicketStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		mock := newRecordingWebhookMock(t, "wh-99")
		defer mock.Close()
		cfgID := ticketingWebhookConfig(t, pool, h, mock.URL)
		findingID := seedFindingForTicketing(t, pool, "rtw-agent", "T1059.001", "Critical")
		h.PushFindingToITSM(httptest.NewRecorder(), ticketingConfigReq(map[string]any{"findingId": findingID, "configId": cfgID}))

		resolvedBody, _ := json.Marshal(map[string]any{"ticketId": "wh-99", "state": "resolved"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(resolvedBody)), "configId", cfgID)
		rec := httptest.NewRecorder()
		h.ReceiveTicketingWebhook(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var status string
		var reval bool
		pool.QueryRow(context.Background(),
			`SELECT status, revalidation_required FROM finding_tickets WHERE finding_id=$1`, findingID).Scan(&status, &reval)
		if status != "resolved" || !reval {
			t.Fatalf("after resolved webhook: status=%q revalidation_required=%v, want resolved/true", status, reval)
		}

		reopenBody, _ := json.Marshal(map[string]any{"ticketId": "wh-99", "state": "reopened"})
		req2 := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(reopenBody)), "configId", cfgID)
		h.ReceiveTicketingWebhook(httptest.NewRecorder(), req2)
		pool.QueryRow(context.Background(),
			`SELECT status, revalidation_required FROM finding_tickets WHERE finding_id=$1`, findingID).Scan(&status, &reval)
		if status != "open" || reval {
			t.Fatalf("after reopened webhook: status=%q revalidation_required=%v, want open/false", status, reval)
		}
	})
}

func TestTriggerTicketingSync_NilTicketing503(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TriggerTicketingSync(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", rec.Code)
		}
	})
}

func TestTriggerTicketingSync_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		rec := httptest.NewRecorder()
		h.TriggerTicketingSync(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
		}
	})
}

func TestTicketingSummary_NilTicketingZeroState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandler(t, pool)
		rec := httptest.NewRecorder()
		h.TicketingSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			OpenTickets         int `json:"openTickets"`
			ResolvedTickets     int `json:"resolvedTickets"`
			PendingRevalidation int `json:"pendingRevalidation"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.OpenTickets != 0 || out.ResolvedTickets != 0 || out.PendingRevalidation != 0 {
			t.Fatalf("out = %+v, want all zero", out)
		}
	})
}

// TestTicketingSummary_CountsByProviderAfterPush pins the aggregate counts
// end to end: one pushed finding shows up as one open ticket for the
// webhook provider.
func TestTicketingSummary_CountsByProviderAfterPush(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		mock := newRecordingWebhookMock(t, "wh-sum")
		defer mock.Close()
		cfgID := ticketingWebhookConfig(t, pool, h, mock.URL)
		findingID := seedFindingForTicketing(t, pool, "sum-agent", "T1059.001", "Critical")
		h.PushFindingToITSM(httptest.NewRecorder(), ticketingConfigReq(map[string]any{"findingId": findingID, "configId": cfgID}))

		rec := httptest.NewRecorder()
		h.TicketingSummary(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			OpenTickets int `json:"openTickets"`
			ByProvider  []struct {
				Provider string `json:"provider"`
				Count    int    `json:"count"`
			} `json:"byProvider"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.OpenTickets != 1 {
			t.Fatalf("openTickets = %d, want 1", out.OpenTickets)
		}
		if len(out.ByProvider) != 1 || out.ByProvider[0].Provider != "webhook" || out.ByProvider[0].Count != 1 {
			t.Fatalf("byProvider = %+v, want [{webhook 1}]", out.ByProvider)
		}
	})
}

func TestRevalidationStatus_CountsPendingResolvedTickets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		mock := newRecordingWebhookMock(t, "wh-reval")
		defer mock.Close()
		cfgID := ticketingWebhookConfig(t, pool, h, mock.URL)
		findingID := seedFindingForTicketing(t, pool, "reval-agent", "T1059.001", "Critical")
		h.PushFindingToITSM(httptest.NewRecorder(), ticketingConfigReq(map[string]any{"findingId": findingID, "configId": cfgID}))

		zeroRec := httptest.NewRecorder()
		h.RevalidationStatus(zeroRec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var zeroOut struct {
			PendingRevalidation int `json:"pendingRevalidation"`
		}
		json.Unmarshal(zeroRec.Body.Bytes(), &zeroOut)
		if zeroOut.PendingRevalidation != 0 {
			t.Fatalf("before resolution: pendingRevalidation = %d, want 0", zeroOut.PendingRevalidation)
		}

		resolvedBody, _ := json.Marshal(map[string]any{"ticketId": "wh-reval", "state": "resolved"})
		req := withURLParam(httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(resolvedBody)), "configId", cfgID)
		h.ReceiveTicketingWebhook(httptest.NewRecorder(), req)

		rec := httptest.NewRecorder()
		h.RevalidationStatus(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		var out struct {
			PendingRevalidation int `json:"pendingRevalidation"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out.PendingRevalidation != 1 {
			t.Fatalf("after resolution: pendingRevalidation = %d, want 1", out.PendingRevalidation)
		}
	})
}

// TestDispatchTicketing_RealDispatchAutoCreatesTicket closes the coverage
// gap flagged in 3e.2 (finding_lifecycle_test.go's
// TestDispatchTicketing_NilTicketing_NoOp only covered the nil-ticketing
// guard — the real-dispatch path needed a ticketing.Manager fixture, which
// this sub-phase now has). A new Critical finding (upsertFindingsForRun's
// Created transition) auto-creates a ticket end to end: applyFinding calls
// dispatchTicketing, which calls the real (async) ticketing.Manager.Dispatch,
// which — because autoCreate="critical" matches the finding's severity —
// posts to the webhook and writes a finding_tickets row.
func TestDispatchTicketing_RealDispatchAutoCreatesTicket(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := ticketingHandlerWithManager(t, pool)
		mock := newRecordingWebhookMock(t, "wh-auto")
		defer mock.Close()
		cfgRec := httptest.NewRecorder()
		h.CreateTicketingConfig(cfgRec, ticketingConfigReq(map[string]any{
			"name": "auto", "provider": "webhook", "enabled": true, "autoCreate": "critical",
			"settings": map[string]string{"url": mock.URL},
		}))

		at := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
		seedReportableRun(t, pool, "dt-auto-run", "dt-auto-agent", reportRunOpts{
			Results: oneResult("r1", "T1059.001", "fail", "Critical", at),
		})
		h.upsertFindingsForRun(context.Background(), "dt-auto-run")

		deadline := time.Now().Add(5 * time.Second)
		var n int
		for time.Now().Before(deadline) {
			pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM finding_tickets`).Scan(&n)
			if n > 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if n != 1 {
			t.Fatalf("finding_tickets rows = %d, want 1 (Critical finding should auto-create via the webhook connector)", n)
		}
		var ticketID string
		pool.QueryRow(context.Background(), `SELECT ticket_id FROM finding_tickets`).Scan(&ticketID)
		if ticketID != "wh-auto" {
			t.Fatalf("ticket_id = %q, want wh-auto", ticketID)
		}
		actions := mock.Actions()
		if len(actions) != 1 || actions[0] != "create" {
			t.Fatalf("webhook actions = %v, want exactly one [create]", actions)
		}
	})
}
