package ticketing

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Closing a drill ticket must say it was a drill. The finding path's CloseTicket writes "BAS revalidation
// confirmed this technique is now prevented", which would be false text on an exercise ticket.

func TestSnowCloseWithNote_UsesTheDrillNote(t *testing.T) {
	var body map[string]any
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"PATCH /api/now/table/incident/i1": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()
	s := newServiceNow(map[string]string{"instance_url": srv.URL})

	if err := s.CloseWithNote(context.Background(), "incident/i1", "Exercise ended; closing the drill ticket."); err != nil {
		t.Fatalf("CloseWithNote: %v", err)
	}
	if body["state"] != "6" {
		t.Fatalf("state = %v, want 6 (resolved)", body["state"])
	}
	notes, _ := body["close_notes"].(string)
	if notes != "Exercise ended; closing the drill ticket." || strings.Contains(strings.ToLower(notes), "revalidation") {
		t.Fatalf("close_notes = %q, want the drill note and no finding text", notes)
	}
}

func TestJiraCloseWithNote_CommentsTheDrillNote(t *testing.T) {
	var comment string
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /rest/api/2/issue/SEC-1/transitions": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"transitions": []map[string]string{{"id": "31", "name": "Done"}}})
		},
		"POST /rest/api/2/issue/SEC-1/transitions": func(w http.ResponseWriter, r *http.Request) {
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			upd := b["update"].(map[string]any)["comment"].([]any)
			comment = upd[0].(map[string]any)["add"].(map[string]any)["body"].(string)
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()
	j := newJira(map[string]string{"base_url": srv.URL})

	if err := j.CloseWithNote(context.Background(), "SEC-1", "Exercise ended; closing the drill ticket."); err != nil {
		t.Fatalf("CloseWithNote: %v", err)
	}
	if comment != "Exercise ended; closing the drill ticket." {
		t.Fatalf("comment = %q, want the drill note", comment)
	}
}

func TestManager_TicketStatusAndCloseExerciseTicket(t *testing.T) {
	var patched bool
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /api/now/table/incident/i1": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"state": "2"}})
		},
		"PATCH /api/now/table/incident/i1": func(w http.ResponseWriter, r *http.Request) {
			patched = true
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()
	m := notifyManager(
		map[string]*Config{"snow-1": {ID: "snow-1", Provider: "servicenow"}, "hook-1": {ID: "hook-1", Provider: "webhook"}},
		map[string]Connector{"snow-1": newServiceNow(map[string]string{"instance_url": srv.URL}), "hook-1": newWebhook(map[string]string{"url": "http://127.0.0.1:1"})},
	)
	ctx := context.Background()

	st, err := m.TicketStatus(ctx, "snow-1", "incident/i1")
	if err != nil || st != "in_progress" {
		t.Fatalf("TicketStatus = %q, %v; want in_progress", st, err)
	}
	if err := m.CloseExerciseTicket(ctx, "snow-1", "incident/i1", "drill over"); err != nil || !patched {
		t.Fatalf("CloseExerciseTicket err=%v patched=%v", err, patched)
	}
	if _, err := m.TicketStatus(ctx, "missing", "x"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown connector status err = %v", err)
	}
	if err := m.CloseExerciseTicket(ctx, "missing", "x", "n"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown connector close err = %v", err)
	}
	// the generic webhook connector has no drill-aware close, and must not be closed with finding text
	if err := m.CloseExerciseTicket(ctx, "hook-1", "x", "n"); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("webhook close err = %v, want 'does not support'", err)
	}
}
