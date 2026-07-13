package ticketing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewServiceNow_NormalizesInstanceURLAndDefaults(t *testing.T) {
	s := newServiceNow(map[string]string{"instance_url": "acme.service-now.com/"})
	if s.instanceURL != "https://acme.service-now.com" {
		t.Errorf("instanceURL = %q, want https://acme.service-now.com", s.instanceURL)
	}
	if s.category != "security" {
		t.Errorf("category = %q, want default security", s.category)
	}

	custom := newServiceNow(map[string]string{"instance_url": "http://sn.internal", "category": "network", "assignment_group": "SOC"})
	if custom.instanceURL != "http://sn.internal" {
		t.Errorf("instanceURL = %q, want http://sn.internal unchanged", custom.instanceURL)
	}
	if custom.category != "network" || custom.assignGroup != "SOC" {
		t.Errorf("category/assignGroup = %q/%q, want network/SOC", custom.category, custom.assignGroup)
	}
}

func snowMock(t *testing.T, handlers map[string]func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Method + " " + r.URL.Path
		if h, ok := handlers[key]; ok {
			h(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestSnowCreateTicket_IncidentTable(t *testing.T) {
	var gotBody map[string]any
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/now/table/incident": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&gotBody)
			json.NewEncoder(w).Encode(map[string]any{
				"result": map[string]string{"sys_id": "abc123", "number": "INC0001"},
			})
		},
	})
	defer srv.Close()

	s := newServiceNow(map[string]string{"instance_url": srv.URL, "assignment_group": "SOC"})
	ref, err := s.CreateTicket(context.Background(), testFinding(), RecordIncident)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if ref.TicketID != "incident/abc123" {
		t.Errorf("TicketID = %q, want incident/abc123", ref.TicketID)
	}
	if ref.TicketURL != srv.URL+"/nav_to.do?uri=incident.do?number=INC0001" {
		t.Errorf("TicketURL = %q", ref.TicketURL)
	}
	if gotBody["assignment_group"] != "SOC" {
		t.Errorf("assignment_group = %v, want SOC", gotBody["assignment_group"])
	}
	if gotBody["urgency"] != "1" || gotBody["impact"] != "1" {
		t.Errorf("urgency/impact = %v/%v, want 1/1 for Critical severity", gotBody["urgency"], gotBody["impact"])
	}
}

// TestSnowCreateTicket_RiskRecordUsesDifferentBodyShape pins the RecordRisk
// special-case: no short_description/urgency/impact, uses name+risk_category
// instead, and targets the sn_risk_risk table.
func TestSnowCreateTicket_RiskRecordUsesDifferentBodyShape(t *testing.T) {
	var gotBody map[string]any
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/now/table/sn_risk_risk": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&gotBody)
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": "risk1"}})
		},
	})
	defer srv.Close()

	s := newServiceNow(map[string]string{"instance_url": srv.URL})
	ref, err := s.CreateTicket(context.Background(), testFinding(), RecordRisk)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if ref.TicketID != "sn_risk_risk/risk1" {
		t.Fatalf("TicketID = %q", ref.TicketID)
	}
	if _, has := gotBody["short_description"]; has {
		t.Error("risk body should not carry short_description")
	}
	if _, has := gotBody["urgency"]; has {
		t.Error("risk body should not carry urgency")
	}
	if gotBody["risk_category"] != "security" {
		t.Errorf("risk_category = %v, want security", gotBody["risk_category"])
	}
	if gotBody["name"] == nil || gotBody["name"] == "" {
		t.Error("risk body should carry name")
	}
}

func TestSnowCreateTicket_MissingSysIDErrors(t *testing.T) {
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/now/table/incident": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{}})
		},
	})
	defer srv.Close()
	s := newServiceNow(map[string]string{"instance_url": srv.URL})
	if _, err := s.CreateTicket(context.Background(), testFinding(), RecordIncident); err == nil {
		t.Fatal("expected an error when sys_id is missing from the response")
	}
}

func TestSnowAddComment_UsesWorkNotesOnCorrectTableAndID(t *testing.T) {
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"PATCH /api/now/table/incident/abc123": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["work_notes"] != "note" {
				t.Errorf("work_notes = %v, want note", body["work_notes"])
			}
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()
	s := newServiceNow(map[string]string{"instance_url": srv.URL})
	if err := s.AddComment(context.Background(), "incident/abc123", "note"); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
}

func TestSnowAddComment_InvalidTicketIDErrors(t *testing.T) {
	s := newServiceNow(map[string]string{"instance_url": "http://unused"})
	if err := s.AddComment(context.Background(), "no-slash-here", "note"); err == nil {
		t.Fatal("expected an error for a ticketID without table/sys_id shape")
	}
}

// TestSnowCloseTicket_IncidentVsProblemPayloadShape pins the two distinct
// close payload shapes: incident uses state=6 + close_code/close_notes;
// problem uses state=107 + cause_notes/fix_notes instead.
func TestSnowCloseTicket_IncidentVsProblemPayloadShape(t *testing.T) {
	var incidentBody, problemBody map[string]any
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"PATCH /api/now/table/incident/i1": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&incidentBody)
			w.WriteHeader(http.StatusOK)
		},
		"PATCH /api/now/table/problem/p1": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&problemBody)
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()
	s := newServiceNow(map[string]string{"instance_url": srv.URL})

	if err := s.CloseTicket(context.Background(), "incident/i1"); err != nil {
		t.Fatalf("CloseTicket(incident): %v", err)
	}
	if incidentBody["state"] != "6" || incidentBody["close_code"] == nil {
		t.Errorf("incident close body = %+v, want state=6 with close_code", incidentBody)
	}

	if err := s.CloseTicket(context.Background(), "problem/p1"); err != nil {
		t.Fatalf("CloseTicket(problem): %v", err)
	}
	if problemBody["state"] != "107" || problemBody["cause_notes"] == nil {
		t.Errorf("problem close body = %+v, want state=107 with cause_notes", problemBody)
	}
	if _, has := problemBody["close_code"]; has {
		t.Error("problem close body should not carry close_code")
	}
}

func TestSnowReopenTicket_SetsStateToTwo(t *testing.T) {
	var gotBody map[string]any
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"PATCH /api/now/table/incident/i1": func(w http.ResponseWriter, r *http.Request) {
			json.NewDecoder(r.Body).Decode(&gotBody)
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()
	s := newServiceNow(map[string]string{"instance_url": srv.URL})
	if err := s.ReopenTicket(context.Background(), "incident/i1"); err != nil {
		t.Fatalf("ReopenTicket: %v", err)
	}
	if gotBody["state"] != "2" {
		t.Errorf("state = %v, want 2", gotBody["state"])
	}
}

func TestSnowGetStatus_MapsStateCodes(t *testing.T) {
	cases := []struct {
		state string
		want  string
	}{
		{"1", "open"}, {"2", "in_progress"}, {"3", "in_progress"},
		{"4", "resolved"}, {"6", "resolved"}, {"7", "resolved"}, {"99", "unknown"},
	}
	for _, c := range cases {
		t.Run(c.state, func(t *testing.T) {
			srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
				"GET /api/now/table/incident/i1": func(w http.ResponseWriter, r *http.Request) {
					json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"state": c.state}})
				},
			})
			defer srv.Close()
			s := newServiceNow(map[string]string{"instance_url": srv.URL})
			got, err := s.GetStatus(context.Background(), "incident/i1")
			if err != nil {
				t.Fatalf("GetStatus: %v", err)
			}
			if got != c.want {
				t.Errorf("GetStatus(state=%s) = %q, want %q", c.state, got, c.want)
			}
		})
	}
}

func TestSnowTestConnection_SuccessAndFailure(t *testing.T) {
	ok := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /api/now/table/incident": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	})
	defer ok.Close()
	if err := newServiceNow(map[string]string{"instance_url": ok.URL}).TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}

	bad := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /api/now/table/incident": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
	})
	defer bad.Close()
	if err := newServiceNow(map[string]string{"instance_url": bad.URL}).TestConnection(context.Background()); err == nil {
		t.Fatal("expected an error for a 401 response")
	}
}

func TestSplitSnowID(t *testing.T) {
	table, sysID, err := splitSnowID("incident/abc123")
	if err != nil || table != "incident" || sysID != "abc123" {
		t.Fatalf("splitSnowID = %q/%q/%v, want incident/abc123/nil", table, sysID, err)
	}
	if _, _, err := splitSnowID("no-slash"); err == nil {
		t.Fatal("expected an error for a ticketID without a slash")
	}
	if _, _, err := splitSnowID("table/"); err == nil {
		t.Fatal("expected an error for an empty sys_id")
	}
}
