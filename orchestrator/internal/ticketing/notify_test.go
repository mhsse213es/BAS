package ticketing

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// An exercise ticket is not a finding. Its text must say it is a drill, must not carry finding-shaped
// placeholders ("[BAS] T1059 — PowerShell on host"), and must not be mistaken for a real incident.

func TestSnowNotify_OpensLabelledIncidentWithoutFindingText(t *testing.T) {
	var got map[string]any
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/now/table/incident": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": "s1", "number": "INC9"}})
		},
	})
	defer srv.Close()

	s := newServiceNow(map[string]string{"instance_url": srv.URL, "assignment_group": "SOC"})
	ref, err := s.Notify(context.Background(), "Suspicious login", "User reported odd MFA prompts", RecordIncident)
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if got["short_description"] != "[BAS EXERCISE] Suspicious login" {
		t.Fatalf("short_description = %v", got["short_description"])
	}
	desc, _ := got["description"].(string)
	if !strings.Contains(desc, "User reported odd MFA prompts") || !strings.Contains(strings.ToLower(desc), "exercise") {
		t.Fatalf("description must carry the body and say it is an exercise, got %q", desc)
	}
	if strings.Contains(desc, "T1") || strings.Contains(got["short_description"].(string), "[BAS] ") {
		t.Fatalf("an exercise ticket must not carry finding-shaped text, got %v / %q", got["short_description"], desc)
	}
	if got["assignment_group"] != "SOC" {
		t.Fatalf("the connector's assignment group must still apply, got %v", got["assignment_group"])
	}
	if ref.TicketID != "incident/s1" || !strings.Contains(ref.TicketURL, "INC9") {
		t.Fatalf("ref = %+v", ref)
	}
}

func TestSnowNotify_TruncatesLongSubjectAndRejectsBlank(t *testing.T) {
	var got map[string]any
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/now/table/incident": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&got)
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": "s2"}})
		},
	})
	defer srv.Close()
	s := newServiceNow(map[string]string{"instance_url": srv.URL})

	if _, err := s.Notify(context.Background(), strings.Repeat("x", 400), "b", RecordIncident); err != nil {
		t.Fatal(err)
	}
	if n := len(got["short_description"].(string)); n > 160 {
		t.Fatalf("short_description is %d chars, ServiceNow's limit is 160", n)
	}
	if _, err := s.Notify(context.Background(), "   ", "b", RecordIncident); err == nil {
		t.Fatal("a blank subject must be refused, not sent as an empty ticket")
	}
}

func TestJiraNotify_OpensLabelledIssue(t *testing.T) {
	var fields map[string]any
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /rest/api/2/issue": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			fields = body["fields"].(map[string]any)
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "SEC-7", "self": "x"})
		},
	})
	defer srv.Close()

	j := newJira(map[string]string{"base_url": srv.URL, "username": "bob", "api_token": "tok", "project_key": "SEC"})
	ref, err := j.Notify(context.Background(), "Suspicious login", "details here", RecordIncident)
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if fields["summary"] != "[BAS EXERCISE] Suspicious login" {
		t.Fatalf("summary = %v", fields["summary"])
	}
	if fields["project"].(map[string]any)["key"] != "SEC" {
		t.Fatalf("project = %v", fields["project"])
	}
	labels, _ := fields["labels"].([]any)
	found := false
	for _, l := range labels {
		if l == "BAS-EXERCISE" {
			found = true
		}
		if s, _ := l.(string); strings.HasPrefix(s, "T1") {
			t.Fatalf("an exercise ticket must not carry an ATT&CK technique label, got %v", labels)
		}
	}
	if !found {
		t.Fatalf("labels = %v, want BAS-EXERCISE so the SOC can filter drills", labels)
	}
	if ref.TicketID != "SEC-7" || ref.TicketURL != srv.URL+"/browse/SEC-7" {
		t.Fatalf("ref = %+v", ref)
	}
}

// Jira projects ship different issue types; exercise tickets must use the same fallback the finding path uses.
func TestJiraNotify_FallsBackThroughIssueTypes(t *testing.T) {
	var tried []string
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /rest/api/2/issue": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			name := body["fields"].(map[string]any)["issuetype"].(map[string]any)["name"].(string)
			tried = append(tried, name)
			if name != "Task" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"errors":{"issuetype":"invalid issue type"}}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"key": "SEC-8"})
		},
	})
	defer srv.Close()
	j := newJira(map[string]string{"base_url": srv.URL, "username": "b", "api_token": "t", "project_key": "SEC"})
	ref, err := j.Notify(context.Background(), "s", "b", RecordIncident)
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if ref.TicketID != "SEC-8" || len(tried) < 2 {
		t.Fatalf("ref=%+v tried=%v, want a fallback to Task", ref, tried)
	}
}

// ── Manager.NotifyStep: connector lookup and rules, no database needed ──────────

func notifyManager(cfgs map[string]*Config, cons map[string]Connector) *Manager {
	return &Manager{cfgs: cfgs, cons: cons}
}

func TestManagerNotifyStep_Lookup(t *testing.T) {
	srv := snowMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /api/now/table/incident": func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]string{"sys_id": "z", "number": "INC1"}})
		},
	})
	defer srv.Close()
	m := notifyManager(
		map[string]*Config{"snow-1": {ID: "snow-1", Provider: "servicenow"}, "hook-1": {ID: "hook-1", Provider: "webhook"}},
		map[string]Connector{"snow-1": newServiceNow(map[string]string{"instance_url": srv.URL}), "hook-1": newWebhook(map[string]string{"url": "http://127.0.0.1:1"})},
	)
	ctx := context.Background()

	res, err := m.NotifyStep(ctx, "snow-1", "Subject", "Body", "") // blank record type defaults to incident
	if err != nil {
		t.Fatalf("NotifyStep: %v", err)
	}
	if res["channel"] != "ticket" || res["provider"] != "servicenow" || res["ticket_id"] != "incident/z" || res["record_type"] != "incident" {
		t.Fatalf("result = %v", res)
	}
	if _, err := m.NotifyStep(ctx, "missing", "s", "b", ""); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown connector err = %v, want 'not found'", err)
	}
	if _, err := m.NotifyStep(ctx, "hook-1", "s", "b", ""); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("webhook connector err = %v, want 'does not support'", err)
	}
	if _, err := m.NotifyStep(ctx, "snow-1", "s", "b", "not-a-type"); err == nil || !strings.Contains(err.Error(), "record type") {
		t.Fatalf("bad record type err = %v, want a record type error", err)
	}
}
