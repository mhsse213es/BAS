package ticketing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testFinding() TicketFinding {
	return TicketFinding{
		FindingID:     "f1",
		TechniqueID:   "T1059.001",
		TechniqueName: "PowerShell",
		Tactic:        "execution",
		Severity:      "Critical",
		ControlClass:  "prevention",
		ExposureState: "missed",
		AgentID:       "agent-1",
		AgentHostname: "HOST1",
		FirstSeen:     time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		LastRunID:     "run-1",
		DaysExposed:   3,
	}
}

func TestNewJira_NormalizesBaseURLAndSetsInsecureTLS(t *testing.T) {
	j := newJira(map[string]string{"base_url": "jira.example.com/", "insecure_tls": "yes"})
	if j.baseURL != "https://jira.example.com" {
		t.Errorf("baseURL = %q, want https://jira.example.com (scheme prepended, trailing slash trimmed)", j.baseURL)
	}
	if j.httpClient.Transport == nil {
		t.Error("expected a custom Transport when insecure_tls=yes")
	}

	plain := newJira(map[string]string{"base_url": "http://jira.internal"})
	if plain.baseURL != "http://jira.internal" {
		t.Errorf("baseURL = %q, want http://jira.internal unchanged (already has a scheme)", plain.baseURL)
	}
	if plain.httpClient.Transport != nil {
		t.Error("expected no custom Transport when insecure_tls is unset")
	}
}

// jiraMock is a minimal Jira REST v2 mock driven by a caller-supplied handler
// map keyed "METHOD path" so each test only wires the endpoints it needs.
func jiraMock(t *testing.T, handlers map[string]func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
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

func TestJiraCreateTicket_SucceedsOnFirstIssueType(t *testing.T) {
	var gotAuth string
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /rest/api/2/issue": func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			fields := body["fields"].(map[string]any)
			issuetype := fields["issuetype"].(map[string]any)
			if issuetype["name"] != "Bug" { // default RecordType maps to "Bug"
				t.Errorf("issuetype = %v, want Bug", issuetype)
			}
			json.NewEncoder(w).Encode(map[string]string{"key": "SEC-1", "self": "x"})
		},
	})
	defer srv.Close()

	j := newJira(map[string]string{"base_url": srv.URL, "username": "bob", "api_token": "tok", "project_key": "SEC"})
	ref, err := j.CreateTicket(context.Background(), testFinding(), RecordIncident)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if ref.TicketID != "SEC-1" || ref.TicketURL != srv.URL+"/browse/SEC-1" {
		t.Errorf("ref = %+v", ref)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("bob:tok"))
	if gotAuth != wantAuth {
		t.Errorf("Authorization = %q, want %q", gotAuth, wantAuth)
	}
}

// TestJiraCreateTicket_CascadesThroughIssueTypesOnRejection pins the retry
// contract: the preferred issue type name is tried first; on an
// issuetype-shaped 400 it retries with the next cascade candidate rather
// than failing outright.
func TestJiraCreateTicket_CascadesThroughIssueTypesOnRejection(t *testing.T) {
	var triedTypes []string
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /rest/api/2/issue": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			fields := body["fields"].(map[string]any)
			issuetype := fields["issuetype"].(map[string]any)
			name := issuetype["name"].(string)
			triedTypes = append(triedTypes, name)
			if name != "Task" {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"errors":{"issuetype":"invalid issue type"}}`))
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"key": "SEC-2", "self": "x"})
		},
	})
	defer srv.Close()

	j := newJira(map[string]string{"base_url": srv.URL, "project_key": "SEC"})
	ref, err := j.CreateTicket(context.Background(), testFinding(), RecordTask)
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if ref.TicketID != "SEC-2" {
		t.Fatalf("ref = %+v", ref)
	}
	if len(triedTypes) == 0 || triedTypes[0] != "Task" {
		t.Fatalf("expected Task tried first (RecordTask's preferred type), got %v", triedTypes)
	}
}

// TestJiraCreateTicket_NonIssueTypeErrorStopsImmediately pins that a
// non-issuetype-shaped failure (e.g. auth/permission) is NOT retried across
// the cascade — it must surface immediately as the returned error.
func TestJiraCreateTicket_NonIssueTypeErrorStopsImmediately(t *testing.T) {
	attempts := 0
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /rest/api/2/issue": func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errorMessages":["permission denied"]}`))
		},
	})
	defer srv.Close()

	j := newJira(map[string]string{"base_url": srv.URL, "project_key": "SEC"})
	_, err := j.CreateTicket(context.Background(), testFinding(), RecordIncident)
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (no retry on a non-issuetype error)", attempts)
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error = %v, want it to surface the permission-denied body", err)
	}
}

func TestJiraAddComment_Success(t *testing.T) {
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"POST /rest/api/2/issue/SEC-1/comment": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["body"] != "hello" {
				t.Errorf("comment body = %v, want hello", body["body"])
			}
			w.WriteHeader(http.StatusOK)
		},
	})
	defer srv.Close()
	j := newJira(map[string]string{"base_url": srv.URL})
	if err := j.AddComment(context.Background(), "SEC-1", "hello"); err != nil {
		t.Fatalf("AddComment: %v", err)
	}
}

// TestJiraCloseTicket_MatchesTransitionByName pins findTransition's primary
// path: an exact (case-insensitive) name match against the candidate list.
func TestJiraCloseTicket_MatchesTransitionByName(t *testing.T) {
	var postedTransitionID string
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /rest/api/2/issue/SEC-1/transitions": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"transitions": []map[string]string{
					{"id": "11", "name": "In Progress"},
					{"id": "31", "name": "Done"},
				},
			})
		},
		"POST /rest/api/2/issue/SEC-1/transitions": func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			postedTransitionID = body["transition"].(map[string]any)["id"].(string)
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()
	j := newJira(map[string]string{"base_url": srv.URL})
	if err := j.CloseTicket(context.Background(), "SEC-1"); err != nil {
		t.Fatalf("CloseTicket: %v", err)
	}
	if postedTransitionID != "31" {
		t.Fatalf("posted transition id = %q, want 31 (Done)", postedTransitionID)
	}
}

// TestJiraReopenTicket_FallsBackToKeywordMatch pins findTransition's second
// tier: when none of the named candidates match exactly, it falls back to
// any transition whose name contains a done/close/resolv-style keyword —
// here simulated by having only keyword-bearing names for the REOPEN search
// (an unusual but valid workflow) to force the fallback path.
func TestJiraReopenTicket_FallsBackToLastTransitionWhenNoKeywordMatches(t *testing.T) {
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /rest/api/2/issue/SEC-1/transitions": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{
				"transitions": []map[string]string{
					{"id": "5", "name": "Escalate"},
					{"id": "6", "name": "Triage"},
				},
			})
		},
		"POST /rest/api/2/issue/SEC-1/transitions": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	})
	defer srv.Close()
	j := newJira(map[string]string{"base_url": srv.URL})
	// Neither name candidate ("Reopen", "Open", "To Do", …) nor a done/
	// close/resolv keyword appears among "Escalate"/"Triage" — findTransition
	// falls back to the last transition in the list rather than erroring.
	if err := j.ReopenTicket(context.Background(), "SEC-1"); err != nil {
		t.Fatalf("ReopenTicket: %v", err)
	}
}

func TestJiraFindTransition_NoTransitionsAvailableErrors(t *testing.T) {
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /rest/api/2/issue/SEC-1/transitions": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"transitions": []map[string]string{}})
		},
	})
	defer srv.Close()
	j := newJira(map[string]string{"base_url": srv.URL})
	if err := j.CloseTicket(context.Background(), "SEC-1"); err == nil {
		t.Fatal("expected an error when no transitions are available")
	}
}

func TestJiraGetStatus_MapsStatusCategory(t *testing.T) {
	cases := []struct {
		categoryKey string
		want        string
	}{
		{"done", "resolved"},
		{"new", "open"},
		{"undefined", "open"},
		{"indeterminate", "in_progress"},
	}
	for _, c := range cases {
		t.Run(c.categoryKey, func(t *testing.T) {
			srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
				"GET /rest/api/2/issue/SEC-1": func(w http.ResponseWriter, r *http.Request) {
					json.NewEncoder(w).Encode(map[string]any{
						"fields": map[string]any{
							"status": map[string]any{"statusCategory": map[string]string{"key": c.categoryKey}},
						},
					})
				},
			})
			defer srv.Close()
			j := newJira(map[string]string{"base_url": srv.URL})
			got, err := j.GetStatus(context.Background(), "SEC-1")
			if err != nil {
				t.Fatalf("GetStatus: %v", err)
			}
			if got != c.want {
				t.Errorf("GetStatus categoryKey=%q = %q, want %q", c.categoryKey, got, c.want)
			}
		})
	}
}

func TestJiraTestConnection_SuccessAndFailure(t *testing.T) {
	ok := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /rest/api/2/project/SEC": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
	})
	defer ok.Close()
	if err := newJira(map[string]string{"base_url": ok.URL, "project_key": "SEC"}).TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}

	bad := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /rest/api/2/project/SEC": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
	})
	defer bad.Close()
	if err := newJira(map[string]string{"base_url": bad.URL, "project_key": "SEC"}).TestConnection(context.Background()); err == nil {
		t.Fatal("expected an error for a 401 response")
	}
}

func TestJiraListProjects_Success(t *testing.T) {
	srv := jiraMock(t, map[string]func(w http.ResponseWriter, r *http.Request){
		"GET /rest/api/2/project": func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode([]map[string]string{
				{"key": "SEC", "name": "Security"},
				{"key": "OPS", "name": "Operations"},
			})
		},
	})
	defer srv.Close()
	j := newJira(map[string]string{"base_url": srv.URL})
	projects, err := j.ListProjects(context.Background())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 2 || projects[0]["key"] != "SEC" {
		t.Fatalf("projects = %+v", projects)
	}
}
