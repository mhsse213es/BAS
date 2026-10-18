package purview

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func newTestClient(t *testing.T, tokenURL, baseURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.BaseURL = baseURL
	return c
}

func TestQueryDLPEvents_ListsContentThenFetchesAndNormalizes(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	created := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	var contentURL string
	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/activity/feed/subscriptions/content":
			json.NewEncoder(w).Encode([]map[string]any{
				{"contentUri": contentURL, "contentId": "blob-1", "contentType": "DLP.All"},
			})
		case r.URL.Path == "/contentblob":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"Id": "rec-1", "Workload": "SharePoint", "Operation": "DlpRuleMatch",
					"CreationTime": created.Format("2006-01-02T15:04:05"),
					"UserId":       "user@example-lab.test", "ObjectId": "https://example-lab.sharepoint.com/doc.csv",
					"PolicyDetails": []map[string]any{
						{
							"PolicyName": "BFSI PAN Policy",
							"Rules": []map[string]any{
								{"RuleName": "Block external share", "Actions": []map[string]any{{"Action": "BlockAccess"}}},
							},
						},
					},
				},
			})
		default:
			t.Errorf("unexpected request path %s", r.URL.Path)
		}
	}))
	defer mgmtSrv.Close()
	contentURL = mgmtSrv.URL + "/contentblob"

	c := newTestClient(t, tokenSrv.URL, mgmtSrv.URL)
	events, err := c.QueryDLPEvents(context.Background(), created.Add(-time.Hour), created.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryDLPEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want 1", events)
	}
	e := events[0]
	if e.Workload != "SharePoint" || e.Operation != "DlpRuleMatch" || e.UserID != "user@example-lab.test" {
		t.Errorf("event = %+v, want Workload=SharePoint Operation=DlpRuleMatch UserID=user@example-lab.test", e)
	}
	if e.PolicyName != "BFSI PAN Policy" {
		t.Errorf("PolicyName = %q, want %q", e.PolicyName, "BFSI PAN Policy")
	}
	if len(e.Actions) != 1 || e.Actions[0] != "BlockAccess" {
		t.Errorf("Actions = %v, want [BlockAccess]", e.Actions)
	}
}

func TestQueryDLPEvents_EmptyContentList_ReturnsEmptyNotError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer mgmtSrv.Close()

	c := newTestClient(t, tokenSrv.URL, mgmtSrv.URL)
	events, err := c.QueryDLPEvents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("QueryDLPEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("events = %+v, want empty", events)
	}
}

func TestQueryDLPEvents_PermissionDenied_NamesTheMissingScope(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":"AF50001","message":"Access denied"}}`))
	}))
	defer mgmtSrv.Close()

	c := newTestClient(t, tokenSrv.URL, mgmtSrv.URL)
	_, err := c.QueryDLPEvents(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err == nil {
		t.Fatal("want an error for HTTP 403, got nil")
	}
	if !strings.Contains(err.Error(), "ActivityFeed.ReadDlp") {
		t.Errorf("error = %q, want it to name the missing ActivityFeed.ReadDlp permission", err.Error())
	}
}

func TestEnsureSubscriptionStarted_AlreadyEnabled_TreatedAsSuccess(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"code":"AF20024","message":"The subscription is already enabled. No property change happened."}}`))
	}))
	defer mgmtSrv.Close()

	c := newTestClient(t, tokenSrv.URL, mgmtSrv.URL)
	if err := c.EnsureSubscriptionStarted(context.Background()); err != nil {
		t.Errorf("EnsureSubscriptionStarted: %v, want nil (already-enabled is success)", err)
	}
}

func TestEnsureSubscriptionStarted_GenuineError_Fails(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":{"code":"AF50001","message":"Access denied"}}`))
	}))
	defer mgmtSrv.Close()

	c := newTestClient(t, tokenSrv.URL, mgmtSrv.URL)
	if err := c.EnsureSubscriptionStarted(context.Background()); err == nil {
		t.Error("want an error for a genuine access-denied response, got nil")
	}
}

func TestTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	mgmtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{})
	}))
	defer mgmtSrv.Close()

	c := newTestClient(t, tokenSrv.URL, mgmtSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Errorf("TestConnection: %v", err)
	}
}
