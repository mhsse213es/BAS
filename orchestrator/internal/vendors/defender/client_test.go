package defender

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func tokenMock(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"access_token":"tok","expires_in":3600}`))
	}))
}

func newTestClient(t *testing.T, tokenURL, graphURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	c.BaseURL = graphURL
	return c
}

func TestQueryAlerts_ReturnsNormalizedAlerts(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Suspicious process", "severity": "high",
					"createdDateTime": alertTime.Format(time.RFC3339),
					// The real Graph alerts_v2 field is "mitreTechniques", not
					// "techniques" -- this fixture mirrors the actual API so the
					// test can't pass against a typo that happens to match itself.
					"mitreTechniques": []string{"T1055"},
					"evidence":        []map[string]any{{"deviceDnsName": "HOST1"}},
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), alertTime.Add(-time.Hour), alertTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if alerts[0].ID != "alert-1" || alerts[0].DeviceDNSName != "HOST1" || len(alerts[0].Techniques) != 1 {
		t.Fatalf("alerts[0] = %+v, want alert-1/HOST1/[T1055]", alerts[0])
	}
}

func TestQueryAlerts_ParsesInvestigationStateAndResolvedDateTime(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	resolvedTime := alertTime.Add(5 * time.Minute)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Malicious email", "severity": "high",
					"createdDateTime":    alertTime.Format(time.RFC3339),
					"investigationState": "successfullyRemediated",
					"resolvedDateTime":   resolvedTime.Format(time.RFC3339),
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), alertTime.Add(-time.Hour), alertTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if alerts[0].InvestigationState != "successfullyRemediated" {
		t.Errorf("InvestigationState = %q, want %q", alerts[0].InvestigationState, "successfullyRemediated")
	}
	if !alerts[0].ResolvedDateTime.Equal(resolvedTime) {
		t.Errorf("ResolvedDateTime = %v, want %v", alerts[0].ResolvedDateTime, resolvedTime)
	}
}

// TestQueryAlerts_UnresolvedAlert_ResolvedDateTimeIsZero proves an
// alert with no resolvedDateTime (a non-terminal investigationState,
// e.g. "running") correctly parses to the zero time.Time, never an
// error -- unlike QueryAnalyzedEmails' loggedDateTime, an absent
// resolution timestamp here is a real, valid state (not yet
// resolved), not a parsing failure to guard against.
func TestQueryAlerts_UnresolvedAlert_ResolvedDateTimeIsZero(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "alert-1", "title": "Malicious email", "severity": "high",
					"createdDateTime":    alertTime.Format(time.RFC3339),
					"investigationState": "running",
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	alerts, err := c.QueryAlerts(context.Background(), alertTime.Add(-time.Hour), alertTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("QueryAlerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if !alerts[0].ResolvedDateTime.IsZero() {
		t.Errorf("ResolvedDateTime = %v, want zero value for an unresolved alert", alerts[0].ResolvedDateTime)
	}
}

func TestQueryAlerts_GraphHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.QueryAlerts(context.Background(), time.Now().Add(-time.Hour), time.Now()); err == nil {
		t.Fatal("expected an error from a 403 Graph response")
	}
}

func TestTestConnection_Success(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
}

func TestQueryMailAlerts_EmptyHint_ReturnsAll(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "alert-1", "title": "Phish delivered", "severity": "medium", "createdDateTime": alertTime.Format(time.RFC3339)},
				{"id": "alert-2", "title": "Malware detected", "severity": "high", "createdDateTime": alertTime.Format(time.RFC3339)},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	alerts, err := c.QueryMailAlerts(context.Background(), alertTime.Add(-time.Hour), alertTime.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("QueryMailAlerts: %v", err)
	}
	if len(alerts) != 2 {
		t.Fatalf("alerts = %+v, want 2 -- an empty correlationHint must return every alert", alerts)
	}
}

func TestQueryMailAlerts_FiltersByCorrelationHint(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	alertTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "alert-1", "title": "Phish delivered to cfo-test@example-lab.test", "severity": "medium", "createdDateTime": alertTime.Format(time.RFC3339)},
				{"id": "alert-2", "title": "Unrelated malware alert", "severity": "high", "createdDateTime": alertTime.Format(time.RFC3339)},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	alerts, err := c.QueryMailAlerts(context.Background(), alertTime.Add(-time.Hour), alertTime.Add(time.Hour), "cfo-test@example-lab.test")
	if err != nil {
		t.Fatalf("QueryMailAlerts: %v", err)
	}
	if len(alerts) != 1 || alerts[0].ID != "alert-1" {
		t.Fatalf("alerts = %+v, want only alert-1 (the one whose RawJSON contains the correlation hint)", alerts)
	}
}

func TestQueryAnalyzedEmails_ParsesDeliveryAndAuthenticationDetails(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	loggedTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	var gotQuery url.Values
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{
					"id": "email-1", "loggedDateTime": loggedTime.Format(time.RFC3339),
					"networkMessageId": "nmid-1", "internetMessageId": "<imid-1@example-lab.test>",
					"recipientEmailAddress": "finance-test@example-lab.test", "subject": "Urgent wire request",
					"policy": "Anti-phish policy", "policyAction": "Quarantine message",
					"originalDelivery": map[string]any{"action": "blocked", "location": "quarantine"},
					"latestDelivery":   map[string]any{"action": "blocked", "location": "quarantine"},
					"authenticationDetails": map[string]any{
						"senderPolicyFramework": "fail", "dkim": "fail", "dmarc": "fail", "compositeAuthentication": "fail",
					},
					"alertIds": []string{"alert-1"},
				},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	emails, err := c.QueryAnalyzedEmails(context.Background(), loggedTime.Add(-time.Hour), loggedTime.Add(time.Hour), "recipientEmailAddress eq 'finance-test@example-lab.test'")
	if err != nil {
		t.Fatalf("QueryAnalyzedEmails: %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("emails = %+v, want 1", emails)
	}
	got := emails[0]
	if got.LatestDeliveryAction != "blocked" || got.LatestDeliveryLocation != "quarantine" {
		t.Errorf("LatestDelivery = (%q, %q), want (blocked, quarantine)", got.LatestDeliveryAction, got.LatestDeliveryLocation)
	}
	if got.SPF != "fail" || got.DKIM != "fail" || got.DMARC != "fail" {
		t.Errorf("auth details = (SPF=%q, DKIM=%q, DMARC=%q), want all fail", got.SPF, got.DKIM, got.DMARC)
	}
	if got.NetworkMessageID != "nmid-1" {
		t.Errorf("NetworkMessageID = %q, want %q", got.NetworkMessageID, "nmid-1")
	}
	if len(got.AlertIDs) != 1 || got.AlertIDs[0] != "alert-1" {
		t.Errorf("AlertIDs = %+v, want [alert-1]", got.AlertIDs)
	}
	if gotQuery.Get("$filter") != "recipientEmailAddress eq 'finance-test@example-lab.test'" {
		t.Errorf("$filter sent = %q, want the recipient filter unchanged", gotQuery.Get("$filter"))
	}
	if gotQuery.Get("startTime") == "" || gotQuery.Get("endTime") == "" {
		t.Error("startTime/endTime query params were not sent")
	}
}

func TestQueryAnalyzedEmails_EmptyFilter_OmitsFilterParam(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	var gotQuery url.Values
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.QueryAnalyzedEmails(context.Background(), time.Now().Add(-time.Hour), time.Now(), ""); err != nil {
		t.Fatalf("QueryAnalyzedEmails: %v", err)
	}
	if _, ok := gotQuery["$filter"]; ok {
		t.Errorf("$filter was sent as %q, want it omitted entirely for an empty filter", gotQuery.Get("$filter"))
	}
}

func TestQueryAnalyzedEmails_UnparseableLoggedDateTime_RecordExcluded(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	validTime := time.Date(2026, 7, 14, 10, 2, 0, 0, time.UTC)
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{
				{"id": "email-bad", "loggedDateTime": "not-a-timestamp", "recipientEmailAddress": "finance-test@example-lab.test"},
				{"id": "email-good", "loggedDateTime": validTime.Format(time.RFC3339), "recipientEmailAddress": "finance-test@example-lab.test"},
			},
		})
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	emails, err := c.QueryAnalyzedEmails(context.Background(), validTime.Add(-time.Hour), validTime.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("QueryAnalyzedEmails: %v", err)
	}
	if len(emails) != 1 || emails[0].ID != "email-good" {
		t.Fatalf("emails = %+v, want exactly email-good -- a record with an unparseable loggedDateTime must never surface with a zero-value Timestamp", emails)
	}
}

func TestQueryAnalyzedEmails_GraphHTTPError_ReturnsError(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()
	graphSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer graphSrv.Close()

	c := newTestClient(t, tokenSrv.URL, graphSrv.URL)
	if _, err := c.QueryAnalyzedEmails(context.Background(), time.Now().Add(-time.Hour), time.Now(), ""); err == nil {
		t.Fatal("expected an error from a 403 Graph response")
	}
}

func newTestClientWithActionURLs(t *testing.T, tokenURL, actionTokenURL, actionBaseURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.TokenURL() = tokenURL
	*c.ActionTokenURL() = actionTokenURL
	c.ActionBaseURL = actionBaseURL
	return c
}

func TestResolveDevice_FindsAndCaches(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var queryCalls int
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryCalls++
		if r.URL.Query().Get("$filter") != "computerDnsName eq 'HOST1'" {
			t.Errorf("$filter = %q", r.URL.Query().Get("$filter"))
		}
		json.NewEncoder(w).Encode(map[string]any{
			"value": []map[string]any{{"id": "machine-123", "computerDnsName": "HOST1"}},
		})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	id, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice: %v", err)
	}
	if id != "machine-123" {
		t.Fatalf("id = %q, want machine-123", id)
	}

	id2, err := c.ResolveDevice(context.Background(), "HOST1")
	if err != nil {
		t.Fatalf("ResolveDevice (cached): %v", err)
	}
	if id2 != "machine-123" {
		t.Fatalf("cached id = %q, want machine-123", id2)
	}
	if queryCalls != 1 {
		t.Fatalf("queryCalls = %d, want 1 (second ResolveDevice should reuse the cache)", queryCalls)
	}
}

func TestResolveDevice_NoMatch_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	machinesSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{}})
	}))
	defer machinesSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, machinesSrv.URL)
	if _, err := c.ResolveDevice(context.Background(), "NOHOST"); err == nil {
		t.Fatal("expected an error when no machine matches the hostname")
	}
}

func TestIsolate_CallsIsolateEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	var gotBody map[string]any
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "action-abc"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.Isolate(context.Background(), "machine-123")
	if err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	if actionID != "action-abc" {
		t.Fatalf("actionID = %q, want action-abc", actionID)
	}
	if gotPath != "/machines/machine-123/isolate" {
		t.Fatalf("path = %q, want /machines/machine-123/isolate", gotPath)
	}
	if gotBody["IsolationType"] != "Full" {
		t.Fatalf("body = %v, want IsolationType=Full", gotBody)
	}
}

func TestRelease_CallsUnisolateEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"id": "action-def"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.Release(context.Background(), "machine-123")
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if actionID != "action-def" {
		t.Fatalf("actionID = %q, want action-def", actionID)
	}
	if gotPath != "/machines/machine-123/unisolate" {
		t.Fatalf("path = %q, want /machines/machine-123/unisolate", gotPath)
	}
}

func TestMachineAction_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	if _, err := c.Isolate(context.Background(), "machine-999"); err == nil {
		t.Fatal("expected an error from a 403 machine action response")
	}
}

func TestQuarantineFile_CallsStopAndQuarantineFileEndpoint(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotPath string
	var gotBody map[string]any
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "action-quarantine-1"})
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	actionID, err := c.QuarantineFile(context.Background(), "machine-123", "aabbccddeeff00112233445566778899aabbccdd")
	if err != nil {
		t.Fatalf("QuarantineFile: %v", err)
	}
	if actionID != "action-quarantine-1" {
		t.Fatalf("actionID = %q, want action-quarantine-1", actionID)
	}
	if gotPath != "/machines/machine-123/StopAndQuarantineFile" {
		t.Fatalf("path = %q, want /machines/machine-123/StopAndQuarantineFile", gotPath)
	}
	if gotBody["Sha1"] != "aabbccddeeff00112233445566778899aabbccdd" {
		t.Fatalf("body Sha1 = %v, want the test sha1", gotBody["Sha1"])
	}
}

func TestQuarantineFile_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	actionSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer actionSrv.Close()

	c := newTestClientWithActionURLs(t, "", actionTokenSrv.URL, actionSrv.URL)
	if _, err := c.QuarantineFile(context.Background(), "machine-123", "badhash"); err == nil {
		t.Fatal("expected an error from a 400 StopAndQuarantineFile response")
	}
}

func newTestClientWithLiveResponseURL(t *testing.T, actionTokenURL, liveResponseURL, scriptName string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1", KillProcessScriptName: scriptName})
	*c.ActionTokenURL() = actionTokenURL
	c.LiveResponseURL = liveResponseURL
	return c
}

func TestKillProcess_CallsRunLiveResponseWithConfiguredScript(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotBody map[string]any
	lrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "machineaction-1"})
	}))
	defer lrSrv.Close()

	c := newTestClientWithLiveResponseURL(t, actionTokenSrv.URL, lrSrv.URL, "Contoso-KillProc.ps1")
	actionID, err := c.KillProcess(context.Background(), "machine-123", 4821)
	if err != nil {
		t.Fatalf("KillProcess: %v", err)
	}
	if actionID != "machineaction-1" {
		t.Fatalf("actionID = %q, want machineaction-1", actionID)
	}
	commands, ok := gotBody["Commands"].([]any)
	if !ok || len(commands) != 1 {
		t.Fatalf("Commands = %v, want exactly one command", gotBody["Commands"])
	}
	cmd, ok := commands[0].(map[string]any)
	if !ok || cmd["type"] != "RunScript" {
		t.Fatalf("commands[0] = %v, want type=RunScript", commands[0])
	}
	params, ok := cmd["params"].([]any)
	if !ok || len(params) != 2 {
		t.Fatalf("params = %v, want ScriptName and Args", cmd["params"])
	}
	scriptParam, ok := params[0].(map[string]any)
	if !ok || scriptParam["key"] != "ScriptName" || scriptParam["value"] != "Contoso-KillProc.ps1" {
		t.Fatalf("params[0] = %v, want key=ScriptName value=Contoso-KillProc.ps1", params[0])
	}
	argsParam, ok := params[1].(map[string]any)
	if !ok || argsParam["key"] != "Args" || argsParam["value"] != "4821" {
		t.Fatalf("params[1] = %v, want key=Args value=4821", params[1])
	}
}

func TestKillProcess_EmptyScriptName_DefaultsToAudspectScript(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()

	var gotBody map[string]any
	lrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(map[string]any{"id": "machineaction-2"})
	}))
	defer lrSrv.Close()

	c := newTestClientWithLiveResponseURL(t, actionTokenSrv.URL, lrSrv.URL, "")
	if _, err := c.KillProcess(context.Background(), "machine-123", 100); err != nil {
		t.Fatalf("KillProcess: %v", err)
	}
	commands := gotBody["Commands"].([]any)
	cmd := commands[0].(map[string]any)
	params := cmd["params"].([]any)
	scriptParam := params[0].(map[string]any)
	if scriptParam["value"] != "Audspect-KillProcess.ps1" {
		t.Fatalf("default script name = %v, want Audspect-KillProcess.ps1", scriptParam["value"])
	}
}

func TestKillProcess_HTTPError_ReturnsError(t *testing.T) {
	actionTokenSrv := tokenMock(t)
	defer actionTokenSrv.Close()
	lrSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"message":"Script not found in library"}}`))
	}))
	defer lrSrv.Close()

	c := newTestClientWithLiveResponseURL(t, actionTokenSrv.URL, lrSrv.URL, "")
	if _, err := c.KillProcess(context.Background(), "machine-123", 100); err == nil {
		t.Fatal("expected an error when the vendor reports the script isn't found")
	}
}
