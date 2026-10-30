package defender

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newHuntTestClient(t *testing.T, tokenURL, huntURL string) *Client {
	t.Helper()
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	*c.HuntTokenURL() = tokenURL
	c.HuntBaseURL = huntURL
	return c
}

// FindBlockEvents must query DeviceEvents for the exact device and window and
// return only block action types. Anything else would let a non-block event
// stand in for a prevention result.
func TestFindBlockEvents_QueriesDeviceEventsAndParsesRows(t *testing.T) {
	tokenSrv := tokenMock(t)
	defer tokenSrv.Close()

	var gotQuery string
	huntSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/advancedhunting/run" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Query string `json:"Query"`
		}
		_ = json.Unmarshal(body, &req)
		gotQuery = req.Query
		json.NewEncoder(w).Encode(map[string]any{
			"Results": []map[string]any{
				{"Timestamp": "2026-10-29T10:02:00Z", "ActionType": "ControlledFolderAccessViolationBlocked"},
			},
		})
	}))
	defer huntSrv.Close()

	c := newHuntTestClient(t, tokenSrv.URL, huntSrv.URL)
	start := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	recs, err := c.FindBlockEvents(t.Context(), "HOST1", start, end)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].ActionType != "ControlledFolderAccessViolationBlocked" {
		t.Fatalf("records = %+v", recs)
	}
	for _, want := range []string{`DeviceName =~ "HOST1"`, "ControlledFolderAccessViolationBlocked", `startswith "Asr"`, "DeviceEvents"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query missing %q:\n%s", want, gotQuery)
		}
	}
}

// A device name is interpolated into KQL, so anything outside the hostname
// character set is rejected before any request is sent.
func TestFindBlockEvents_RejectsDeviceNameThatIsNotAHostname(t *testing.T) {
	c := New(Config{TenantID: "t1", ClientID: "c1", ClientSecret: "s1"})
	hit := false
	huntSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer huntSrv.Close()
	c.HuntBaseURL = huntSrv.URL

	start := time.Now()
	_, err := c.FindBlockEvents(t.Context(), `HOST1" or 1==1 //`, start, start.Add(time.Minute))
	if err == nil {
		t.Fatal("expected a non-hostname device name to be rejected")
	}
	if hit {
		t.Fatal("rejected device name must not reach the hunting API")
	}
}
