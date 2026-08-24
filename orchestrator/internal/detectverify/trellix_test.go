package detectverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func newTestTrellixConnector(t *testing.T, baseURL string) *trellixConnector {
	t.Helper()
	c := newTrellixConnector(Config{Provider: "trellix", BaseURL: baseURL, APIToken: "tok"})
	return c
}

func trellixDetectionsPage(dets ...trellixDetection) string {
	b, _ := json.Marshal(struct {
		Data []trellixDetection `json:"data"`
	}{Data: dets})
	return string(b)
}

func TestTrellixQueryPage_SetsAuthorizationSinceAndLimit(t *testing.T) {
	var gotAuth, gotSince, gotLimit, gotOffset string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSince = r.URL.Query().Get("since")
		gotLimit = r.URL.Query().Get("limit")
		gotOffset = r.URL.Query().Get("offset")
		w.Write([]byte(trellixDetectionsPage()))
	}))
	defer srv.Close()

	c := newTestTrellixConnector(t, srv.URL)
	since := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	if _, err := c.queryPage(context.Background(), since, 0); err != nil {
		t.Fatalf("queryPage: %v", err)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer tok")
	}
	if gotSince != since.Format(time.RFC3339) {
		t.Errorf("since = %q, want %q", gotSince, since.Format(time.RFC3339))
	}
	if gotLimit != "100" {
		t.Errorf("limit = %q, want 100", gotLimit)
	}
	if gotOffset != "0" {
		t.Errorf("offset = %q, want 0", gotOffset)
	}
}

func TestTrellixFetchDetections_PaginatesUntilShortPage(t *testing.T) {
	stepTime := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	makePage := func(offset, count int) []trellixDetection {
		dets := make([]trellixDetection, count)
		for i := range count {
			dets[i] = trellixDetection{
				ID: "det-" + strconv.Itoa(offset+i), HostName: "HOST1",
				DetectedAt: stepTime.Add(time.Duration(offset+i) * time.Second),
				Severity:   "medium",
			}
		}
		return dets
	}

	var offsetsSeen []string
	c := &trellixConnector{pageSize: 2, token: "tok", httpClient: http.DefaultClient}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("offset")
		offsetsSeen = append(offsetsSeen, offset)
		switch offset {
		case "0":
			w.Write([]byte(trellixDetectionsPage(makePage(0, 2)...))) // full page -> keep going
		case "2":
			w.Write([]byte(trellixDetectionsPage(makePage(2, 1)...))) // short page -> stop
		default:
			t.Fatalf("unexpected offset %q", offset)
		}
	}))
	defer srv.Close()
	c.baseURL = srv.URL

	alerts, err := c.fetchDetections(context.Background(), VerifyRequest{
		HostName: "HOST1", WindowStart: stepTime.Add(-time.Minute), WindowEnd: stepTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("fetchDetections: %v", err)
	}
	if len(offsetsSeen) != 2 || offsetsSeen[0] != "0" || offsetsSeen[1] != "2" {
		t.Fatalf("offsetsSeen = %v, want [0 2]", offsetsSeen)
	}
	if len(alerts) != 3 {
		t.Fatalf("alerts = %d, want 3 (2 from page 1 + 1 from page 2)", len(alerts))
	}
}

func TestTrellixFetchDetections_MatchOnPage2_TechniqueDetected(t *testing.T) {
	stepTime := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	c := &trellixConnector{pageSize: 1, token: "tok", httpClient: http.DefaultClient}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("offset") {
		case "0":
			w.Write([]byte(trellixDetectionsPage(trellixDetection{
				ID: "det-0", HostName: "HOST1", DetectedAt: stepTime, Severity: "low",
			})))
		case "1":
			w.Write([]byte(trellixDetectionsPage(trellixDetection{
				ID: "det-1", HostName: "HOST1", DetectedAt: stepTime.Add(5 * time.Second),
				Severity: "high", MitreAttack: []string{"T1059.001"},
			})))
		default:
			w.Write([]byte(trellixDetectionsPage())) // terminates the loop
		}
	}))
	defer srv.Close()
	c.baseURL = srv.URL

	result, err := c.Verify(context.Background(), VerifyRequest{
		TechniqueID: "T1059.001", HostName: "HOST1", StepExecutedAt: stepTime,
		WindowStart: stepTime.Add(-time.Minute), WindowEnd: stepTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictDetected || result.Confidence != ConfidenceHigh {
		t.Fatalf("result = %+v, want Detected/high (match was on page 2)", result)
	}
	if len(result.MatchedAlerts) != 2 {
		t.Fatalf("MatchedAlerts = %d, want 2 (both pages returned alerts for this host/window)", len(result.MatchedAlerts))
	}
}

func TestTrellixFetchDetections_FiltersOtherHosts(t *testing.T) {
	stepTime := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	c := newTestTrellixConnector(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(trellixDetectionsPage(
			trellixDetection{ID: "det-mine", HostName: "HOST1", DetectedAt: stepTime, Severity: "high"},
			trellixDetection{ID: "det-other", HostName: "SOMEONE-ELSE", DetectedAt: stepTime, Severity: "high"},
		)))
	}))
	defer srv.Close()
	c.baseURL = srv.URL

	alerts, err := c.fetchDetections(context.Background(), VerifyRequest{
		HostName: "HOST1", WindowStart: stepTime.Add(-time.Minute), WindowEnd: stepTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("fetchDetections: %v", err)
	}
	if len(alerts) != 1 || alerts[0].AlertID != "det-mine" {
		t.Fatalf("alerts = %+v, want only det-mine", alerts)
	}
}

func TestTrellixFetchDetections_FiltersOutsideWindowEnd(t *testing.T) {
	stepTime := time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC)
	c := newTestTrellixConnector(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(trellixDetectionsPage(
			trellixDetection{ID: "det-in-window", HostName: "HOST1", DetectedAt: stepTime, Severity: "high"},
			trellixDetection{ID: "det-after-window", HostName: "HOST1", DetectedAt: stepTime.Add(2 * time.Hour), Severity: "high"},
		)))
	}))
	defer srv.Close()
	c.baseURL = srv.URL

	alerts, err := c.fetchDetections(context.Background(), VerifyRequest{
		HostName: "HOST1", WindowStart: stepTime.Add(-time.Minute), WindowEnd: stepTime.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("fetchDetections: %v", err)
	}
	if len(alerts) != 1 || alerts[0].AlertID != "det-in-window" {
		t.Fatalf("alerts = %+v, want only det-in-window (since has no upper bound server-side)", alerts)
	}
}

func TestTrellixFetchDetections_NoMatches_NotDetected(t *testing.T) {
	c := newTestTrellixConnector(t, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(trellixDetectionsPage()))
	}))
	defer srv.Close()
	c.baseURL = srv.URL

	result, err := c.Verify(context.Background(), VerifyRequest{TechniqueID: "T1059.001", HostName: "HOST1", StepExecutedAt: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Verdict != VerdictNotDetected {
		t.Fatalf("Verdict = %q, want NotDetected", result.Verdict)
	}
}

func TestTrellixQueryPage_401_ReturnsAuthenticationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid token"}`))
	}))
	defer srv.Close()

	c := newTestTrellixConnector(t, srv.URL)
	_, err := c.queryPage(context.Background(), time.Now(), 0)
	if err == nil {
		t.Fatal("expected an authentication error from a 401 response")
	}
}

func TestTrellixQueryPage_ServerError_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestTrellixConnector(t, srv.URL)
	if _, err := c.queryPage(context.Background(), time.Now(), 0); err == nil {
		t.Fatal("expected an error from a 500 response, not a fabricated empty page")
	}
}

func TestTrellixTestConnection_SuccessOnEmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(trellixDetectionsPage())) // 2xx, zero detections
	}))
	defer srv.Close()

	c := newTestTrellixConnector(t, srv.URL)
	if err := c.TestConnection(context.Background()); err != nil {
		t.Fatalf("TestConnection: %v, want success on an empty-but-2xx response", err)
	}
}

func TestTrellixTestConnection_401_Fails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestTrellixConnector(t, srv.URL)
	if err := c.TestConnection(context.Background()); err == nil {
		t.Fatal("expected TestConnection to fail on a 401")
	}
}

func TestNormalizeTrellixDetection_PassesThroughUnrecognizedTechniqueTags(t *testing.T) {
	// matchAlerts, not this function, decides what counts as a match --
	// don't filter or validate mitreAttack values here.
	d := trellixDetection{ID: "d1", MitreAttack: []string{"T1059.001", "not-a-real-technique-id"}}
	a := normalizeTrellixDetection(d)
	if len(a.Techniques) != 2 {
		t.Fatalf("Techniques = %v, want both values passed through unfiltered", a.Techniques)
	}
}
