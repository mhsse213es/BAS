package observability

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPostAlert_SendsRuleAndStateAsJSON(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			t.Errorf("method %s content-type %q", r.Method, r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := postAlert(context.Background(), srv.URL, Alert{
		RuleName: "scheduler_stalled", Description: "ticks dropped", Severity: "critical", Firing: true,
		FiredAt: time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC), Message: "FIRING: ticks dropped (critical)",
	})
	if err != nil {
		t.Fatalf("postAlert: %v", err)
	}
	if got["rule"] != "scheduler_stalled" || got["state"] != "FIRING" || got["severity"] != "critical" {
		t.Fatalf("payload = %v", got)
	}
}

func TestPostAlert_ServerErrorIsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if err := postAlert(context.Background(), srv.URL, Alert{RuleName: "x"}); err == nil {
		t.Fatal("postAlert returned nil for a 500 from the webhook")
	}
}

func TestFireAlert_DeliversToWebhookWithoutBlockingEvaluation(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	e := &AlertEngine{fired: map[string]bool{}}
	e.fireAlert(&AlertRule{Name: "scheduler_stalled", Description: "ticks", Severity: "critical", NotificationWebhook: srv.URL}, true)
	select {
	case body := <-got:
		if !strings.Contains(body, `"state":"FIRING"`) || !strings.Contains(body, `"rule":"scheduler_stalled"`) {
			t.Fatalf("webhook body = %s", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("alert never reached the webhook")
	}
	if len(e.history) != 1 {
		t.Fatalf("history has %d alerts, want 1", len(e.history))
	}
}
