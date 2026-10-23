package dbsim

// Contract-pinning tests for the existing code dbsim builds on (spec section 3).
// They pass against current behaviour and exist so a later change to those
// packages fails loudly here instead of silently invalidating dbsim. They use
// only exported APIs: the Elastic query is observed on the wire via httptest.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/audspect/bas/internal/detectverify"
	"github.com/audspect/bas/internal/dlpreport"
)

func TestRecordValidateRequiresLimitationsWhenUncertain(t *testing.T) {
	r := dlpreport.Record{
		ScenarioID:     "DB-01",
		Enforcement:    dlpreport.EnforcementAllowed,
		Classification: dlpreport.ClassificationCorrect,
		Telemetry:      dlpreport.TelemetryUnverifiable,
		Response:       dlpreport.ResponseAlerted,
	}
	if err := r.Validate(); err == nil {
		t.Fatal("Telemetry=Unverifiable with empty Limitations must fail Validate")
	}
	r.Limitations = "no audit source reachable"
	if err := r.Validate(); err != nil {
		t.Fatalf("with Limitations set Validate must pass, got %v", err)
	}
}

func contractReq() detectverify.VerifyRequest {
	t0 := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	return detectverify.VerifyRequest{
		RunID: "run-1", ExpectationID: "exp-1", TechniqueID: "T1005",
		HostName: "db-01", HostIP: "10.0.0.5",
		StepExecutedAt: t0,
		WindowStart:    t0.Add(-time.Minute),
		WindowEnd:      t0.Add(10 * time.Minute),
	}
}

func elasticEnvelope(hits ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{
		"timed_out": false,
		"_shards":   map[string]any{"total": 1, "failed": 0},
		"hits":      map[string]any{"hits": hits},
	})
	return string(b)
}

func TestElasticBuildQueryScopesByHostNameAndIP(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = w.Write([]byte(elasticEnvelope()))
	}))
	defer srv.Close()

	c, err := detectverify.NewConnector(detectverify.Config{Provider: "elastic", BaseURL: srv.URL, APIToken: "K"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Verify(context.Background(), contractReq()); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body)
	for _, want := range []string{
		`"host.name"`, `"host.ip"`, "db-01", "10.0.0.5",
		"2026-10-22T08:59:00Z", "2026-10-22T09:10:00Z", `"@timestamp"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("query missing %s: %s", want, raw)
		}
	}
	// Pins the fact that the query has no marker/free-text clause: a marker can
	// only be applied after the fact (spec section 6).
	for _, absent := range []string{`"match"`, `"query_string"`, `"wildcard"`} {
		if strings.Contains(string(raw), absent) {
			t.Errorf("query unexpectedly contains %s; spec section 3 assumed no marker clause: %s", absent, raw)
		}
	}
	// Amendment A1: "message" is now only in the _source whitelist (so the
	// marker is visible in RawJSON), never in the query clause.
	var q struct {
		Source []string       `json:"_source"`
		Query  map[string]any `json:"query"`
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	qb, _ := json.Marshal(q.Query)
	if strings.Contains(string(qb), `"message"`) {
		t.Errorf("message must not appear in the query clause: %s", qb)
	}
	hasMsg := false
	for _, f := range q.Source {
		hasMsg = hasMsg || f == "message"
	}
	if !hasMsg {
		t.Errorf("A1: _source whitelist must include message: %v", q.Source)
	}
}

func elasticHit(id, ruleName string, extra map[string]any) map[string]any {
	src := map[string]any{
		"@timestamp":                   "2026-10-22T09:01:00Z",
		"kibana.alert.uuid":            id,
		"kibana.alert.rule.name":       ruleName,
		"kibana.alert.severity":        "high",
		"kibana.alert.workflow_status": "open",
		"host":                         map[string]any{"name": "db-01"},
	}
	for k, v := range extra {
		src[k] = v
	}
	return map[string]any{"_id": "doc-" + id, "_source": src, "sort": []any{1, id}}
}

func verifyAgainst(t *testing.T, hits ...map[string]any) detectverify.VerifyResult {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(elasticEnvelope(hits...)))
	}))
	defer srv.Close()
	c, err := detectverify.NewConnector(detectverify.Config{Provider: "elastic", BaseURL: srv.URL, APIToken: "K"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Verify(context.Background(), contractReq())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestMatchedAlertKeepsRawJSON(t *testing.T) {
	res := verifyAgainst(t, elasticHit("a1", "DB marker rule", nil))
	if res.Verdict != detectverify.VerdictDetected || len(res.MatchedAlerts) != 1 {
		t.Fatalf("want 1 Detected alert, got %+v", res)
	}
	m := res.MatchedAlerts[0]
	if len(m.RawJSON) == 0 || !json.Valid(m.RawJSON) {
		t.Fatalf("MatchedAlert.RawJSON must be non-empty valid JSON, got %q", m.RawJSON)
	}
	if !strings.Contains(string(m.RawJSON), "DB marker rule") {
		t.Errorf("RawJSON lost the rule name: %s", m.RawJSON)
	}
}

// TestContractElasticRawJSONIsNormalizedSubset pins a fact that CONTRADICTS the
// assumption in spec section 3/6 ("keeps RawJSON, so dbsim post-filters it for
// the marker"): for Elastic, RawJSON is a synthesized summary
// {alertId,ruleName,timestamp,severity,techniques,workflowStatus}, NOT the
// alert document, and the query's _source whitelist excludes message/event
// fields. A marker carried in the audited statement is therefore invisible to
// the post-filter unless the connector is extended. See docs/dbsim-discovery.md.
func TestContractElasticRawJSONIsNormalizedSubset(t *testing.T) {
	const marker = "BAS-DB-MARKER-7f3a"
	res := verifyAgainst(t, elasticHit("a2", "Generic DB rule", map[string]any{
		"message":                     "SELECT 1 /* " + marker + " */",
		"kibana.alert.original_event": map[string]any{"original": marker},
		"kibana.alert.reason":         marker,
		"kibana.alert.original_time":  "2026-10-22T09:01:00Z",
	}))
	if len(res.MatchedAlerts) != 1 {
		t.Fatalf("want 1 alert, got %d", len(res.MatchedAlerts))
	}
	// Amendment A1 (Task 12): the connector now exposes the whitelisted alert
	// source under "source", so the exact-marker post-filter is viable.
	if !strings.Contains(string(res.MatchedAlerts[0].RawJSON), marker) {
		t.Fatalf("A1: RawJSON must carry the source so the marker is visible: %s", res.MatchedAlerts[0].RawJSON)
	}
	var m map[string]any
	if err := json.Unmarshal(res.MatchedAlerts[0].RawJSON, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"alertId", "ruleName", "timestamp", "severity", "techniques", "workflowStatus"} {
		if _, ok := m[k]; !ok {
			t.Errorf("RawJSON missing normalized key %q: %v", k, m)
		}
	}
}
