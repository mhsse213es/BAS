package detectverify

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Fix round 2 I-2: the alert-source exposure is OPT-IN. With the flag off the
// connector behaves exactly as at origin/main: same _source field list and the
// same RawJSON content (no "source").

var originMainSourceFields = []any{
	"@timestamp", "kibana.alert.uuid", "kibana.alert.rule.name", "kibana.alert.severity",
	"kibana.alert.rule.threat", "kibana.alert.workflow_status", "kibana.alert.original_time",
	"threat", "host.name", "host.hostname",
}

const optInHit = `{"timed_out":false,"_shards":{"total":1,"failed":0},"hits":{"hits":[{"_id":"d1","sort":[1,"x"],"_source":{
	"@timestamp":"2026-10-06T09:00:00Z","kibana.alert.uuid":"u1","kibana.alert.rule.name":"R","kibana.alert.severity":"high",
	"kibana.alert.workflow_status":"open","host.name":"WIN-01","message":"secret log text dbsim-marker",
	"kibana.alert.rule.threat":[{"technique":[{"id":"T1059","subtechnique":[{"id":"T1059.001"}]}]}]}}]}}`

func TestElasticSourceExposureIsOptIn(t *testing.T) {
	// OFF (zero value): byte-for-byte the origin/main request field list and RawJSON.
	c, body, _ := elasticCapture(t, optInHit)
	res, err := c.Verify(context.Background(), elasticReq())
	if err != nil {
		t.Fatal(err)
	}
	if got := (*body)["_source"]; !reflect.DeepEqual(got, originMainSourceFields) {
		t.Fatalf("_source with the flag off differs from origin/main: %v", got)
	}
	if len(res.MatchedAlerts) != 1 {
		t.Fatalf("matched = %d", len(res.MatchedAlerts))
	}
	raw := res.MatchedAlerts[0].RawJSON
	want := `{"alertId":"u1","ruleName":"R","severity":"high","techniques":["T1059","T1059.001"],"timestamp":"2026-10-06T09:00:00Z","workflowStatus":"open"}`
	if string(raw) != want {
		t.Fatalf("RawJSON with the flag off changed:\n got %s\nwant %s", raw, want)
	}
	if strings.Contains(string(raw), "secret log text") || strings.Contains(string(raw), "source") {
		t.Fatal("alert source leaked with the flag off")
	}

	// ON: the extra fields are requested and the bounded source is returned.
	c2, body2, _ := elasticCapture(t, optInHit)
	req := elasticReq()
	req.IncludeAlertSource = true
	res2, err := c2.Verify(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := (*body2)["_source"].([]any)
	want2 := append(append([]any{}, originMainSourceFields...), "message", "event.original", "host.ip", "kibana.alert.reason")
	if !reflect.DeepEqual(fields, want2) {
		t.Fatalf("_source with the flag on: %v", fields)
	}
	var doc struct {
		Source map[string]any `json:"source"`
	}
	if err := json.Unmarshal(res2.MatchedAlerts[0].RawJSON, &doc); err != nil || doc.Source["message"] != "secret log text dbsim-marker" {
		t.Fatalf("source not returned with the flag on: %s", res2.MatchedAlerts[0].RawJSON)
	}
}

func TestElasticSourceTruncationUnchangedWhenOptedIn(t *testing.T) {
	big := strings.Repeat("é", elasticRawSourceMax)
	h := elasticHit{ID: "d", Source: json.RawMessage(`{"@timestamp":"2026-10-06T09:00:00Z","message":"` + big + `"}`)}
	a, err := normalizeElasticHitWith(h, true)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(a.RawJSON, &doc)
	if doc["sourceTruncated"] != true {
		t.Fatalf("truncation flag missing: %.200s", a.RawJSON)
	}
	if s, _ := doc["source"].(string); len(s) > elasticRawSourceMax {
		t.Fatalf("source %d bytes", len(s))
	}
	off, _ := normalizeElasticHit(h)
	if strings.Contains(string(off.RawJSON), "source") {
		t.Fatal("source present with the flag off")
	}
}
