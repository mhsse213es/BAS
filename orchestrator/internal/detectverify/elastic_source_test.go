package detectverify

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// Amendment A1 (dbsim): the Elastic connector exposes the raw alert source
// under a `source` key of RawJSON so a correlator can see an in-band marker.

func a1Hit(msg string) map[string]any {
	h := elasticHitJSON("u1", elasticT0, "T1059.001")
	src := h["_source"].(map[string]any)
	src["message"] = msg
	src["event.original"] = "orig " + msg
	src["host"] = map[string]any{"name": "WIN-01", "ip": []any{"10.0.0.5"}}
	src["kibana.alert.reason"] = "reason"
	return h
}

// a1Req is the request the dbsim correlator sends: it opts in to the alert source.
func a1Req() VerifyRequest {
	r := elasticReq()
	r.IncludeAlertSource = true
	return r
}

func a1Verify(t *testing.T, resp string) VerifyResult {
	t.Helper()
	c, _, _ := elasticCapture(t, resp)
	res, err := c.Verify(context.Background(), a1Req())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestElasticA1_SourceKeyExposesMarkerAndKeepsExistingKeys(t *testing.T) {
	const marker = "bas-dbsim:0123456789abcdef01234567"
	res := a1Verify(t, elasticResp(a1Hit("SELECT 1 /* "+marker+" */")))
	if len(res.MatchedAlerts) != 1 {
		t.Fatalf("alerts %d", len(res.MatchedAlerts))
	}
	raw := res.MatchedAlerts[0].RawJSON
	if !strings.Contains(string(raw), marker) {
		t.Fatalf("marker not visible in RawJSON: %s", raw)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"alertId", "ruleName", "timestamp", "severity", "techniques", "workflowStatus", "source"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, raw)
		}
	}
	if _, ok := m["sourceTruncated"]; ok {
		t.Error("sourceTruncated must be absent when nothing was cut")
	}
	var src map[string]any
	if err := json.Unmarshal(m["source"], &src); err != nil {
		t.Fatalf("source is not an object: %s", m["source"])
	}
	if src["message"] == nil || src["event.original"] == nil || src["host"] == nil || src["kibana.alert.reason"] == nil {
		t.Errorf("source lacks expected fields: %v", src)
	}
}

func TestElasticA1_RequestSourceWhitelistWidened(t *testing.T) {
	c, body, _ := elasticCapture(t, elasticResp())
	if _, err := c.Verify(context.Background(), a1Req()); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal((*body)["_source"])
	for _, want := range []string{"message", "event.original", "host.ip", "host.name", "kibana.alert.reason",
		"@timestamp", "kibana.alert.uuid", "kibana.alert.rule.name", "kibana.alert.severity", "kibana.alert.rule.threat", "threat"} {
		if !strings.Contains(string(b), `"`+want+`"`) {
			t.Errorf("_source whitelist missing %q: %s", want, b)
		}
	}
}

func TestElasticA1_OversizedSourceIsCappedOnRuneBoundaryAndFlagged(t *testing.T) {
	// multibyte runes so a naive byte cut would split one.
	big := strings.Repeat("é", elasticRawSourceMax) // 2 bytes each, well over the cap
	res := a1Verify(t, elasticResp(a1Hit(big)))
	raw := res.MatchedAlerts[0].RawJSON
	var m struct {
		Source          json.RawMessage `json:"source"`
		SourceTruncated bool            `json:"sourceTruncated"`
		AlertID         string          `json:"alertId"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("RawJSON must stay valid JSON: %v", err)
	}
	if !m.SourceTruncated || m.AlertID != "u1" {
		t.Fatalf("truncated=%v id=%q", m.SourceTruncated, m.AlertID)
	}
	var s string
	if err := json.Unmarshal(m.Source, &s); err != nil {
		t.Fatalf("truncated source must be a string: %v", err)
	}
	if len(s) > elasticRawSourceMax || !utf8.ValidString(s) {
		t.Fatalf("len=%d valid=%v", len(s), utf8.ValidString(s))
	}
	if len(raw) > elasticRawSourceMax+2048 {
		t.Fatalf("RawJSON not bounded: %d", len(raw))
	}
}

func TestElasticA1_MarkerBeyondCutIsNotVisible(t *testing.T) {
	const marker = "bas-dbsim:0123456789abcdef01234567"
	res := a1Verify(t, elasticResp(a1Hit(strings.Repeat("x", elasticRawSourceMax)+marker)))
	raw := res.MatchedAlerts[0].RawJSON
	if strings.Contains(string(raw), marker) {
		t.Fatal("marker beyond the cap leaked")
	}
	if !strings.Contains(string(raw), `"sourceTruncated":true`) {
		t.Fatalf("truncation not flagged: %.200s", raw)
	}
}

func TestElasticA1_UTF8CutHelper(t *testing.T) {
	s := "aé" // 3 bytes
	if got := cutUTF8(s, 2); got != "a" {
		t.Fatalf("got %q", got)
	}
	if got := cutUTF8(s, 3); got != s {
		t.Fatalf("got %q", got)
	}
}
