package detectverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var elasticT0 = time.Date(2026, 10, 6, 9, 0, 0, 0, time.UTC)

func elasticReq() VerifyRequest {
	return VerifyRequest{
		TechniqueID: "T1059.001", HostName: "WIN-01", StepExecutedAt: elasticT0,
		WindowStart: elasticT0.Add(-time.Minute), WindowEnd: elasticT0.Add(10 * time.Minute),
	}
}

func elasticAPIKeyCfg(url string) Config {
	return Config{Provider: "elastic", BaseURL: url, APIToken: "KEY123"}
}

// elasticHitJSON builds a realistic alert hit with the nested threat mapping.
func elasticHitJSON(id string, ts time.Time, techs ...string) map[string]any {
	var threat []any
	for _, t := range techs {
		tech := map[string]any{"id": t, "name": "n"}
		if i := strings.Index(t, "."); i > 0 {
			tech = map[string]any{"id": t[:i], "subtechnique": []any{map[string]any{"id": t}}}
		}
		threat = append(threat, map[string]any{
			"framework": "MITRE ATT&CK", "technique": []any{tech},
		})
	}
	return map[string]any{
		"_id": "doc-" + id,
		"_source": map[string]any{
			"@timestamp":                   ts.Format(time.RFC3339Nano),
			"kibana.alert.uuid":            id,
			"kibana.alert.rule.name":       "Suspicious PowerShell",
			"kibana.alert.severity":        "high",
			"kibana.alert.workflow_status": "open",
			"kibana.alert.rule.threat":     threat,
			"host":                         map[string]any{"name": "WIN-01"},
		},
		"sort": []any{ts.UnixMilli(), id},
	}
}

func elasticResp(hits ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"timed_out": false, "_shards": map[string]any{"total": 1, "failed": 0}, "hits": map[string]any{"hits": hits}})
	return string(b)
}

func TestElasticVerify_RequestShape_APIKey(t *testing.T) {
	var gotPath, gotAuth string
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(elasticResp()))
	}))
	defer srv.Close()

	c := newElasticConnector(elasticAPIKeyCfg(srv.URL))
	res, err := c.Verify(context.Background(), elasticReq())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictNotDetected {
		t.Errorf("verdict = %s, want NotDetected", res.Verdict)
	}
	if gotPath != "/.alerts-security.alerts-*/_search" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "ApiKey KEY123" {
		t.Errorf("auth = %q", gotAuth)
	}
	raw, _ := json.Marshal(body)
	for _, want := range []string{"WIN-01", "host.name", "host.hostname", "@timestamp", "2026-10-06T08:59:00Z", "2026-10-06T09:10:00Z", "kibana.alert.uuid"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("query body missing %q: %s", want, raw)
		}
	}
	if body["size"].(float64) > 500 {
		t.Errorf("size = %v, want <= 500", body["size"])
	}
}

func TestElasticVerify_BasicAuthHeader(t *testing.T) {
	var user, pass string
	var ok bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		w.Write([]byte(elasticResp()))
	}))
	defer srv.Close()
	c := newElasticConnector(Config{Provider: "elastic", BaseURL: srv.URL, ClientID: "elastic", ClientSecret: "p@ss:w"})
	if _, err := c.Verify(context.Background(), elasticReq()); err != nil {
		t.Fatal(err)
	}
	if !ok || user != "elastic" || pass != "p@ss:w" {
		t.Errorf("basic auth = %v %q %q", ok, user, pass)
	}
}

func TestElasticVerify_HostWithQuotesIsData(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		w.Write([]byte(elasticResp()))
	}))
	defer srv.Close()
	req := elasticReq()
	req.HostName = `x"}]}},"size":9999,"y":{"`
	c := newElasticConnector(elasticAPIKeyCfg(srv.URL))
	if _, err := c.Verify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if body["size"].(float64) != 500 || body["y"] != nil {
		t.Errorf("host string escaped into query structure: %s", raw)
	}
}

func TestElasticVerify_Paginates(t *testing.T) {
	var afters []any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		afters = append(afters, body["search_after"])
		switch len(afters) {
		case 1:
			w.Write([]byte(elasticResp(elasticHitJSON("a1", elasticT0), elasticHitJSON("a2", elasticT0.Add(time.Second)))))
		case 2:
			w.Write([]byte(elasticResp(elasticHitJSON("a3", elasticT0.Add(2*time.Second)), elasticHitJSON("a4", elasticT0.Add(3*time.Second), "T1059.001"))))
		default:
			w.Write([]byte(elasticResp(elasticHitJSON("a5", elasticT0.Add(4*time.Second)))))
		}
	}))
	defer srv.Close()
	c := newElasticConnector(elasticAPIKeyCfg(srv.URL))
	c.pageSize = 2
	res, err := c.Verify(context.Background(), elasticReq())
	if err != nil {
		t.Fatal(err)
	}
	if len(afters) != 3 {
		t.Fatalf("requests = %d, want 3", len(afters))
	}
	if afters[0] != nil {
		t.Errorf("first page must not send search_after: %v", afters[0])
	}
	if a, ok := afters[1].([]any); !ok || len(a) != 2 || a[1] != "a2" {
		t.Errorf("page 2 search_after = %v", afters[1])
	}
	if len(res.MatchedAlerts) != 5 {
		t.Errorf("alerts = %d, want 5", len(res.MatchedAlerts))
	}
}

func TestElasticVerify_PageCapIsError(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		w.Write([]byte(elasticResp(elasticHitJSON(fmt.Sprint("u", n), elasticT0))))
	}))
	defer srv.Close()
	c := newElasticConnector(elasticAPIKeyCfg(srv.URL))
	c.pageSize, c.maxPages = 1, 3
	_, err := c.Verify(context.Background(), elasticReq())
	if err == nil || !strings.Contains(err.Error(), "exceeded 3 pages") {
		t.Fatalf("err = %v, want page cap error", err)
	}
	if n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestElasticVerify_TechniqueAndSubtechnique(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(elasticResp(
			elasticHitJSON("late", elasticT0.Add(time.Minute), "T1059.001"),
			elasticHitJSON("other", elasticT0.Add(time.Second), "T1003"),
		)))
	}))
	defer srv.Close()
	c := newElasticConnector(elasticAPIKeyCfg(srv.URL))
	res, err := c.Verify(context.Background(), elasticReq())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictDetected || res.Confidence != ConfidenceHigh {
		t.Errorf("verdict=%s confidence=%s", res.Verdict, res.Confidence)
	}
	if res.DetectionLatency != time.Minute {
		t.Errorf("latency = %v (should come from the technique-tagged alert)", res.DetectionLatency)
	}
	if res.InvestigationURL != "" {
		t.Errorf("InvestigationURL should be empty")
	}
}

func TestNormalizeElasticHit_FlattenedKeys(t *testing.T) {
	h := elasticHit{ID: "d", Source: json.RawMessage(`{"@timestamp":"2026-10-06T09:00:00.123Z",
		"kibana.alert.rule.threat.technique.id":["T1003"],
		"kibana.alert.rule.threat.technique.subtechnique.id":["T1003.001"]}`)}
	a, _ := normalizeElasticHit(h)
	if !containsTechnique(a.Techniques, "T1003") || !containsTechnique(a.Techniques, "T1003.001") {
		t.Errorf("techniques = %v", a.Techniques)
	}
	if a.Timestamp.IsZero() {
		t.Error("timestamp not parsed")
	}
}

func TestElasticVerify_HTTPErrorsAreErrors(t *testing.T) {
	for _, code := range []int{401, 403, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(`{"error":"x"}`))
		}))
		c := newElasticConnector(elasticAPIKeyCfg(srv.URL))
		res, err := c.Verify(context.Background(), elasticReq())
		if err == nil {
			t.Errorf("%d: expected error, got verdict %q", code, res.Verdict)
		} else if code == 401 && !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("401 err = %v", err)
		} else if code == 403 && !strings.Contains(err.Error(), "read privilege") {
			t.Errorf("403 err = %v", err)
		}
		if tErr := c.TestConnection(context.Background()); tErr == nil {
			t.Errorf("%d: TestConnection expected error", code)
		}
		srv.Close()
	}
}

func TestElasticTestConnection_SizeZero(t *testing.T) {
	var body map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(elasticResp()))
	}))
	defer srv.Close()
	if err := newElasticConnector(elasticAPIKeyCfg(srv.URL)).TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if body["size"].(float64) != 0 || path != "/.alerts-security.alerts-*/_search" {
		t.Errorf("path=%q body=%v", path, body)
	}
}

func TestElastic_AuthModeValidation(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	cases := map[string]Config{
		"neither":    {Provider: "elastic", BaseURL: srv.URL},
		"both":       {Provider: "elastic", BaseURL: srv.URL, APIToken: "k", ClientID: "u", ClientSecret: "p"},
		"half basic": {Provider: "elastic", BaseURL: srv.URL, ClientID: "u"},
		"key+user":   {Provider: "elastic", BaseURL: srv.URL, APIToken: "k", ClientID: "u"},
	}
	for name, cfg := range cases {
		c, err := NewConnector(cfg)
		if err != nil {
			t.Fatalf("%s: NewConnector: %v", name, err)
		}
		if _, err := c.Verify(context.Background(), elasticReq()); err == nil {
			t.Errorf("%s: Verify should error", name)
		}
		if err := c.TestConnection(context.Background()); err == nil {
			t.Errorf("%s: TestConnection should error", name)
		}
	}
	if hit {
		t.Error("no request should be sent with invalid auth config")
	}
}

func TestElastic_TLSVerifiedByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(elasticResp()))
	}))
	defer srv.Close()
	if err := newElasticConnector(elasticAPIKeyCfg(srv.URL)).TestConnection(context.Background()); err == nil {
		t.Fatal("self-signed cert must be rejected by default")
	}
	cfg := elasticAPIKeyCfg(srv.URL)
	cfg.InsecureTLS = true
	if err := newElasticConnector(cfg).TestConnection(context.Background()); err != nil {
		t.Fatalf("InsecureTLS opt-out: %v", err)
	}
}
