package detectverify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func elasticCapture(t *testing.T, resp string) (*elasticConnector, *map[string]any, *string) {
	t.Helper()
	body := map[string]any{}
	rawQuery := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawQuery = r.URL.RawQuery
		body = map[string]any{}
		json.NewDecoder(r.Body).Decode(&body)
		w.Write([]byte(resp))
	}))
	t.Cleanup(srv.Close)
	return newElasticConnector(elasticAPIKeyCfg(srv.URL)), &body, &rawQuery
}

func TestElastic_StrictSearchParams(t *testing.T) {
	c, _, q := elasticCapture(t, elasticResp())
	if _, err := c.Verify(context.Background(), elasticReq()); err != nil {
		t.Fatal(err)
	}
	vals, err := url.ParseQuery(*q)
	if err != nil {
		t.Fatal(err)
	}
	if vals.Get("allow_partial_search_results") != "false" || vals.Get("allow_no_indices") != "false" || vals.Get("expand_wildcards") != "open,hidden" {
		t.Errorf("query params = %v", vals)
	}
}

func TestElastic_PartialOrEmpty200IsError(t *testing.T) {
	cases := map[string]string{
		"shards failed": `{"timed_out":false,"_shards":{"total":3,"failed":1},"hits":{"hits":[]}}`,
		"timed out":     `{"timed_out":true,"_shards":{"total":3,"failed":0},"hits":{"hits":[]}}`,
		"zero shards":   `{"timed_out":false,"_shards":{"total":0,"failed":0},"hits":{"hits":[]}}`,
		"malformed":     `{"hits":`,
	}
	for name, resp := range cases {
		c, _, _ := elasticCapture(t, resp)
		if res, err := c.Verify(context.Background(), elasticReq()); err == nil {
			t.Errorf("%s: Verify returned verdict %q, want error", name, res.Verdict)
		}
		if err := c.TestConnection(context.Background()); err == nil {
			t.Errorf("%s: TestConnection should error", name)
		}
	}
	c, _, _ := elasticCapture(t, cases["zero shards"])
	err := c.TestConnection(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no Elastic Security alerts index visible") {
		t.Errorf("zero-shard message = %v", err)
	}
}

func elasticFilters(body map[string]any) []any {
	return body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
}

func elasticHostShould(body map[string]any) []any {
	return elasticFilters(body)[1].(map[string]any)["bool"].(map[string]any)["should"].([]any)
}

func TestElastic_HostClauses(t *testing.T) {
	c, body, _ := elasticCapture(t, elasticResp())
	req := elasticReq()
	req.HostName, req.HostIP = "WIN-01", "10.1.2.3"
	if _, err := c.Verify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	should := elasticHostShould(*body)
	if len(should) != 4 {
		t.Fatalf("should clauses = %d, want 4: %v", len(should), should)
	}
	term := should[0].(map[string]any)["term"].(map[string]any)["host.name"].(map[string]any)
	if term["value"] != "WIN-01" || term["case_insensitive"] != true {
		t.Errorf("host.name term = %v", term)
	}
	hn := should[1].(map[string]any)["term"].(map[string]any)["host.hostname"].(map[string]any)
	if hn["value"] != "WIN-01" || hn["case_insensitive"] != true {
		t.Errorf("host.hostname term = %v", hn)
	}
	pre := should[2].(map[string]any)["prefix"].(map[string]any)["host.name"].(map[string]any)
	if pre["value"] != "WIN-01." || pre["case_insensitive"] != true {
		t.Errorf("prefix = %v", pre)
	}
	if should[3].(map[string]any)["term"].(map[string]any)["host.ip"] != "10.1.2.3" {
		t.Errorf("ip clause = %v", should[3])
	}
}

func TestElastic_InvalidIPOmitted(t *testing.T) {
	c, body, _ := elasticCapture(t, elasticResp())
	req := elasticReq()
	req.HostIP = "not-an-ip"
	if _, err := c.Verify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if n := len(elasticHostShould(*body)); n != 3 {
		t.Errorf("should clauses = %d, want 3 (no ip)", n)
	}
}

func TestElastic_IPOnlyHostIsAllowed(t *testing.T) {
	c, body, _ := elasticCapture(t, elasticResp())
	req := elasticReq()
	req.HostName, req.HostIP = "", "10.1.2.3"
	if _, err := c.Verify(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if n := len(elasticHostShould(*body)); n != 1 {
		t.Errorf("should clauses = %d, want only ip", n)
	}
}

func TestElastic_NoHostIdentityIsError(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	req := elasticReq()
	req.HostName, req.HostIP = "  ", ""
	_, err := newElasticConnector(elasticAPIKeyCfg(srv.URL)).Verify(context.Background(), req)
	if err == nil || !strings.Contains(err.Error(), "no host identity") || hit {
		t.Errorf("err=%v hit=%v", err, hit)
	}
}

func TestElastic_WindowCoversEventTime(t *testing.T) {
	c, body, _ := elasticCapture(t, elasticResp())
	if _, err := c.Verify(context.Background(), elasticReq()); err != nil {
		t.Fatal(err)
	}
	win := elasticFilters(*body)[0].(map[string]any)["bool"].(map[string]any)
	if win["minimum_should_match"].(float64) != 1 {
		t.Errorf("minimum_should_match = %v", win["minimum_should_match"])
	}
	fields := map[string]bool{}
	for _, cl := range win["should"].([]any) {
		for f, v := range cl.(map[string]any)["range"].(map[string]any) {
			fields[f] = true
			if v.(map[string]any)["format"] != "strict_date_optional_time" {
				t.Errorf("%s format = %v", f, v)
			}
		}
	}
	if !fields["@timestamp"] || !fields["kibana.alert.original_time"] {
		t.Errorf("range fields = %v", fields)
	}
	if (*body)["sort"].([]any)[0].(map[string]any)["@timestamp"] != "asc" {
		t.Errorf("sort = %v", (*body)["sort"])
	}
}

func TestNormalizeElasticHit_ECSThreatAndTimestampFallback(t *testing.T) {
	a, err := normalizeElasticHit(elasticHit{ID: "d", Source: json.RawMessage(`{
		"kibana.alert.original_time":"2026-10-06T09:00:05Z",
		"threat":{"technique":{"id":["T1003"],"subtechnique":{"id":["T1003.001"]}}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !containsTechnique(a.Techniques, "T1003") || !containsTechnique(a.Techniques, "T1003.001") {
		t.Errorf("techniques = %v", a.Techniques)
	}
	if a.Timestamp.IsZero() {
		t.Error("expected original_time fallback")
	}
}

func TestElasticVerify_MalformedHitIsError(t *testing.T) {
	c, _, _ := elasticCapture(t, `{"timed_out":false,"_shards":{"total":1,"failed":0},"hits":{"hits":[{"_id":"x","_source":"oops","sort":[1,"x"]}]}}`)
	if _, err := c.Verify(context.Background(), elasticReq()); err == nil {
		t.Error("malformed hit should be an error")
	}
}

func TestElasticVerify_ZeroTimestampSkipsLatency(t *testing.T) {
	c, _, _ := elasticCapture(t, `{"timed_out":false,"_shards":{"total":1,"failed":0},"hits":{"hits":[{"_id":"x","_source":{"kibana.alert.rule.threat":[{"technique":[{"id":"T1059","subtechnique":[{"id":"T1059.001"}]}]}]},"sort":[1,"x"]}]}}`)
	res, err := c.Verify(context.Background(), elasticReq())
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != VerdictDetected || res.DetectionLatency != 0 {
		t.Errorf("verdict=%s latency=%v", res.Verdict, res.DetectionLatency)
	}
}

func TestElastic_WhitespaceCredsCountAsEmpty(t *testing.T) {
	if err := ValidateElasticAuth(Config{APIToken: "  ", ClientID: " ", ClientSecret: ""}); err == nil {
		t.Error("whitespace-only creds must count as unset")
	}
	if err := ValidateElasticAuth(Config{APIToken: "k", ClientID: " "}); err != nil {
		t.Errorf("whitespace username must not conflict with an API key: %v", err)
	}
}

func TestElastic_ErrorBodyTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(strings.Repeat("x", 100000)))
	}))
	defer srv.Close()
	err := newElasticConnector(elasticAPIKeyCfg(srv.URL)).TestConnection(context.Background())
	if err == nil || len(err.Error()) > 5000 {
		t.Errorf("error len = %d", len(fmt.Sprint(err)))
	}
}

func TestElastic_CredentialsSentTrimmed(t *testing.T) {
	var auth, user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		user, pass, _ = r.BasicAuth()
		w.Write([]byte(elasticResp()))
	}))
	defer srv.Close()
	if err := newElasticConnector(Config{BaseURL: srv.URL, APIToken: "  k 	"}).TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if auth != "ApiKey k" {
		t.Errorf("Authorization = %q", auth)
	}
	if err := newElasticConnector(Config{BaseURL: srv.URL, ClientID: " u ", ClientSecret: " p "}).TestConnection(context.Background()); err != nil {
		t.Fatal(err)
	}
	if user != "u" || pass != "p" {
		t.Errorf("basic = %q/%q", user, pass)
	}
}
