package pipelinecheck

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ElasticConfig is the connection for a read-only ingestion check. Use either Username and
// Password, or APIKey. Credentials are sent in a header and never placed in a URL or in
// the evidence.
type ElasticConfig struct {
	BaseURL  string
	Username string
	Password string
	APIKey   string
}

// IngestionQuery names the stable identifier to look for and the window to look in.
type IngestionQuery struct {
	Index      string    // index pattern, for example "logs-*"
	Field      string    // field that carries the identifier, for example "event.id"
	Identifier string    // the value to match
	From       time.Time // window start, inclusive
	To         time.Time // window end, inclusive
	PageSize   int       // matches to return for evidence; 0 means 10
}

const maxElasticResponse = 1 << 20

// CheckElasticIngestion runs a read-only search and reports the ingestion stage. It does
// not claim normalisation or correlation: those stages are reported NOT_TESTED by the
// caller, because a raw match does not show they ran.
func CheckElasticIngestion(ctx context.Context, client *http.Client, cfg ElasticConfig, q IngestionQuery, now func() time.Time) StageReport {
	ev := Evidence{Connector: "elastic", Target: q.Index, Field: q.Field, Identifier: q.Identifier, WindowFrom: q.From, WindowTo: q.To}
	report := func(st StageStatus, reason string) StageReport {
		return StageReport{Stage: StageIngestion, Status: st, Reason: reason, Evidence: ev, CheckedAt: now()}
	}
	if q.Index == "" || q.Field == "" || q.Identifier == "" || q.From.IsZero() || q.To.IsZero() || !q.To.After(q.From) {
		return report(StatusError, "invalid ingestion query: index, field, identifier and a valid window are all required")
	}
	size := q.PageSize
	if size <= 0 {
		size = 10
	}

	body, err := json.Marshal(map[string]any{
		"size":    size,
		"_source": []string{"@timestamp"},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"match_phrase": map[string]any{q.Field: q.Identifier}},
			map[string]any{"range": map[string]any{"@timestamp": map[string]any{
				"gte": q.From.UTC().Format(time.RFC3339), "lte": q.To.UTC().Format(time.RFC3339),
			}}},
		}}},
	})
	if err != nil {
		return report(StatusError, "could not build query: "+err.Error())
	}

	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/" + url.PathEscape(q.Index) + "/_search?allow_no_indices=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return report(StatusError, "could not build request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case cfg.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+cfg.APIKey)
	case cfg.Username != "":
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		ev.ErrorDetail = "transport error: " + err.Error()
		return report(StatusError, "query failed before a response was received")
	}
	defer resp.Body.Close()
	ev.HTTPStatus = resp.StatusCode
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxElasticResponse))
	if err != nil {
		ev.ErrorDetail = "reading response: " + err.Error()
		return report(StatusError, "response could not be read")
	}
	ev.ResponseBytes = len(raw)

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return report(StatusError, "authentication failed (401): check the connector credentials")
	case resp.StatusCode == http.StatusForbidden:
		return report(StatusError, "permission denied (403): the connector user needs read privilege on the index pattern")
	case resp.StatusCode == http.StatusNotFound:
		return report(StatusError, "no index matches the pattern: "+q.Index)
	case resp.StatusCode != http.StatusOK:
		ev.ErrorDetail = fmt.Sprintf("unexpected status %d", resp.StatusCode)
		return report(StatusError, fmt.Sprintf("query returned status %d", resp.StatusCode))
	}

	var parsed struct {
		Hits struct {
			Total json.RawMessage `json:"total"`
			Hits  []struct {
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		ev.ErrorDetail = "decoding response: " + err.Error()
		return report(StatusError, "response was not a valid search result")
	}
	total, err := elasticTotal(parsed.Hits.Total)
	if err != nil {
		ev.ErrorDetail = err.Error()
		return report(StatusError, "response did not report a match total")
	}
	ev.MatchCount = total
	for _, h := range parsed.Hits.Hits {
		ev.EventIDs = append(ev.EventIDs, h.ID)
		if ts, ok := h.Source["@timestamp"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ev.SourceTimes = append(ev.SourceTimes, t)
			}
		}
	}

	if total == 0 {
		return report(StatusInconclusive, "zero matching events in the window; ingestion delay and non-delivery are not distinguished")
	}
	return report(StatusVerified, fmt.Sprintf("%d matching event(s) found in the window; this shows raw ingestion only", total))
}

// elasticTotal reads hits.total, which is an object in Elasticsearch 7 and later and a
// bare integer in older responses. A missing total is an error, never a zero.
func elasticTotal(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 {
		return 0, fmt.Errorf("hits.total is missing")
	}
	var obj struct {
		Value int64 `json:"value"`
	}
	// relation "gte" means the value is a lower bound; any value above zero still proves a match.
	if err := json.Unmarshal(raw, &obj); err == nil && len(raw) > 0 && raw[0] == '{' {
		return obj.Value, nil
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, fmt.Errorf("hits.total is not a number: %v", err)
	}
	return n, nil
}
