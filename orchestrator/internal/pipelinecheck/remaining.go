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
)

// RemainingResult says which of the approved records are still in the index. It is read-only. Status
// is "checked" when the search completed, or "error" when it did not, in which case no count is given.
type RemainingResult struct {
	Status    string   `json:"status"`
	Reason    string   `json:"reason"`
	Requested int      `json:"requested"`
	Remaining []string `json:"remaining"`
	// Suggested is "deleted", "not_deleted" or "partial", from the count. It is advice to the
	// person reconciling. It is empty when the check did not complete.
	Suggested string `json:"suggested"`
}

// CheckRemainingElastic looks up the given record IDs that still carry the run identifier and the
// marker tag. It writes nothing. An unmapped index is an error, not an empty result.
func CheckRemainingElastic(ctx context.Context, client *http.Client, cfg ElasticConfig, index, runID string, ids []string) RemainingResult {
	res := RemainingResult{Status: "error", Requested: len(ids), Remaining: []string{}}
	if !ValidTestRunID(runID) || !ValidIndexName(index) {
		res.Reason = "refused: run identifier or index is not valid"
		return res
	}
	if len(ids) == 0 {
		res.Status, res.Suggested = "checked", "deleted"
		res.Reason = "no approved records to check"
		return res
	}
	if reason := checkMarkerMapped(ctx, client, cfg, index); reason != "" {
		res.Reason = reason
		return res
	}
	body, err := json.Marshal(map[string]any{
		"size":    len(ids),
		"_source": false,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"ids": map[string]any{"values": ids}},
			map[string]any{"match_phrase": map[string]any{MarkerField: runID}},
			map[string]any{"match_phrase": map[string]any{"tags": MarkerTag}},
		}}},
	})
	if err != nil {
		res.Reason = "could not build query: " + err.Error()
		return res
	}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/" + url.PathEscape(index) + "/_search?allow_no_indices=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		res.Reason = "could not build request: " + err.Error()
		return res
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
		res.Reason = "connector not reachable: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		res.Reason = "could not read response: " + err.Error()
		return res
	}
	if reason := statusReason(resp.StatusCode); reason != "" {
		res.Reason = reason
		return res
	}
	var parsed struct {
		Hits struct {
			Hits []struct {
				ID string `json:"_id"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		res.Reason = "response is not a search result: " + err.Error()
		return res
	}
	approved := make(map[string]bool, len(ids))
	for _, id := range ids {
		approved[id] = true
	}
	for _, h := range parsed.Hits.Hits {
		// Only approved records count. The search filters on the IDs too, but a count must never
		// include a record that was not approved, whatever the search returns.
		if approved[h.ID] {
			res.Remaining = append(res.Remaining, h.ID)
		}
	}
	res.Status = "checked"
	switch n := len(res.Remaining); {
	case n == 0:
		res.Suggested = "deleted"
	case n == len(ids):
		res.Suggested = "not_deleted"
	default:
		res.Suggested = "partial"
	}
	res.Reason = fmt.Sprintf("%d of %d approved records still present", len(res.Remaining), len(ids))
	return res
}
