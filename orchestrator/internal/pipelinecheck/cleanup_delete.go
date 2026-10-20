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

// CleanupDeleteResult reports a deletion. Status is "deleted" (every requested record was removed),
// "partial" (some were not removed; the reason gives the counts), or "error" (the result could not be
// verified).
type CleanupDeleteResult struct {
	Requested int    `json:"requested"`
	Deleted   int64  `json:"deleted"`
	Conflicts int64  `json:"conflicts"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
}

// DeleteElasticCandidates deletes only the given record IDs, and only where the stored record still
// carries this run's identifier and the marker tag. It never deletes by time window or wildcard.
// conflicts=abort stops the delete on a version conflict rather than skipping silently. The marker
// mapping is checked first, as the preview does.
func DeleteElasticCandidates(ctx context.Context, client *http.Client, cfg ElasticConfig, index, runID string, ids []string) (CleanupDeleteResult, error) {
	res := CleanupDeleteResult{Requested: len(ids)}
	if !ValidTestRunID(runID) {
		return res, fmt.Errorf("refused: test run identifier is not in the server-generated form")
	}
	if !ValidIndexName(index) {
		return res, fmt.Errorf("refused: cleanup must name one explicit index, with no wildcard or list")
	}
	if len(ids) == 0 {
		res.Status, res.Reason = "deleted", "nothing to delete"
		return res, nil
	}
	if len(ids) > cleanupPreviewLimit {
		return res, fmt.Errorf("refused: %d records requested, above the limit of %d", len(ids), cleanupPreviewLimit)
	}
	if reason := checkMarkerMapped(ctx, client, cfg, index); reason != "" {
		return res, fmt.Errorf("%s", reason)
	}
	body, err := json.Marshal(map[string]any{
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"ids": map[string]any{"values": ids}},
			map[string]any{"match_phrase": map[string]any{MarkerField: runID}},
			map[string]any{"match_phrase": map[string]any{"tags": MarkerTag}},
		}}},
	})
	if err != nil {
		return res, err
	}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/" + url.PathEscape(index) +
		"/_delete_by_query?conflicts=abort&refresh=true&wait_for_completion=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return res, err
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
		res.Status, res.Reason = "error", "connector not reachable: "+err.Error()
		return res, nil
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		res.Status, res.Reason = "error", "could not read response: "+err.Error()
		return res, nil
	}
	if reason := statusReason(resp.StatusCode); reason != "" {
		res.Status, res.Reason = "error", reason
		return res, nil
	}
	var out struct {
		Deleted          int64             `json:"deleted"`
		VersionConflicts int64             `json:"version_conflicts"`
		Failures         []json.RawMessage `json:"failures"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		res.Status, res.Reason = "error", "delete response is unreadable: "+err.Error()
		return res, nil
	}
	res.Deleted, res.Conflicts = out.Deleted, out.VersionConflicts
	switch {
	case len(out.Failures) > 0:
		res.Status, res.Reason = "error", fmt.Sprintf("%d records failed to delete", len(out.Failures))
	case res.Deleted == int64(res.Requested) && res.Conflicts == 0:
		res.Status, res.Reason = "deleted", fmt.Sprintf("%d of %d records deleted", res.Deleted, res.Requested)
	default:
		res.Status = "partial"
		res.Reason = fmt.Sprintf("%d of %d records deleted; %d version conflicts; the rest were not removed",
			res.Deleted, res.Requested, res.Conflicts)
	}
	return res, nil
}
