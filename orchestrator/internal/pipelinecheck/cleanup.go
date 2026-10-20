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

// cleanupPreviewLimit caps the candidate set. A preview that finds more is refused, not
// truncated, so a partial list is never presented as the complete one.
const cleanupPreviewLimit = 1000

// CleanupPreview lists the records that would be removed. Nothing is deleted by a preview.
// Status is "previewed" (the list is complete for this run) or "error" (no list is reported).
// Retained lists records the search returned but whose stored marker could not be confirmed
// exactly; they are never candidates.
type CleanupPreview struct {
	RunID      string   `json:"runId"`
	Index      string   `json:"index"`
	Status     string   `json:"status"`
	Reason     string   `json:"reason"`
	Candidates []string `json:"candidates"`
	Retained   []string `json:"retained"`
}

// PreviewElasticCleanup finds records in one explicit index that carry the run identifier and
// the marker tag, then confirms each one against its stored fields. Analysed text fields make
// the search loose (a phrase can match related values), so the search only narrows the set:
// a record becomes a candidate only if its stored audspect.test_run equals runID exactly and
// its tags include MarkerTag. It writes nothing.
func PreviewElasticCleanup(ctx context.Context, client *http.Client, cfg ElasticConfig, index, runID string) CleanupPreview {
	p := CleanupPreview{RunID: runID, Index: index, Candidates: []string{}, Retained: []string{}}
	fail := func(reason string) CleanupPreview {
		p.Status, p.Reason, p.Candidates, p.Retained = "error", reason, nil, nil
		return p
	}
	if !ValidTestRunID(runID) {
		return fail("refused: test run identifier is not in the server-generated form")
	}
	if !ValidIndexName(index) {
		return fail("refused: cleanup must name one explicit index, with no wildcard or list")
	}

	body, err := json.Marshal(map[string]any{
		"size":    cleanupPreviewLimit + 1,
		"_source": []string{MarkerField, "tags"},
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"match_phrase": map[string]any{MarkerField: runID}},
			map[string]any{"match_phrase": map[string]any{"tags": MarkerTag}},
		}}},
	})
	if err != nil {
		return fail("could not build query: " + err.Error())
	}
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/" + url.PathEscape(index) + "/_search?allow_no_indices=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fail("could not build request: " + err.Error())
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
		return fail("connector not reachable: " + err.Error())
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fail("could not read response: " + err.Error())
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return fail("authentication failed (HTTP 401)")
	case resp.StatusCode == http.StatusForbidden:
		return fail("permission denied reading the index (HTTP 403); cleanup not verified")
	case resp.StatusCode == http.StatusNotFound:
		return fail("index not found (HTTP 404)")
	case resp.StatusCode != http.StatusOK:
		return fail(fmt.Sprintf("unexpected response (HTTP %d)", resp.StatusCode))
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
		return fail("response is not a search result: " + err.Error())
	}
	total, err := elasticTotal(parsed.Hits.Total)
	if err != nil {
		return fail("response total is unreadable: " + err.Error())
	}
	if total > cleanupPreviewLimit {
		return fail(fmt.Sprintf("refused: %d records match, above the preview limit of %d; nothing is listed", total, cleanupPreviewLimit))
	}
	for _, h := range parsed.Hits.Hits {
		if h.ID == "" {
			continue
		}
		if confirmsMarker(h.Source, runID) {
			p.Candidates = append(p.Candidates, h.ID)
		} else {
			p.Retained = append(p.Retained, h.ID)
		}
	}
	p.Status = "previewed"
	switch {
	case len(p.Candidates) == 0 && len(p.Retained) == 0:
		p.Reason = "no records carry this run's identifier and marker tag"
	default:
		p.Reason = fmt.Sprintf("%d confirmed for this run; %d retained because their stored marker could not be confirmed",
			len(p.Candidates), len(p.Retained))
	}
	return p
}

// confirmsMarker reports whether a stored record carries exactly this run's identifier in its
// marker field, and the marker tag. Either form of tags (a string or a list) is accepted.
func confirmsMarker(source map[string]any, runID string) bool {
	audspect, ok := source["audspect"].(map[string]any)
	if !ok {
		return false
	}
	if got, ok := audspect["test_run"].(string); !ok || got != runID {
		return false
	}
	switch tags := source["tags"].(type) {
	case string:
		return tags == MarkerTag
	case []any:
		for _, t := range tags {
			if s, ok := t.(string); ok && s == MarkerTag {
				return true
			}
		}
	}
	return false
}
