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

// cleanupPreviewLimit caps the candidate set. A preview that finds more is refused, not
// truncated, so a partial list is never presented as the complete one.
const cleanupPreviewLimit = 1000

// RetentionWindow is the platform default retention for test records: a record is eligible for
// cleanup once its event time is at least this old. Customer policy may shorten or lengthen it; this
// is the default the server enforces when no other window is configured.
const RetentionWindow = 30 * 24 * time.Hour

// EventTimeField is the document field that holds a record's event time. Retention is decided from
// it. A record without a valid value in this field is never eligible.
const EventTimeField = "@timestamp"

// CleanupRecord is one candidate with the event time it was judged on. Both are bound into the
// approval, so a change to either between approval and execution changes the set.
type CleanupRecord struct {
	ID        string `json:"id"`
	EventTime string `json:"eventTime"`
}

// CleanupPreview lists the records that would be removed. Nothing is deleted by a preview.
// Status is "previewed" (the list is complete for this run) or "error" (no list is reported).
// Retained lists records the search returned but whose stored marker could not be confirmed
// exactly; they are never candidates. RetentionHeld lists confirmed records that are not yet
// eligible: too young, or with a missing, malformed or future event time.
type CleanupPreview struct {
	RunID         string          `json:"runId"`
	Index         string          `json:"index"`
	Status        string          `json:"status"`
	Reason        string          `json:"reason"`
	Candidates    []string        `json:"candidates"`
	Records       []CleanupRecord `json:"records"`
	Retained      []string        `json:"retained"`
	RetentionHeld []string        `json:"retentionHeld"`
}

// PreviewElasticCleanup previews at the current server time.
func PreviewElasticCleanup(ctx context.Context, client *http.Client, cfg ElasticConfig, index, runID string) CleanupPreview {
	return PreviewElasticCleanupAt(ctx, client, cfg, index, runID, time.Now().UTC())
}

// PreviewElasticCleanupAt finds records in one explicit index that carry the run identifier and the
// marker tag, then confirms each against its stored fields and applies the retention rule at now. Analysed
// text fields make the search loose (a phrase can match related values), so the search only narrows
// the set: a record becomes a candidate only if its stored audspect.test_run equals runID exactly, its
// tags include MarkerTag, and its event time is at least RetentionWindow before now. It writes nothing.
func PreviewElasticCleanupAt(ctx context.Context, client *http.Client, cfg ElasticConfig, index, runID string, now time.Time) CleanupPreview {
	p := CleanupPreview{RunID: runID, Index: index, Candidates: []string{}, Records: []CleanupRecord{}, Retained: []string{}, RetentionHeld: []string{}}
	fail := func(reason string) CleanupPreview {
		p.Status, p.Reason, p.Candidates, p.Records, p.Retained, p.RetentionHeld = "error", reason, nil, nil, nil, nil
		return p
	}
	if !ValidTestRunID(runID) {
		return fail("refused: test run identifier is not in the server-generated form")
	}
	if !ValidIndexName(index) {
		return fail("refused: cleanup must name one explicit index, with no wildcard or list")
	}

	if reason := checkMarkerMapped(ctx, client, cfg, index); reason != "" {
		return fail(reason)
	}

	body, err := json.Marshal(map[string]any{
		"size":    cleanupPreviewLimit + 1,
		"_source": []string{MarkerField, "tags", EventTimeField},
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
		if !confirmsMarker(h.Source, runID) {
			p.Retained = append(p.Retained, h.ID)
			continue
		}
		eventTime, eligible := retentionEligible(h.Source, now)
		if !eligible {
			p.RetentionHeld = append(p.RetentionHeld, h.ID)
			continue
		}
		p.Candidates = append(p.Candidates, h.ID)
		p.Records = append(p.Records, CleanupRecord{ID: h.ID, EventTime: eventTime})
	}
	p.Status = "previewed"
	p.Reason = fmt.Sprintf("%d eligible for cleanup; %d held by retention; %d retained because their stored marker could not be confirmed",
		len(p.Candidates), len(p.RetentionHeld), len(p.Retained))
	return p
}

// retentionEligible reports whether a confirmed record is old enough to clean up at now, and returns
// its stored event time. It is eligible only when the event time is present, is a string in RFC 3339
// form, is not in the future, and is at least RetentionWindow before now. A record exactly at the
// cutoff is eligible. Any other case is held.
func retentionEligible(source map[string]any, now time.Time) (string, bool) {
	raw, ok := source[EventTimeField].(string)
	if !ok || raw == "" {
		return "", false
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return "", false
	}
	if t.After(now) {
		return "", false
	}
	if t.After(now.Add(-RetentionWindow)) {
		return "", false
	}
	return raw, true
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

// checkMarkerMapped confirms the marker fields exist in the index mapping before any search. In
// Elasticsearch a search on an unmapped field returns zero hits without an error. Without this
// check, a mapping mismatch would look exactly like "nothing to clean up". It returns "" when both
// fields are mapped, or the reason the preview must fail.
func checkMarkerMapped(ctx context.Context, client *http.Client, cfg ElasticConfig, index string) string {
	endpoint := strings.TrimRight(cfg.BaseURL, "/") + "/" + url.PathEscape(index) +
		"/_mapping/field/" + MarkerField + ",tags," + url.PathEscape(EventTimeField) + "?allow_no_indices=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "could not build mapping request: " + err.Error()
	}
	switch {
	case cfg.APIKey != "":
		req.Header.Set("Authorization", "ApiKey "+cfg.APIKey)
	case cfg.Username != "":
		req.SetBasicAuth(cfg.Username, cfg.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "connector not reachable: " + err.Error()
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "could not read mapping: " + err.Error()
	}
	if reason := statusReason(resp.StatusCode); reason != "" {
		return reason
	}
	var mapping map[string]struct {
		Mappings map[string]json.RawMessage `json:"mappings"`
	}
	if err := json.Unmarshal(raw, &mapping); err != nil {
		return "mapping response is unreadable: " + err.Error()
	}
	for _, idx := range mapping {
		_, hasRun := idx.Mappings[MarkerField]
		_, hasTags := idx.Mappings["tags"]
		if !hasRun || !hasTags {
			continue
		}
		// Retention compares event times in the search and in the delete query. That is reliable only
		// when the field is a date. As text or keyword the comparison is lexical and can be wrong.
		if !isDateMapped(idx.Mappings[EventTimeField]) {
			return "refused: " + EventTimeField + " is not mapped as a date in this index, so retention cannot be verified"
		}
		return ""
	}
	return "refused: the marker fields are not mapped in this index, so nothing can be verified; not reported as empty"
}

// isDateMapped reports whether a field mapping from the _mapping/field API has a date type.
func isDateMapped(raw json.RawMessage) bool {
	var f struct {
		Mapping map[string]struct {
			Type string `json:"type"`
		} `json:"mapping"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &f) != nil {
		return false
	}
	for _, m := range f.Mapping {
		if m.Type == "date" || m.Type == "date_nanos" {
			return true
		}
	}
	return false
}

// statusReason maps a non-success HTTP status to the reason a preview reports. It returns "" for 200.
func statusReason(status int) string {
	switch status {
	case http.StatusOK:
		return ""
	case http.StatusUnauthorized:
		return "authentication failed (HTTP 401)"
	case http.StatusForbidden:
		return "permission denied reading the index (HTTP 403); cleanup not verified"
	case http.StatusNotFound:
		return "index not found (HTTP 404)"
	}
	return fmt.Sprintf("unexpected response (HTTP %d)", status)
}
