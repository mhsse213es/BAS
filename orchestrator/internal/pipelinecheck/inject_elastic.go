package pipelinecheck

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ElasticInjector writes one tagged test record to one explicit Elasticsearch index. It is used only
// through the approval gate. It writes one document, with a generated ID, and refreshes the index so
// the record is searchable at once. It never updates or deletes.
type ElasticInjector struct {
	Client *http.Client
	Cfg    ElasticConfig
}

// Supported is true: Elasticsearch has a write adapter in this build.
func (e ElasticInjector) Supported() bool { return true }

// Inject writes the tagged document. It returns EXECUTED when Elasticsearch reports the document
// created, and an error for any other response. An error means the state is unknown and the caller
// must record it as failed, not retry.
func (e ElasticInjector) Inject(ctx context.Context, req InjectionRequest) (InjectionOutcome, error) {
	if !ValidIndexName(req.Index) {
		return InjectionOutcome{}, fmt.Errorf("refused: injection must name one explicit index")
	}
	if !ValidTestRunID(req.RunID) {
		return InjectionOutcome{}, fmt.Errorf("refused: test run identifier is not in the server-generated form")
	}
	docID, err := newInjectionDocID(req.RunID)
	if err != nil {
		return InjectionOutcome{}, err
	}
	body, err := json.Marshal(req.Document)
	if err != nil {
		return InjectionOutcome{}, fmt.Errorf("could not encode the document: %w", err)
	}
	endpoint := strings.TrimRight(e.Cfg.BaseURL, "/") + "/" + url.PathEscape(req.Index) + "/_doc/" +
		url.PathEscape(docID) + "?refresh=true&op_type=create"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return InjectionOutcome{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	switch {
	case e.Cfg.APIKey != "":
		httpReq.Header.Set("Authorization", "ApiKey "+e.Cfg.APIKey)
	case e.Cfg.Username != "":
		httpReq.SetBasicAuth(e.Cfg.Username, e.Cfg.Password)
	}
	resp, err := e.Client.Do(httpReq)
	if err != nil {
		return InjectionOutcome{}, fmt.Errorf("connector not reachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return InjectionOutcome{}, fmt.Errorf("elasticsearch refused the write (HTTP %d)", resp.StatusCode)
	}
	var out struct {
		Result string `json:"result"`
		ID     string `json:"_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Result != "created" {
		return InjectionOutcome{}, fmt.Errorf("elasticsearch did not confirm creation")
	}
	return InjectionOutcome{Status: "EXECUTED", Reason: fmt.Sprintf("record %s written to %s", out.ID, req.Index)}, nil
}

// newInjectionDocID returns a document ID that carries the run identifier and a random suffix. The
// suffix makes repeated writes distinct, and op_type=create refuses to overwrite an existing document.
func newInjectionDocID(runID string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return runID + "-" + hex.EncodeToString(b[:]), nil
}
