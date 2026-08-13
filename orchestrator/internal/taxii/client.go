package taxii

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const mediaType = "application/taxii+json;version=2.1"

// Client speaks the TAXII 2.1 Collections API (discovery -> API root ->
// collections -> paginated objects). Skips TLS verification for self-signed
// certs, matching MISPClient's existing precedent for on-prem/air-gapped
// deployments.
type Client struct {
	cfg        ConnectorConfig
	httpClient *http.Client
}

func NewClient(cfg ConnectorConfig) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
	}
}

type Discovery struct {
	Title          string   `json:"title"`
	DefaultAPIRoot string   `json:"default"`
	APIRoots       []string `json:"api_roots"`
}

type Collection struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type collectionsResponse struct {
	Collections []Collection `json:"collections"`
}

// ObjectsPage is one page of a TAXII 2.1 "objects" envelope response:
// {"more": bool, "next": "opaque-cursor", "objects": [...]}.
type ObjectsPage struct {
	Objects []json.RawMessage
	More    bool
	Next    string
}

type objectsEnvelope struct {
	More    bool              `json:"more"`
	Next    string            `json:"next"`
	Objects []json.RawMessage `json:"objects"`
}

// ErrAuthFailed is returned for HTTP 401/403 responses.
type ErrAuthFailed struct{ StatusCode int }

func (e *ErrAuthFailed) Error() string {
	return fmt.Sprintf("taxii auth failed (HTTP %d)", e.StatusCode)
}

func (c *Client) do(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", mediaType)
	if c.cfg.AuthType == "basic" {
		auth := base64.StdEncoding.EncodeToString([]byte(c.cfg.Username + ":" + c.cfg.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		resp.Body.Close()
		return nil, &ErrAuthFailed{StatusCode: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("taxii server returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return resp, nil
}

// Discover fetches the server's discovery document (GET {server_url}/taxii2/).
func (c *Client) Discover(ctx context.Context) (Discovery, error) {
	resp, err := c.do(ctx, strings.TrimRight(c.cfg.ServerURL, "/")+"/taxii2/")
	if err != nil {
		return Discovery{}, err
	}
	defer resp.Body.Close()
	var d Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return Discovery{}, fmt.Errorf("decode discovery response: %w", err)
	}
	return d, nil
}

// ListCollections fetches the collections available under an API root.
func (c *Client) ListCollections(ctx context.Context, apiRoot string) ([]Collection, error) {
	resp, err := c.do(ctx, strings.TrimRight(apiRoot, "/")+"/collections/")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cr collectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decode collections response: %w", err)
	}
	return cr.Collections, nil
}

// PollObjects fetches one page of a collection's objects. addedAfter
// (nil-able) does incremental polling; next carries the previous page's
// pagination cursor ("" for the first page).
func (c *Client) PollObjects(ctx context.Context, apiRoot, collectionID string, addedAfter *time.Time, next string) (ObjectsPage, error) {
	u := strings.TrimRight(apiRoot, "/") + "/collections/" + collectionID + "/objects/"
	var params []string
	if addedAfter != nil {
		params = append(params, "added_after="+addedAfter.UTC().Format(time.RFC3339))
	}
	if next != "" {
		params = append(params, "next="+next)
	}
	if len(params) > 0 {
		u += "?" + strings.Join(params, "&")
	}
	resp, err := c.do(ctx, u)
	if err != nil {
		return ObjectsPage{}, err
	}
	defer resp.Body.Close()
	var env objectsEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return ObjectsPage{}, fmt.Errorf("decode objects response: %w", err)
	}
	return ObjectsPage{Objects: env.Objects, More: env.More, Next: env.Next}, nil
}
