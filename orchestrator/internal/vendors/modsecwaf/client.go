// Package modsecwaf is a real (non-fixture) HTTP client for a live,
// self-hosted ModSecurity + OWASP CRS WAF -- the lab target defined at
// lab/wafmodsec/docker-compose.yml. It performs genuine network I/O: it
// builds a real *http.Request from a wafcatalog.RequestTemplate and
// sends it over the wire, returning the WAF's real raw response.
//
// It knows nothing about wafval; internal/wafmodsec is the separate
// bridge that turns RawResponse into wafval.Observation/CollectionResult
// (mirrors internal/vendors/defender + internal/avdefender's split).
package modsecwaf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/audspect/bas/internal/wafcatalog"
)

// Config holds the connection settings for one live WAF lab target.
type Config struct {
	// BaseURL is the WAF's own listening address, e.g. "http://localhost:8888"
	// (the host port lab/wafmodsec/docker-compose.yml publishes) -- never the
	// origin directly; every request must pass through the WAF to mean
	// anything.
	BaseURL string
	Timeout time.Duration // defaults to 10s if zero
}

// Client sends real HTTP requests to one live WAF lab target.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient builds a Client. It performs no I/O itself.
func NewClient(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &Client{cfg: cfg, http: &http.Client{Timeout: timeout}}
}

// RawResponse is the live WAF's real, unmodified response to one request.
type RawResponse struct {
	StatusCode int
	Body       []byte
}

// BuildRequest turns one wafcatalog.RequestTemplate into a real *http.Request
// against baseURL. It implements exactly the two PayloadLocation forms this
// package's live thin slice uses today -- "" (no payload; method+path alone,
// e.g. HTTP verb tampering) and "query:<param>" (a single query-string
// parameter) -- and returns an error for any other form rather than silently
// misinterpreting it. Extending this to header:/body: forms is a deliberate
// follow-up, not an oversight: see lab/wafmodsec/docker-compose.yml's own doc
// comment on this version's scope.
func BuildRequest(baseURL string, tmpl wafcatalog.RequestTemplate) (*http.Request, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + tmpl.Path)
	if err != nil {
		return nil, fmt.Errorf("modsecwaf: parsing %q + %q: %w", baseURL, tmpl.Path, err)
	}
	switch {
	case tmpl.PayloadLocation == "":
		// No payload to place; method+path alone is the whole request.
	case strings.HasPrefix(tmpl.PayloadLocation, "query:"):
		param := strings.TrimPrefix(tmpl.PayloadLocation, "query:")
		q := u.Query()
		q.Set(param, tmpl.Payload)
		u.RawQuery = q.Encode()
	default:
		return nil, fmt.Errorf("modsecwaf: unsupported PayloadLocation %q (only \"\" and \"query:<param>\" are implemented)", tmpl.PayloadLocation)
	}
	return http.NewRequest(tmpl.Method, u.String(), nil)
}

// Send builds a real request from tmpl and executes it against the live WAF,
// returning its genuine raw response. The only error this returns is a real
// transport/build failure (DNS, connection refused, timeout, unsupported
// PayloadLocation) -- never a classification of the response itself, which is
// internal/wafmodsec's job.
func (c *Client) Send(ctx context.Context, tmpl wafcatalog.RequestTemplate) (RawResponse, error) {
	req, err := BuildRequest(c.cfg.BaseURL, tmpl)
	if err != nil {
		return RawResponse{}, err
	}
	req = req.WithContext(ctx)
	resp, err := c.http.Do(req)
	if err != nil {
		return RawResponse{}, fmt.Errorf("modsecwaf: sending %s %s: %w", tmpl.Method, tmpl.Path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return RawResponse{}, fmt.Errorf("modsecwaf: reading response body for %s %s: %w", tmpl.Method, tmpl.Path, err)
	}
	return RawResponse{StatusCode: resp.StatusCode, Body: body}, nil
}
