// Package sentinelone is a real SentinelOne Singularity Management
// Console API client. Unlike internal/vendors/defender, SentinelOne
// publishes no public, authoritative API reference (no equivalent of
// learn.microsoft.com exists) -- its only real schema reference lives
// inside each customer's own console (Help -> API Hub / Swagger),
// which is not reachable from this environment (no live SentinelOne
// tenant exists here). Every detail below is corroborated across
// multiple independent third-party sources checked 2026-10-16
// (Stitchflow's SentinelOne API guide, docs.praetorian.com's
// SentinelOne article, LimaCharlie's SentinelOne extension docs,
// D3 Security's integration docs, ThreatQ's SentinelOne action docs,
// the archived Celerium/SentinelOne-PowerShellWrapper and
// PS-SentinelOne PowerShell modules) rather than against SentinelOne's
// own documentation, and is disclosed as such everywhere it matters --
// see each file's own doc comments for exactly which facts are
// well-corroborated versus best-effort.
package sentinelone

import (
	"net/http"
	"sync"
	"time"
)

// Config holds the connection settings for one SentinelOne tenant.
// Unlike Defender/CrowdStrike, SentinelOne authenticates with a single,
// static, console-generated API token (Authorization: ApiToken
// <token>) -- there is no OAuth client-credentials flow and therefore
// no token expiry/refresh logic needed here at all.
type Config struct {
	// BaseURL is the tenant's own management console URL (e.g.
	// "https://your-company.sentinelone.net", possibly with a regional
	// prefix such as usea1-/eu1-/apse1-) -- there is no global
	// endpoint. The "/web/api/v2.1" API path is appended per call.
	BaseURL  string
	APIToken string
}

type deviceCacheEntry struct {
	deviceID  string
	expiresAt time.Time
}

// deviceCacheTTL matches internal/vendors/defender's own cache TTL
// philosophy.
const deviceCacheTTL = 15 * time.Minute

// Client is a SentinelOne Management Console API client. BaseURL is
// exported so tests can point it at an httptest.Server.
type Client struct {
	BaseURL    string
	apiToken   string
	httpClient *http.Client

	deviceCacheMu sync.Mutex
	deviceCache   map[string]deviceCacheEntry
}

func New(cfg Config) *Client {
	return &Client{
		BaseURL:     cfg.BaseURL,
		apiToken:    cfg.APIToken,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
		deviceCache: make(map[string]deviceCacheEntry),
	}
}

func (c *Client) authHeader() string {
	return "ApiToken " + c.apiToken
}
