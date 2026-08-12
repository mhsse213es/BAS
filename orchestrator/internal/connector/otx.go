package connector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// OTXSource performs a periodic sync against AlienVault OTX, reporting
// pulse-mention activity evidence -- never curated actor attribution. Each
// subscribed pulse's adversary field is matched against
// attackdata.GroupTechniqueIndex()'s MITRE-authoritative group names; on a
// match, the pulse contributes to that actor's ActivitySignal (a count and
// an observed date range), never a ThreatActor. See
// docs/superpowers/specs/2026-08-12-otx-activity-signal-design.md, which
// supersedes docs/superpowers/specs/2026-07-22-otx-technique-mapping-design.md
// for everything concerning what Fetch (now FetchActivity) returns.
//
// This is a distinct client from internal/ioc/otx.go's otxProvider, which
// performs synchronous on-demand single-indicator lookups (IP/domain/hash/
// CVE) for LookupIOC -- a different concern from this package's periodic
// sync, matching this codebase's existing package split between
// internal/ioc and internal/connector.
type OTXSource struct {
	apiKey     string
	httpClient *http.Client
	baseURL    string // overridden by tests; otxAPIBaseURL in production
	lastStat   SourceStat
}

const otxAPIBaseURL = "https://otx.alienvault.com/api/v1"

// otxPageLimit/otxMaxPages bound each sync to at most 500 pulses
// (10 pages x 50), regardless of how many pulses the account is actually
// subscribed to. This assumes /pulses/subscribed returns pulses ordered
// most-recently-modified-first by default -- unverified against a live OTX
// account; see the design spec's "Open assumption" note.
const otxPageLimit = 50
const otxMaxPages = 10

// NewOTXSource creates an OTX periodic-sync client.
func NewOTXSource(apiKey string) *OTXSource {
	return &OTXSource{
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    otxAPIBaseURL,
	}
}

// Name identifies this source. Implements Source.
func (c *OTXSource) Name() string { return "otx" }

type otxPulse struct {
	Name      string `json:"name"`
	Adversary string `json:"adversary"`
	Modified  string `json:"modified"` // RFC3339
}

type otxPulsesResponse struct {
	Count   int        `json:"count"`
	Results []otxPulse `json:"results"`
}

// otxActivityAccumulator tracks one actor's pulse count and observed date
// range while paging through subscribed pulses this sync.
type otxActivityAccumulator struct {
	count       int
	first, last time.Time
}

// FetchActivity pages through the account's subscribed pulses (capped at
// otxMaxPages x otxPageLimit) and builds one ActivitySignal per matched
// MITRE group, counting every matching pulse and tracking the earliest/
// latest Modified date seen this sync. A page-1 failure returns nil, err.
// A later-page failure returns whatever signals were gathered from the
// pages that did succeed, alongside the error.
func (c *OTXSource) FetchActivity() ([]ActivitySignal, error) {
	groupTechs := attackdata.GroupTechniqueIndex()
	normalizedGroups := make(map[string]string, len(groupTechs))
	for name := range groupTechs {
		normalizedGroups[normalizeAdversary(name)] = name
	}

	accByActor := make(map[string]*otxActivityAccumulator)
	var totalFetched int

	for page := 1; page <= otxMaxPages; page++ {
		pulses, err := c.fetchPulsesPage(page)
		if err != nil {
			if page == 1 {
				c.lastStat = SourceStat{Name: "otx", Error: err.Error(), FetchedAt: time.Now()}
				return nil, fmt.Errorf("otx fetch page 1: %w", err)
			}
			out := otxSignalsFromMap(accByActor)
			c.lastStat = SourceStat{Name: "otx", RawCount: totalFetched, ActorCount: len(out), Error: err.Error(), FetchedAt: time.Now()}
			return out, fmt.Errorf("otx fetch page %d: %w", page, err)
		}

		totalFetched += len(pulses)
		for _, p := range pulses {
			if strings.TrimSpace(p.Adversary) == "" {
				continue
			}
			groupName, ok := normalizedGroups[normalizeAdversary(p.Adversary)]
			if !ok {
				continue
			}
			modified, parseErr := time.Parse(time.RFC3339, p.Modified)
			if parseErr != nil {
				continue // can't order an unparseable timestamp -- skip counting this pulse
			}

			acc, ok := accByActor[groupName]
			if !ok {
				acc = &otxActivityAccumulator{first: modified, last: modified}
				accByActor[groupName] = acc
			}
			acc.count++
			if modified.Before(acc.first) {
				acc.first = modified
			}
			if modified.After(acc.last) {
				acc.last = modified
			}
		}

		if len(pulses) < otxPageLimit {
			break
		}
	}

	out := otxSignalsFromMap(accByActor)
	c.lastStat = SourceStat{Name: "otx", RawCount: totalFetched, ActorCount: len(out), FetchedAt: time.Now()}
	return out, nil
}

// Stats implements StatsSource.
func (c *OTXSource) Stats() SourceStat { return c.lastStat }

func normalizeAdversary(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

func otxSignalsFromMap(m map[string]*otxActivityAccumulator) []ActivitySignal {
	out := make([]ActivitySignal, 0, len(m))
	for name, acc := range m {
		out = append(out, ActivitySignal{
			ActorName: name, PulseCount: acc.count,
			FirstObserved: acc.first, LastObserved: acc.last,
		})
	}
	return out
}

func (c *OTXSource) fetchPulsesPage(page int) ([]otxPulse, error) {
	url := fmt.Sprintf("%s/pulses/subscribed?limit=%d&page=%d", c.baseURL, otxPageLimit, page)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OTX returned HTTP %d", resp.StatusCode)
	}

	var parsed otxPulsesResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return parsed.Results, nil
}
