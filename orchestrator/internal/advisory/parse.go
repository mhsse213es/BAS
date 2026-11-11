// Package advisory ingests threat advisories from CERT-In and FS-ISAC and
// records analyst relevance decisions for them (REQ-018 Gap 2).
//
// The CERT-In parser is built against the RSS 2.0 sample supplied by the
// owner. That sample has NOT been checked against the live feed, which could not
// be reached from the build environment. Parsed items are therefore marked
// Unverified, and nothing in this package fetches from the network.
package advisory

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Item is one advisory as parsed from a source, before it is stored.
type Item struct {
	Source      string // "cert_in" or "fs_isac"
	ExternalID  string
	Title       string
	PublishedAt time.Time // zero if the source gave no date
	SourceRef   string    // feed URL or TAXII collection the item came from
	Body        string
}

// ErrNoItems is returned when a feed parses but contains no usable advisories.
var ErrNoItems = errors.New("advisory: feed contains no usable items")

// --- CERT-In: RSS 2.0 -------------------------------------------------------

type rssDoc struct {
	XMLName xml.Name `xml:"rss"`
	Items   []rssItem `xml:"channel>item"`
}

type rssItem struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}

// ParseCERTInRSS parses a CERT-In RSS 2.0 feed. The external ID is the guid,
// falling back to the vulnid query parameter in the link. An item with no
// usable ID or title is skipped and counted, never silently stored.
// Unverified: format taken from the owner's sample, not the live feed.
func ParseCERTInRSS(raw []byte, sourceRef string) ([]Item, int, error) {
	var doc rssDoc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return nil, 0, fmt.Errorf("advisory: parse CERT-In RSS: %w", err)
	}
	var out []Item
	skipped := 0
	for _, it := range doc.Items {
		id := strings.TrimSpace(it.GUID)
		if id == "" {
			id = vulnIDFromLink(it.Link)
		}
		title := strings.TrimSpace(it.Title)
		if id == "" || title == "" {
			skipped++
			continue
		}
		out = append(out, Item{
			Source:      "cert_in",
			ExternalID:  id,
			Title:       title,
			PublishedAt: parseRFC822(it.PubDate),
			SourceRef:   sourceRef,
			Body:        strings.TrimSpace(it.Description),
		})
	}
	if len(out) == 0 {
		return nil, skipped, ErrNoItems
	}
	return out, skipped, nil
}

func vulnIDFromLink(link string) string {
	i := strings.Index(link, "vulnid=")
	if i < 0 {
		return ""
	}
	id := link[i+len("vulnid="):]
	if j := strings.IndexAny(id, "&#"); j >= 0 {
		id = id[:j]
	}
	return strings.TrimSpace(id)
}

// parseRFC822 accepts the RSS pubDate forms. It returns the zero time if none match.
func parseRFC822(s string) time.Time {
	for _, layout := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t
		}
	}
	return time.Time{}
}

// --- FS-ISAC: STIX 2.1 bundle, report objects -------------------------------

type stixBundle struct {
	Type    string            `json:"type"`
	Objects []json.RawMessage `json:"objects"`
}

type stixReport struct {
	Type        string    `json:"type"`
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Published   string    `json:"published"`
	Created     string    `json:"created"`
}

// ParseFSISACBundle extracts advisories from a STIX 2.1 bundle. Only objects of
// type "report" become advisories. Indicators and other objects are left for the
// IOC path and are not counted here.
func ParseFSISACBundle(raw []byte, collectionRef string) ([]Item, error) {
	var b stixBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("advisory: parse STIX bundle: %w", err)
	}
	if b.Type != "bundle" {
		return nil, fmt.Errorf("advisory: not a STIX bundle (type %q)", b.Type)
	}
	var out []Item
	for _, obj := range b.Objects {
		var r stixReport
		if err := json.Unmarshal(obj, &r); err != nil || r.Type != "report" {
			continue
		}
		if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Name) == "" {
			continue
		}
		pub := parseRFC3339(r.Published)
		if pub.IsZero() {
			pub = parseRFC3339(r.Created)
		}
		out = append(out, Item{
			Source:      "fs_isac",
			ExternalID:  r.ID,
			Title:       strings.TrimSpace(r.Name),
			PublishedAt: pub,
			SourceRef:   collectionRef,
			Body:        strings.TrimSpace(r.Description),
		})
	}
	if len(out) == 0 {
		return nil, ErrNoItems
	}
	return out, nil
}

func parseRFC3339(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}
	}
	return t
}
