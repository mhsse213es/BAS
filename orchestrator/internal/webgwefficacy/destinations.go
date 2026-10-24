package webgwefficacy

import (
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

// DestinationCategory groups web-gateway test destinations by the control
// they exercise. Each category has both known-bad destinations (the gateway
// must block or challenge) and known-good destinations (it must allow), so
// a gateway that blocks everything cannot pass.
type DestinationCategory string

const (
	CategoryPhishing  DestinationCategory = "phishing"
	CategoryC2        DestinationCategory = "command-and-control"
	CategoryURLFilter DestinationCategory = "url-filtering"
	CategorySafeFile  DestinationCategory = "safe-file-download"
)

// reservedTLDs are the RFC 6761 / RFC 2606 names that can never resolve on
// the public internet. Every destination host must sit under one of them so
// no catalog entry can reach a real third-party site or a real attacker
// infrastructure, whatever the gateway does with it.
var reservedTLDs = []string{".test", ".example", ".invalid", ".localhost"}

// safeFileNames are the only file basenames a safe-file-download destination
// may use. Only the EICAR anti-virus test file and a benign text file are
// permitted; no other payload name can be catalogued.
var safeFileNames = map[string]bool{
	"eicar.com":  true,
	"sample.txt": true,
}

// TestDestination is one categorized web-gateway test destination.
type TestDestination struct {
	ID             string
	Category       DestinationCategory
	URL            string
	URLCategory    string
	ExpectedAction ExpectedGatewayAction
	Note           string
}

// NewTestDestination validates every safety and shape invariant before a
// destination exists, so an unsafe or malformed entry cannot be constructed.
func NewTestDestination(id string, category DestinationCategory, rawURL, urlCategory string, expected ExpectedGatewayAction, note string) (TestDestination, error) {
	if id == "" {
		return TestDestination{}, fmt.Errorf("webgw destination: ID must not be empty")
	}
	switch category {
	case CategoryPhishing, CategoryC2, CategoryURLFilter, CategorySafeFile:
	default:
		return TestDestination{}, fmt.Errorf("webgw destination %s: unknown category %q", id, category)
	}
	switch expected {
	case ExpectedAllow, ExpectedBlock, ExpectedChallenge, ExpectedQuarantine:
	default:
		return TestDestination{}, fmt.Errorf("webgw destination %s: unknown expected action %q", id, expected)
	}
	if strings.TrimSpace(note) == "" {
		return TestDestination{}, fmt.Errorf("webgw destination %s: Note must not be empty", id)
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return TestDestination{}, fmt.Errorf("webgw destination %s: URL does not parse: %w", id, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return TestDestination{}, fmt.Errorf("webgw destination %s: scheme %q must be http or https", id, u.Scheme)
	}
	if u.User != nil {
		return TestDestination{}, fmt.Errorf("webgw destination %s: URL must not carry userinfo", id)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return TestDestination{}, fmt.Errorf("webgw destination %s: URL has no host", id)
	}
	if net.ParseIP(host) != nil {
		return TestDestination{}, fmt.Errorf("webgw destination %s: host %q is an IP literal; only reserved DNS names are allowed", id, host)
	}
	if !hasReservedTLD(host) {
		return TestDestination{}, fmt.Errorf("webgw destination %s: host %q is not under a reserved test TLD (%s)", id, host, strings.Join(reservedTLDs, ", "))
	}
	if category == CategorySafeFile && !safeFileNames[path.Base(u.Path)] {
		return TestDestination{}, fmt.Errorf("webgw destination %s: safe-file destination must end in one of the permitted benign or EICAR file names, got %q", id, path.Base(u.Path))
	}

	return TestDestination{
		ID:             id,
		Category:       category,
		URL:            rawURL,
		URLCategory:    urlCategory,
		ExpectedAction: expected,
		Note:           note,
	}, nil
}

func hasReservedTLD(host string) bool {
	for _, tld := range reservedTLDs {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}
	return false
}

// Expectation returns the HTTPExpectation the verifier checks for this
// destination against the named gateway product.
func (d TestDestination) Expectation(controlProduct string) HTTPExpectation {
	return HTTPExpectation{
		RequestURL:     d.URL,
		URLCategory:    d.URLCategory,
		ExpectedAction: d.ExpectedAction,
		ControlProduct: controlProduct,
		Note:           d.Note,
	}
}

// AudspectWebGWDestinationCatalog returns the built-in destinations. Every
// entry goes through NewTestDestination, so an invalid one is an error here
// rather than a silently wrong catalog.
func AudspectWebGWDestinationCatalog() ([]TestDestination, error) {
	specs := []struct {
		id, url, urlCategory, note string
		category                   DestinationCategory
		expected                   ExpectedGatewayAction
	}{
		{"WG-PH-001", "https://login-verify.lookalike-lab.test/signin", "phishing", "lookalike sign-in page for a credential-harvesting test", CategoryPhishing, ExpectedBlock},
		{"WG-PH-002", "https://secure-payroll-update.phish-lab.test/form", "phishing", "credential-collection form destination", CategoryPhishing, ExpectedBlock},
		{"WG-PH-000", "https://intranet.example-lab.test/home", "business", "legitimate internal site: must not be flagged as phishing", CategoryPhishing, ExpectedAllow},

		{"WG-C2-001", "https://beacon.c2-lab.test/api/check-in", "command-and-control", "simulated C2 beacon check-in endpoint", CategoryC2, ExpectedBlock},
		{"WG-C2-002", "https://update-check.c2-lab.test/poll", "command-and-control", "simulated C2 polling endpoint", CategoryC2, ExpectedBlock},
		{"WG-C2-000", "https://api.example-lab.test/status", "technology", "legitimate API status endpoint: must not be flagged as C2", CategoryC2, ExpectedAllow},

		{"WG-UF-001", "https://casino.urlfilter-lab.test/", "gambling", "gambling category, blocked by URL-filtering policy", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-002", "https://news.example-lab.test/", "news", "news category, permitted by default policy", CategoryURLFilter, ExpectedAllow},

		{"WG-SF-001", "https://files.download-lab.test/eicar.com", "file-download", "EICAR anti-virus test file download: must be blocked", CategorySafeFile, ExpectedBlock},
		{"WG-SF-000", "https://files.download-lab.test/sample.txt", "file-download", "benign plain-text file download: must be allowed", CategorySafeFile, ExpectedAllow},
	}

	out := make([]TestDestination, 0, len(specs))
	for _, s := range specs {
		d, err := NewTestDestination(s.id, s.category, s.url, s.urlCategory, s.expected, s.note)
		if err != nil {
			return nil, fmt.Errorf("building webgw destination catalog: %w", err)
		}
		out = append(out, d)
	}
	return out, nil
}
