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

// eicarFileNames are the EICAR anti-virus test file's own published names: the plain file, the .txt copy and the
// zipped copy. Each can only ever contain the EICAR test string.
var eicarFileNames = map[string]bool{
	"eicar.com":     true,
	"eicar.com.txt": true,
	"eicarcom2.zip": true,
}

// sampleExtensions are the extensions a benign placeholder download may carry. The name sample.<ext> is a convention:
// whatever serves it serves plain placeholder text, so a gateway that blocks sample.exe is blocking the file type, not
// any content. Nothing outside this set and eicarFileNames can be catalogued.
var sampleExtensions = map[string]bool{
	"txt": true, "pdf": true, "docx": true, "xlsx": true, "csv": true, "png": true,
	"exe": true, "scr": true, "bat": true, "cmd": true, "ps1": true, "vbs": true, "js": true,
	"jar": true, "msi": true, "dll": true, "iso": true, "lnk": true,
}

// permittedFileName reports whether a download's file name is an EICAR name or a benign sample.<ext> name.
func permittedFileName(name string) bool {
	name = strings.ToLower(name)
	if eicarFileNames[name] {
		return true
	}
	ext, ok := strings.CutPrefix(name, "sample.")
	return ok && sampleExtensions[ext]
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
	if category == CategorySafeFile && !permittedFileName(path.Base(u.Path)) {
		return TestDestination{}, fmt.Errorf("webgw destination %s: safe-file destination must end in an EICAR file name or a benign sample.<ext> name, got %q", id, path.Base(u.Path))
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

		{"WG-UF-003", "https://adult.urlfilter-lab.test/", "adult", "adult content category, blocked by URL-filtering policy", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-004", "https://anonymizer.urlfilter-lab.test/", "anonymizer", "anonymizer and proxy-avoidance category, blocked because it hides traffic from the gateway", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-005", "https://peer-to-peer.urlfilter-lab.test/", "peer-to-peer", "peer-to-peer file sharing category, blocked by URL-filtering policy", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-006", "https://malware-hosting.urlfilter-lab.test/", "malware-hosting", "site category used for malware distribution, blocked", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-007", "https://cryptomining.urlfilter-lab.test/", "cryptomining", "browser cryptomining category, blocked", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-008", "https://hacking.urlfilter-lab.test/", "hacking", "hacking-tools category, blocked", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-009", "https://newly-registered-domain.urlfilter-lab.test/", "newly-registered-domain", "newly registered domain category, blocked or challenged because most attack infrastructure is days old", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-010", "https://illegal-drugs.urlfilter-lab.test/", "illegal-drugs", "illegal-drugs category, blocked by URL-filtering policy", CategoryURLFilter, ExpectedBlock},
		{"WG-UF-011", "https://education.example-lab.test/", "education", "education category, permitted by default policy", CategoryURLFilter, ExpectedAllow},
		{"WG-UF-012", "https://government.example-lab.test/", "government", "government category, permitted by default policy", CategoryURLFilter, ExpectedAllow},
		{"WG-UF-013", "https://health.example-lab.test/", "health", "health category, permitted by default policy", CategoryURLFilter, ExpectedAllow},
		{"WG-UF-014", "https://search-engines.example-lab.test/", "search-engines", "search-engine category, permitted by default policy", CategoryURLFilter, ExpectedAllow},
		{"WG-UF-015", "https://software-updates.example-lab.test/", "software-updates", "software-update category, permitted by default policy", CategoryURLFilter, ExpectedAllow},
		{"WG-UF-016", "https://finance.example-lab.test/", "finance", "finance and banking category, permitted by default policy", CategoryURLFilter, ExpectedAllow},

		{"WG-SF-002", "https://files.download-lab.test/eicar.com.txt", "file-download", "EICAR test string saved with a .txt extension: content scanning must still catch it", CategorySafeFile, ExpectedBlock},
		{"WG-SF-003", "https://files.download-lab.test/eicarcom2.zip", "file-download", "EICAR test file inside a zip archive: the gateway must open the archive", CategorySafeFile, ExpectedBlock},
		{"WG-SF-004", "https://files.download-lab.test/sample.exe", "file-download", "benign placeholder served as a .exe (executable): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-005", "https://files.download-lab.test/sample.scr", "file-download", "benign placeholder served as a .scr (screensaver executable): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-006", "https://files.download-lab.test/sample.bat", "file-download", "benign placeholder served as a .bat (batch script): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-007", "https://files.download-lab.test/sample.cmd", "file-download", "benign placeholder served as a .cmd (command script): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-008", "https://files.download-lab.test/sample.ps1", "file-download", "benign placeholder served as a .ps1 (PowerShell script): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-009", "https://files.download-lab.test/sample.vbs", "file-download", "benign placeholder served as a .vbs (VBScript): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-010", "https://files.download-lab.test/sample.js", "file-download", "benign placeholder served as a .js (JScript): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-011", "https://files.download-lab.test/sample.jar", "file-download", "benign placeholder served as a .jar (Java archive): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-012", "https://files.download-lab.test/sample.msi", "file-download", "benign placeholder served as a .msi (installer package): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-013", "https://files.download-lab.test/sample.dll", "file-download", "benign placeholder served as a .dll (dynamic library): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-014", "https://files.download-lab.test/sample.iso", "file-download", "benign placeholder served as a .iso (disk image): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},
		{"WG-SF-015", "https://files.download-lab.test/sample.lnk", "file-download", "benign placeholder served as a .lnk (shortcut file): blocked by file-type policy alone, with no content to scan", CategorySafeFile, ExpectedBlock},

		{"WG-SF-016", "https://files.download-lab.test/sample.pdf", "file-download", "benign placeholder served as a .pdf (PDF document): ordinary business file type, must be allowed", CategorySafeFile, ExpectedAllow},
		{"WG-SF-017", "https://files.download-lab.test/sample.docx", "file-download", "benign placeholder served as a .docx (Word document): ordinary business file type, must be allowed", CategorySafeFile, ExpectedAllow},
		{"WG-SF-018", "https://files.download-lab.test/sample.xlsx", "file-download", "benign placeholder served as a .xlsx (Excel workbook): ordinary business file type, must be allowed", CategorySafeFile, ExpectedAllow},
		{"WG-SF-019", "https://files.download-lab.test/sample.csv", "file-download", "benign placeholder served as a .csv (CSV file): ordinary business file type, must be allowed", CategorySafeFile, ExpectedAllow},
		{"WG-SF-020", "https://files.download-lab.test/sample.png", "file-download", "benign placeholder served as a .png (PNG image): ordinary business file type, must be allowed", CategorySafeFile, ExpectedAllow},
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
