# IOC Extraction From Run Results Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract IOCs (IPs, domains, URLs, hashes, CVEs) from BAS run results the instant they're submitted, store them with full provenance, and expose them via a new read endpoint — no OTX/correlation calls yet (that's sub-project C).

**Architecture:** A pure regex-based extractor (`internal/ioc/extract.go`) finds indicators in a blob of text. A per-run aggregator (`internal/ioc/aggregate.go`) walks a run's `ExecResult`/`SimCheckResult` slices, calls the extractor on each source (stdout, stderr, details), and dedups into one row per distinct indicator with full technique/simulation traceability. `SubmitScenarioResult` calls the aggregator synchronously right after it finalizes a run's results, and a new DB layer persists the output to a new `run_iocs` table (delete-then-insert per run, matching this handler's existing idempotency pattern). A new `GET /api/scenarios/runs/{runId}/iocs` endpoint reads it back.

**Tech Stack:** Go 1.x, `net`/`net/url`/`regexp` (stdlib only, no new dependencies), PostgreSQL via `pgxpool`, chi router.

## Global Constraints

- Extraction lives inside the existing `internal/ioc` package (no new package) — it reuses the `ip`/`domain`/`url`/`hash`/`cve` type strings `Provider.LookupIP` etc. already use.
- Extraction reads the pre-merge `scenario.ExecResult.Stdout`/`.Stderr` and `scenario.SimCheckResult.Details` — never `models.SimulationResult.RawOutput` (already merged and truncated to 3000 chars upstream).
- Fixed confidence table: `hash`=100, `url`=100, `cve`=100, `ip`=95, `domain`=80.
- Dedup grain: one row per `(run_id, indicator_type, indicator_value)` — not per occurrence.
- Private/reserved IPv4 addresses (RFC1918, loopback, link-local, multicast, unspecified) are filtered out entirely, never stored.
- Domain extraction blocklists common file extensions (`.exe`, `.dll`, `.ps1`, `.sh`, etc.) to avoid false-positiving on filenames — precision over recall is an intentional, tested tradeoff (a legitimate `.sh`-TLD domain would be filtered; this is accepted, not a bug).
- Hash algorithm is preserved via length (32→md5, 40→sha1, 64→sha256) in a dedicated field; `Type` stays `"hash"` for all three.
- Normalization is mandatory before storage: domain/hash lowercase, CVE uppercase, URL lowercase scheme+host with fragment stripped and root path collapsed.
- Write path is transactional delete-then-bulk-insert per `run_id` — never a SQL-side array merge.
- New endpoint sits in the existing JWT-only "Viewer+Analyst+Admin" route group — no new permission required.
- Extraction failures are logged and swallowed — they must never fail result ingestion (this is enrichment, not core scoring).
- Extraction runs on partial runs too (unlike findings, which intentionally skip partial runs).
- "First occurrence" (for `Source`/`OffsetStart`/`OffsetEnd`) is deterministic: walk `execResults` in slice order scanning `Stdout` then `Stderr`, then walk `checks` in slice order scanning `Details`.
- Out of scope for this plan: any OTX/provider call, cross-run correlation, report surfacing.

---

### Task 1: Pure indicator extractor

**Files:**
- Create: `orchestrator/internal/ioc/extract.go`
- Test: `orchestrator/internal/ioc/extract_test.go`

**Interfaces:**
- Produces: `type Indicator struct { Type, Value, Algorithm string; Confidence, OffsetStart, OffsetEnd int }` and `func ExtractIndicators(text string) []Indicator` — used by Task 2.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/ioc/extract_test.go`:

```go
package ioc

import "testing"

func TestExtractIndicators_IPv4Public(t *testing.T) {
	text := "beaconing to 45.33.32.156 every 60s"
	got := ExtractIndicators(text)
	if len(got) != 1 {
		t.Fatalf("got %d indicators, want 1: %+v", len(got), got)
	}
	ind := got[0]
	if ind.Type != "ip" || ind.Value != "45.33.32.156" || ind.Confidence != 95 {
		t.Errorf("got %+v", ind)
	}
	if text[ind.OffsetStart:ind.OffsetEnd] != "45.33.32.156" {
		t.Errorf("offsets [%d:%d] = %q, want 45.33.32.156", ind.OffsetStart, ind.OffsetEnd, text[ind.OffsetStart:ind.OffsetEnd])
	}
}

func TestExtractIndicators_IPv4Private_Filtered(t *testing.T) {
	for _, ip := range []string{"10.0.0.5", "172.16.4.4", "192.168.1.1", "127.0.0.1", "169.254.1.1"} {
		got := ExtractIndicators("connecting to " + ip)
		if len(got) != 0 {
			t.Errorf("private IP %s was not filtered: %+v", ip, got)
		}
	}
}

func TestExtractIndicators_IPv4InvalidOctet_Rejected(t *testing.T) {
	got := ExtractIndicators("windows build 10.0.19045.1")
	for _, ind := range got {
		if ind.Type == "ip" {
			t.Errorf("version string matched as IP: %+v", ind)
		}
	}
}

func TestExtractIndicators_Domain(t *testing.T) {
	got := ExtractIndicators("resolved evil.Example.COM via DNS")
	if len(got) != 1 || got[0].Type != "domain" || got[0].Value != "evil.example.com" || got[0].Confidence != 80 {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_Domain_FileExtensionBlocked(t *testing.T) {
	got := ExtractIndicators("launched svchost.exe and wrote report.json")
	for _, ind := range got {
		if ind.Type == "domain" {
			t.Errorf("filename matched as domain: %+v", ind)
		}
	}
}

func TestExtractIndicators_Domain_ShTLDTradeoff(t *testing.T) {
	// Documented tradeoff: ".sh" is filtered as a shell-script extension, so a
	// legitimate "example.sh" domain is a known, accepted false negative.
	got := ExtractIndicators("curl https://example.sh/x")
	for _, ind := range got {
		if ind.Type == "domain" && ind.Value == "example.sh" {
			t.Errorf("expected example.sh to be filtered as a domain (accepted tradeoff), got %+v", ind)
		}
	}
}

func TestExtractIndicators_URL(t *testing.T) {
	// Asserts exactly 1 result -- the URL's own host ("Evil.Test") must NOT
	// also surface as a separate domain indicator (see ExtractIndicators' doc
	// comment on URL-vs-domain/ip suppression).
	got := ExtractIndicators("Downloaded http://Evil.Test/payload.exe#frag")
	if len(got) != 1 || got[0].Type != "url" {
		t.Fatalf("got %+v, want exactly 1 url indicator (no redundant domain hit for the URL's own host)", got)
	}
	if got[0].Value != "http://evil.test/payload.exe" {
		t.Errorf("Value = %q, want http://evil.test/payload.exe", got[0].Value)
	}
	if got[0].Confidence != 100 {
		t.Errorf("Confidence = %d, want 100", got[0].Confidence)
	}
}

func TestExtractIndicators_URL_RootPathCollapsed(t *testing.T) {
	got := ExtractIndicators("beaconing to http://Evil.Test/")
	if len(got) != 1 || got[0].Value != "http://evil.test" {
		t.Fatalf("got %+v, want http://evil.test", got)
	}
}

func TestExtractIndicators_URL_IPHostNotDoubleCounted(t *testing.T) {
	// Same suppression as the domain case, but for an IP-as-host URL.
	got := ExtractIndicators("dropped stage2 from http://45.33.32.156/s2.bin")
	if len(got) != 1 || got[0].Type != "url" {
		t.Fatalf("got %+v, want exactly 1 url indicator (no redundant ip hit for the URL's own host)", got)
	}
}

func TestExtractIndicators_HashInsideURLPath_StillExtracted(t *testing.T) {
	// Unlike domain/ip, a hash embedded in a URL's path is a distinct
	// indicator in its own right and must still be extracted alongside the url.
	got := ExtractIndicators("fetch http://cdn.example.com/0123456789abcdef0123456789abcdef")
	types := map[string]int{}
	for _, ind := range got {
		types[ind.Type]++
	}
	if types["url"] != 1 || types["hash"] != 1 {
		t.Fatalf("got %+v, want 1 url + 1 hash", got)
	}
}

func TestExtractIndicators_Hash_MD5(t *testing.T) {
	// A mechanically-constructed 32-hex-char string (not a "real" MD5 digest of
	// anything) -- the extractor only cares about hex-run length, so exact
	// length matters here more than the value being a genuine MD5 output.
	got := ExtractIndicators("MD5: 0123456789ABCDEF0123456789ABCDEF")
	if len(got) != 1 || got[0].Type != "hash" || got[0].Algorithm != "md5" {
		t.Fatalf("got %+v", got)
	}
	if got[0].Value != "0123456789abcdef0123456789abcdef" {
		t.Errorf("Value = %q, want lowercase", got[0].Value)
	}
}

func TestExtractIndicators_Hash_SHA1(t *testing.T) {
	got := ExtractIndicators("SHA1: aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
	if len(got) != 1 || got[0].Algorithm != "sha1" {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_Hash_SHA256(t *testing.T) {
	got := ExtractIndicators("SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if len(got) != 1 || got[0].Algorithm != "sha256" {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_CVE(t *testing.T) {
	got := ExtractIndicators("exploiting cve-2024-3094 in xz")
	if len(got) != 1 || got[0].Type != "cve" || got[0].Value != "CVE-2024-3094" || got[0].Confidence != 100 {
		t.Fatalf("got %+v", got)
	}
}

func TestExtractIndicators_RealisticARTStdout(t *testing.T) {
	text := "Scanning subnet...\n" +
		"Host up: 45.33.32.156 (198.51.100.7 filtered)\n" +
		"Retrieved banner from 45.33.32.156:445\n" +
		"Local host: 192.168.1.50 (ignored)"
	got := ExtractIndicators(text)
	var ips []string
	for _, ind := range got {
		if ind.Type == "ip" {
			ips = append(ips, ind.Value)
		}
	}
	if len(ips) != 2 {
		t.Fatalf("ips = %v, want 2 public IPs (192.168.1.50 filtered)", ips)
	}
}

func TestExtractIndicators_RealisticCalderaStdout(t *testing.T) {
	text := "[+] beacon established to c2.evil-domain.net\n" +
		"[+] downloading stage2 from http://c2.evil-domain.net/s2.bin\n" +
		"[+] dropped payload hash 44d88612fea8a8f36de82e1278abb02f"
	got := ExtractIndicators(text)
	types := map[string]int{}
	for _, ind := range got {
		types[ind.Type]++
	}
	if types["domain"] < 1 || types["url"] < 1 || types["hash"] != 1 {
		t.Fatalf("got %+v from %v", got, types)
	}
}

func TestExtractIndicators_NoFalsePositivesOnEmptyText(t *testing.T) {
	if got := ExtractIndicators(""); len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd orchestrator
go test ./internal/ioc/... -run TestExtractIndicators -v
```
Expected: FAIL with `undefined: ExtractIndicators` (and `undefined: Indicator`) — the function doesn't exist yet.

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/ioc/extract.go`:

```go
package ioc

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// Indicator is one raw match ExtractIndicators found in a block of text. It
// carries no run/step context -- BuildRunIndicators (aggregate.go) adds that.
type Indicator struct {
	Type        string // ip | domain | url | hash | cve
	Value       string // normalized
	Algorithm   string // md5 | sha1 | sha256 (hash only, else "")
	Confidence  int    // 0-100
	OffsetStart int
	OffsetEnd   int
}

const (
	confidenceHash   = 100
	confidenceURL    = 100
	confidenceCVE    = 100
	confidenceIPv4   = 95
	confidenceDomain = 80
)

var (
	ipv4Regex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	// Domain: dot-separated labels ending in a 2-24 letter TLD.
	domainRegex = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)
	urlRegex    = regexp.MustCompile(`\bhttps?://[^\s"'<>\)\]]+`)
	hashRegex   = regexp.MustCompile(`\b[a-fA-F0-9]{32,64}\b`)
	cveRegex    = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
)

// domainExtBlocklist holds common non-TLD file extensions that would
// otherwise false-positive against the domain regex (e.g. "svchost.exe").
// Precision-over-recall tradeoff: a few real ccTLDs collide with common
// script extensions (".sh" is both Saint Helena's ccTLD and the most common
// shell-script extension in this system's actual command output) and are
// deliberately excluded here too.
var domainExtBlocklist = map[string]bool{
	"exe": true, "dll": true, "sys": true, "ps1": true, "psm1": true,
	"py": true, "sh": true, "bat": true, "cmd": true, "msi": true,
	"zip": true, "rar": true, "log": true, "txt": true, "json": true,
	"xml": true, "yaml": true, "yml": true, "config": true, "ini": true,
	"dat": true, "tmp": true, "bak": true, "jar": true, "class": true,
}

// ExtractIndicators scans text for IOCs. Pure and stateless: no knowledge of
// runs, steps, or techniques -- see BuildRunIndicators for that context.
//
// URL matches are found first; any ip/domain match whose full span falls
// inside a URL match's span is suppressed. Without this, "http://evil.test/x"
// would produce both a url indicator AND a redundant domain indicator for
// "evil.test" (the URL's own host) -- the spec calls this out explicitly for
// domains, and the same reasoning applies to an IP-as-host ("http://1.2.3.4/x").
// A hash or CVE appearing inside a URL's path is NOT suppressed -- that's a
// distinct indicator value in its own right, not a restatement of the URL's
// address.
func ExtractIndicators(text string) []Indicator {
	urls := extractURLs(text)
	excluded := make([][2]int, len(urls))
	for i, u := range urls {
		excluded[i] = [2]int{u.OffsetStart, u.OffsetEnd}
	}

	var out []Indicator
	out = append(out, extractIPv4(text, excluded)...)
	out = append(out, extractDomains(text, excluded)...)
	out = append(out, urls...)
	out = append(out, extractHashes(text)...)
	out = append(out, extractCVEs(text)...)
	return out
}

// withinAny reports whether [start,end) is fully contained in one of ranges.
func withinAny(start, end int, ranges [][2]int) bool {
	for _, rg := range ranges {
		if start >= rg[0] && end <= rg[1] {
			return true
		}
	}
	return false
}

func extractIPv4(text string, excluded [][2]int) []Indicator {
	var out []Indicator
	for _, loc := range ipv4Regex.FindAllStringIndex(text, -1) {
		if withinAny(loc[0], loc[1], excluded) {
			continue // this IP is the host portion of a URL match -- already covered
		}
		raw := text[loc[0]:loc[1]]
		ip := net.ParseIP(raw)
		if ip == nil || ip.To4() == nil {
			continue // octet out of 0-255 range, or not a real IPv4 literal
		}
		if isFilteredIPv4(ip) {
			continue
		}
		out = append(out, Indicator{
			Type: "ip", Value: raw, Confidence: confidenceIPv4,
			OffsetStart: loc[0], OffsetEnd: loc[1],
		})
	}
	return out
}

func isFilteredIPv4(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

func extractDomains(text string, excluded [][2]int) []Indicator {
	var out []Indicator
	for _, loc := range domainRegex.FindAllStringIndex(text, -1) {
		if withinAny(loc[0], loc[1], excluded) {
			continue // this domain is the host portion of a URL match -- already covered
		}
		raw := text[loc[0]:loc[1]]
		labels := strings.Split(raw, ".")
		tld := strings.ToLower(labels[len(labels)-1])
		if domainExtBlocklist[tld] {
			continue
		}
		out = append(out, Indicator{
			Type: "domain", Value: strings.ToLower(raw), Confidence: confidenceDomain,
			OffsetStart: loc[0], OffsetEnd: loc[1],
		})
	}
	return out
}

func extractURLs(text string) []Indicator {
	var out []Indicator
	for _, loc := range urlRegex.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		out = append(out, Indicator{
			Type: "url", Value: normalizeURL(raw), Confidence: confidenceURL,
			OffsetStart: loc[0], OffsetEnd: loc[1],
		})
	}
	return out
}

func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String()
}

func extractHashes(text string) []Indicator {
	var out []Indicator
	for _, loc := range hashRegex.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		var algo string
		switch len(raw) {
		case 32:
			algo = "md5"
		case 40:
			algo = "sha1"
		case 64:
			algo = "sha256"
		default:
			continue // 33-39 or 41-63 hex chars -- not a known hash length
		}
		out = append(out, Indicator{
			Type: "hash", Value: strings.ToLower(raw), Algorithm: algo,
			Confidence: confidenceHash, OffsetStart: loc[0], OffsetEnd: loc[1],
		})
	}
	return out
}

func extractCVEs(text string) []Indicator {
	var out []Indicator
	for _, loc := range cveRegex.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		out = append(out, Indicator{
			Type: "cve", Value: strings.ToUpper(raw), Confidence: confidenceCVE,
			OffsetStart: loc[0], OffsetEnd: loc[1],
		})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd orchestrator
go test ./internal/ioc/... -run TestExtractIndicators -v
```
Expected: all `PASS`.

- [ ] **Step 5: Run go vet**

```bash
cd orchestrator
go vet ./internal/ioc/...
```
Expected: no output (clean).

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/ioc/extract.go orchestrator/internal/ioc/extract_test.go
git commit -m "feat(ioc): add pure IOC extractor (ip/domain/url/hash/cve)"
```

---

### Task 2: Per-run aggregation with provenance

**Files:**
- Create: `orchestrator/internal/ioc/aggregate.go`
- Test: `orchestrator/internal/ioc/aggregate_test.go`

**Interfaces:**
- Consumes: `Indicator`, `ExtractIndicators` (Task 1); `scenario.ExecResult{TaskID, Stdout, Stderr string}`, `scenario.SimCheckResult{ID, TechniqueID, Details string}`, `scenario.Step{TechniqueID string}` (all already exist in `orchestrator/internal/scenario/types.go`).
- Produces: `type RunIndicator struct { Type, Value, Algorithm, Source string; Confidence, OffsetStart, OffsetEnd int; TechniqueIDs, SimulationIDs []string; ExtractedAt time.Time }` and `func BuildRunIndicators(execResults []scenario.ExecResult, checks []scenario.SimCheckResult, stepMap map[string]scenario.Step) []RunIndicator` — used by Task 3 (DB layer) and Task 4 (handler wiring).

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/ioc/aggregate_test.go`:

```go
package ioc

import (
	"testing"

	"github.com/audspect/bas/internal/scenario"
)

func TestBuildRunIndicators_SameIndicatorTwoStepsSameTechnique(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "T1059::PowerShell", Stdout: "beacon to 45.33.32.156"},
		{TaskID: "T1059::EncodedCommand", Stdout: "beacon to 45.33.32.156"},
	}
	stepMap := map[string]scenario.Step{
		"T1059::PowerShell":     {TechniqueID: "T1059"},
		"T1059::EncodedCommand": {TechniqueID: "T1059"},
	}
	got := BuildRunIndicators(execResults, nil, stepMap)
	if len(got) != 1 {
		t.Fatalf("got %d indicators, want 1: %+v", len(got), got)
	}
	ind := got[0]
	if len(ind.SimulationIDs) != 2 {
		t.Errorf("SimulationIDs = %v, want 2 entries", ind.SimulationIDs)
	}
	if len(ind.TechniqueIDs) != 1 || ind.TechniqueIDs[0] != "T1059" {
		t.Errorf("TechniqueIDs = %v, want [T1059]", ind.TechniqueIDs)
	}
}

func TestBuildRunIndicators_SameIndicatorTwoTechniques(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "T1059::A", Stdout: "beacon to 45.33.32.156"},
		{TaskID: "T1071::B", Stdout: "beacon to 45.33.32.156"},
	}
	stepMap := map[string]scenario.Step{
		"T1059::A": {TechniqueID: "T1059"},
		"T1071::B": {TechniqueID: "T1071"},
	}
	got := BuildRunIndicators(execResults, nil, stepMap)
	if len(got) != 1 || len(got[0].TechniqueIDs) != 2 {
		t.Fatalf("got %+v", got)
	}
}

func TestBuildRunIndicators_StdoutBeforeStderr(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "T1059::A", Stdout: "45.33.32.156 in stdout", Stderr: "45.33.32.156 in stderr"},
	}
	stepMap := map[string]scenario.Step{"T1059::A": {TechniqueID: "T1059"}}
	got := BuildRunIndicators(execResults, nil, stepMap)
	if len(got) != 1 || got[0].Source != "stdout" {
		t.Fatalf("got %+v, want Source=stdout (first in scan order)", got)
	}
}

func TestBuildRunIndicators_LocalCheckUsesDetailsSource(t *testing.T) {
	checks := []scenario.SimCheckResult{
		{ID: "os-patch-posture::last-patch-age", TechniqueID: "T1082", Details: "CVE-2024-3094 unpatched"},
	}
	got := BuildRunIndicators(nil, checks, nil)
	if len(got) != 1 || got[0].Source != "details" || got[0].Type != "cve" {
		t.Fatalf("got %+v", got)
	}
	if len(got[0].SimulationIDs) != 1 || got[0].SimulationIDs[0] != "os-patch-posture::last-patch-age" {
		t.Errorf("SimulationIDs = %v, want [os-patch-posture::last-patch-age]", got[0].SimulationIDs)
	}
}

func TestBuildRunIndicators_UnknownTaskIDNoTechnique(t *testing.T) {
	execResults := []scenario.ExecResult{
		{TaskID: "custom::adhoc", Stdout: "beacon to 45.33.32.156"},
	}
	got := BuildRunIndicators(execResults, nil, map[string]scenario.Step{})
	if len(got) != 1 || len(got[0].TechniqueIDs) != 0 {
		t.Fatalf("got %+v, want empty TechniqueIDs for an unmapped step", got)
	}
	if len(got[0].SimulationIDs) != 1 || got[0].SimulationIDs[0] != "custom::adhoc" {
		t.Errorf("SimulationIDs = %v", got[0].SimulationIDs)
	}
}

func TestBuildRunIndicators_EmptyInputsReturnsEmptySlice(t *testing.T) {
	got := BuildRunIndicators(nil, nil, nil)
	if len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd orchestrator
go test ./internal/ioc/... -run TestBuildRunIndicators -v
```
Expected: FAIL with `undefined: BuildRunIndicators` (and `undefined: RunIndicator`).

- [ ] **Step 3: Write the implementation**

Create `orchestrator/internal/ioc/aggregate.go`:

```go
package ioc

import (
	"time"

	"github.com/audspect/bas/internal/scenario"
)

// RunIndicator is one distinct indicator found anywhere in a run, aggregated
// across every step/technique that produced it. Reused as both the in-memory
// aggregation result and the DB/API shape (internal/db and internal/api
// consume this directly -- no duplicate struct).
type RunIndicator struct {
	Type          string    `json:"type"`
	Value         string    `json:"value"`
	Algorithm     string    `json:"hashAlgorithm,omitempty"`
	Confidence    int       `json:"confidence"`
	Source        string    `json:"source"` // stdout | stderr | details (first occurrence)
	OffsetStart   int       `json:"offsetStart"`
	OffsetEnd     int       `json:"offsetEnd"`
	TechniqueIDs  []string  `json:"techniqueIds"`
	SimulationIDs []string  `json:"simulationIds"`
	ExtractedAt   time.Time `json:"extractedAt,omitempty"` // set on DB read; zero on fresh extraction
}

type dedupKey struct {
	typ   string
	value string
}

// BuildRunIndicators walks every step's raw text in a fixed, deterministic
// order -- execResults in slice order (Stdout then Stderr for each), then
// checks in slice order (Details) -- and dedups matches into one
// RunIndicator per distinct (type, value) pair for the whole run.
// "First occurrence" for Source/OffsetStart/OffsetEnd means first in this
// walk order, not first by wall-clock time.
func BuildRunIndicators(
	execResults []scenario.ExecResult,
	checks []scenario.SimCheckResult,
	stepMap map[string]scenario.Step,
) []RunIndicator {
	byKey := make(map[dedupKey]*RunIndicator)
	var order []dedupKey

	add := func(ind Indicator, source, techniqueID, simulationID string) {
		key := dedupKey{typ: ind.Type, value: ind.Value}
		existing, found := byKey[key]
		if !found {
			existing = &RunIndicator{
				Type: ind.Type, Value: ind.Value, Algorithm: ind.Algorithm,
				Confidence: ind.Confidence, Source: source,
				OffsetStart: ind.OffsetStart, OffsetEnd: ind.OffsetEnd,
			}
			byKey[key] = existing
			order = append(order, key)
		}
		if techniqueID != "" && !containsStr(existing.TechniqueIDs, techniqueID) {
			existing.TechniqueIDs = append(existing.TechniqueIDs, techniqueID)
		}
		if simulationID != "" && !containsStr(existing.SimulationIDs, simulationID) {
			existing.SimulationIDs = append(existing.SimulationIDs, simulationID)
		}
	}

	for _, er := range execResults {
		techniqueID := stepMap[er.TaskID].TechniqueID
		for _, ind := range ExtractIndicators(er.Stdout) {
			add(ind, "stdout", techniqueID, er.TaskID)
		}
		for _, ind := range ExtractIndicators(er.Stderr) {
			add(ind, "stderr", techniqueID, er.TaskID)
		}
	}
	for _, ch := range checks {
		for _, ind := range ExtractIndicators(ch.Details) {
			add(ind, "details", ch.TechniqueID, ch.ID)
		}
	}

	out := make([]RunIndicator, 0, len(order))
	for _, key := range order {
		out = append(out, *byKey[key])
	}
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd orchestrator
go test ./internal/ioc/... -v
```
Expected: all `PASS` (both Task 1's and Task 2's tests).

- [ ] **Step 5: Run go vet**

```bash
cd orchestrator
go vet ./internal/ioc/...
```
Expected: no output.

- [ ] **Step 6: Commit**

```bash
git add orchestrator/internal/ioc/aggregate.go orchestrator/internal/ioc/aggregate_test.go
git commit -m "feat(ioc): aggregate extracted indicators per run with technique/simulation provenance"
```

---

### Task 3: Storage layer (`run_iocs` table)

**Files:**
- Create: `orchestrator/internal/db/ioc.go`
- Create: `orchestrator/internal/db/ioc_test.go`
- Modify: `orchestrator/internal/testutil/testdb.go:70-74` (add `EnsureIOCSchema` call to the test harness bootstrap)
- Modify: `orchestrator/cmd/server/main.go:83-85` (add `EnsureIOCSchema` call to server startup)

**Interfaces:**
- Consumes: `ioc.RunIndicator` (Task 2).
- Produces: `func EnsureIOCSchema(ctx context.Context, pool *pgxpool.Pool) error`, `func UpsertRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, scenarioID string, indicators []ioc.RunIndicator) error`, `func GetRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, typeFilter, search string) ([]ioc.RunIndicator, error)` — used by Task 4.

- [ ] **Step 1: Write the failing tests**

Create `orchestrator/internal/db/ioc_test.go`. This reuses the `sharedDB *testutil.TestDB` package var already declared in `orchestrator/internal/db/tenant_test.go` (same `db_test` package, same `TestMain` spins up a Docker Postgres container via testcontainers-go) — no new test-main needed.

```go
package db_test

import (
	"context"
	"testing"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ioc"
)

func TestUpsertAndGetRunIOCs_RoundTrip(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-roundtrip"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})

	indicators := []ioc.RunIndicator{
		{
			Type: "ip", Value: "45.33.32.156", Confidence: 95, Source: "stdout",
			OffsetStart: 10, OffsetEnd: 22,
			TechniqueIDs: []string{"T1071"}, SimulationIDs: []string{"T1071::A"},
		},
		{
			Type: "hash", Value: "44d88612fea8a8f36de82e1278abb02f", Algorithm: "md5",
			Confidence: 100, Source: "details", OffsetStart: 0, OffsetEnd: 32,
			TechniqueIDs: []string{"T1105"}, SimulationIDs: []string{"T1105::B"},
		},
	}

	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("UpsertRunIOCs: %v", err)
	}

	got, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "", "")
	if err != nil {
		t.Fatalf("GetRunIOCs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d indicators, want 2: %+v", len(got), got)
	}

	var ip *ioc.RunIndicator
	for i := range got {
		if got[i].Type == "ip" {
			ip = &got[i]
		}
	}
	if ip == nil {
		t.Fatal("no ip indicator returned")
	}
	if ip.Value != "45.33.32.156" || len(ip.TechniqueIDs) != 1 || ip.TechniqueIDs[0] != "T1071" {
		t.Errorf("got %+v", ip)
	}
	if ip.ExtractedAt.IsZero() {
		t.Error("ExtractedAt was not populated on read")
	}
}

func TestUpsertRunIOCs_ResubmissionReplaces(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-resubmit"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})

	first := []ioc.RunIndicator{{Type: "cve", Value: "CVE-2024-0001", Confidence: 100, Source: "details"}}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", first); err != nil {
		t.Fatalf("first UpsertRunIOCs: %v", err)
	}

	second := []ioc.RunIndicator{{Type: "cve", Value: "CVE-2024-9999", Confidence: 100, Source: "details"}}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", second); err != nil {
		t.Fatalf("second UpsertRunIOCs: %v", err)
	}

	got, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "", "")
	if err != nil {
		t.Fatalf("GetRunIOCs: %v", err)
	}
	if len(got) != 1 || got[0].Value != "CVE-2024-9999" {
		t.Fatalf("got %+v, want only the second submission's row (replace, not append)", got)
	}
}

func TestGetRunIOCs_TypeAndSearchFilters(t *testing.T) {
	ctx := context.Background()
	const runID = "test-run-ioc-filters"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID)
	})

	indicators := []ioc.RunIndicator{
		{Type: "ip", Value: "45.33.32.156", Confidence: 95, Source: "stdout"},
		{Type: "domain", Value: "evil.example.com", Confidence: 80, Source: "stdout"},
	}
	if err := db.UpsertRunIOCs(ctx, sharedDB.Pool, runID, "test-scenario", indicators); err != nil {
		t.Fatalf("UpsertRunIOCs: %v", err)
	}

	byType, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "domain", "")
	if err != nil {
		t.Fatalf("GetRunIOCs type filter: %v", err)
	}
	if len(byType) != 1 || byType[0].Type != "domain" {
		t.Fatalf("got %+v, want only the domain indicator", byType)
	}

	bySearch, err := db.GetRunIOCs(ctx, sharedDB.Pool, runID, "", "45.33")
	if err != nil {
		t.Fatalf("GetRunIOCs search filter: %v", err)
	}
	if len(bySearch) != 1 || bySearch[0].Value != "45.33.32.156" {
		t.Fatalf("got %+v, want only the matching ip", bySearch)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd orchestrator
go test ./internal/db/... -run TestUpsertAndGetRunIOCs -v
```
Expected: FAIL to compile — `undefined: db.UpsertRunIOCs` / `undefined: db.GetRunIOCs`. (Requires Docker running for the test to even reach that point; if `docker info` fails, start Docker Desktop first.)

- [ ] **Step 3: Write the schema + storage implementation**

Create `orchestrator/internal/db/ioc.go`:

```go
package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ioc"
)

// EnsureIOCSchema creates the run_iocs table. Idempotent -- safe to call on
// every startup.
func EnsureIOCSchema(ctx context.Context, pool *pgxpool.Pool) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS run_iocs (
			id               BIGSERIAL PRIMARY KEY,
			run_id           TEXT NOT NULL,
			scenario_id      TEXT NOT NULL,
			indicator_type   TEXT NOT NULL,
			indicator_value  TEXT NOT NULL,
			hash_algorithm   TEXT,
			confidence       SMALLINT NOT NULL,
			indicator_source TEXT NOT NULL,
			offset_start     INT NOT NULL,
			offset_end       INT NOT NULL,
			technique_ids    JSONB NOT NULL DEFAULT '[]',
			simulation_ids   JSONB NOT NULL DEFAULT '[]',
			extracted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE(run_id, indicator_type, indicator_value)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_run_iocs_run_id ON run_iocs(run_id)`,
		`CREATE INDEX IF NOT EXISTS idx_run_iocs_value ON run_iocs(indicator_type, indicator_value)`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			return fmt.Errorf("ioc schema: %w", err)
		}
	}
	return nil
}

// UpsertRunIOCs replaces the full set of extracted indicators for a run.
// Delete-then-insert (not a merge) mirrors the "agent always submits a
// complete snapshot" idempotency pattern SubmitScenarioResult already uses
// for scenario_runs itself -- a retried submission converges to the same
// row set instead of duplicating or double-merging arrays.
func UpsertRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, scenarioID string, indicators []ioc.RunIndicator) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("ioc upsert: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM run_iocs WHERE run_id = $1`, runID); err != nil {
		return fmt.Errorf("ioc upsert: delete: %w", err)
	}
	for _, ind := range indicators {
		techniqueIDsJSON, _ := json.Marshal(ind.TechniqueIDs)
		simulationIDsJSON, _ := json.Marshal(ind.SimulationIDs)
		var algo any
		if ind.Algorithm != "" {
			algo = ind.Algorithm
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO run_iocs
			 (run_id, scenario_id, indicator_type, indicator_value, hash_algorithm,
			  confidence, indicator_source, offset_start, offset_end, technique_ids, simulation_ids)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb)`,
			runID, scenarioID, ind.Type, ind.Value, algo,
			ind.Confidence, ind.Source, ind.OffsetStart, ind.OffsetEnd,
			techniqueIDsJSON, simulationIDsJSON,
		)
		if err != nil {
			return fmt.Errorf("ioc upsert: insert %s %s: %w", ind.Type, ind.Value, err)
		}
	}
	return tx.Commit(ctx)
}

// GetRunIOCs returns the extracted indicators for a run, optionally filtered
// by indicator type and/or a substring match against indicator_value.
func GetRunIOCs(ctx context.Context, pool *pgxpool.Pool, runID, typeFilter, search string) ([]ioc.RunIndicator, error) {
	query := `SELECT indicator_type, indicator_value, COALESCE(hash_algorithm, ''),
	                  confidence, indicator_source, offset_start, offset_end,
	                  technique_ids, simulation_ids, extracted_at
	           FROM run_iocs WHERE run_id = $1`
	args := []any{runID}
	if typeFilter != "" {
		args = append(args, typeFilter)
		query += fmt.Sprintf(" AND indicator_type = $%d", len(args))
	}
	if search != "" {
		args = append(args, "%"+search+"%")
		query += fmt.Sprintf(" AND indicator_value ILIKE $%d", len(args))
	}
	query += " ORDER BY id ASC"

	rows, err := pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("ioc get: query: %w", err)
	}
	defer rows.Close()

	out := make([]ioc.RunIndicator, 0)
	for rows.Next() {
		var ind ioc.RunIndicator
		var techniqueIDsJSON, simulationIDsJSON []byte
		if err := rows.Scan(&ind.Type, &ind.Value, &ind.Algorithm,
			&ind.Confidence, &ind.Source, &ind.OffsetStart, &ind.OffsetEnd,
			&techniqueIDsJSON, &simulationIDsJSON, &ind.ExtractedAt); err != nil {
			return nil, fmt.Errorf("ioc get: scan: %w", err)
		}
		_ = json.Unmarshal(techniqueIDsJSON, &ind.TechniqueIDs)
		_ = json.Unmarshal(simulationIDsJSON, &ind.SimulationIDs)
		out = append(out, ind)
	}
	return out, rows.Err()
}
```

- [ ] **Step 4: Wire schema bootstrap into the Docker-Postgres test harness**

In `orchestrator/internal/testutil/testdb.go`, find this block (around line 70-74):

```go
	if err := db.EnsureExerciseSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureExerciseSchema: %w", err)
	}

	return &TestDB{
```

Replace with:

```go
	if err := db.EnsureExerciseSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureExerciseSchema: %w", err)
	}
	if err := db.EnsureIOCSchema(ctx, pool); err != nil {
		pool.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("testutil: EnsureIOCSchema: %w", err)
	}

	return &TestDB{
```

- [ ] **Step 5: Wire schema bootstrap into server startup**

In `orchestrator/cmd/server/main.go`, find this block (around line 80-86):

```go
	if err := db.EnsureSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] schema bootstrap: %v", err)
	}
	if err := db.EnsureContentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] content schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

Replace with:

```go
	if err := db.EnsureSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] schema bootstrap: %v", err)
	}
	if err := db.EnsureContentSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] content schema bootstrap: %v", err)
	}
	if err := db.EnsureIOCSchema(context.Background(), pool); err != nil {
		log.Fatalf("[FATAL] ioc schema bootstrap: %v", err)
	}
	log.Println("[+] Schema verified")
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
cd orchestrator
docker info > /dev/null 2>&1 && echo "docker OK" || echo "START DOCKER DESKTOP FIRST"
go test ./internal/db/... -run TestUpsertAndGetRunIOCs -v
go test ./internal/db/... -run TestGetRunIOCs_TypeAndSearchFilters -v
```
Expected: all `PASS`. (First test run in this package will take ~10-20s longer while the Postgres container starts.)

- [ ] **Step 7: Run the full db package suite to confirm no regressions**

```bash
cd orchestrator
go test ./internal/db/... -v 2>&1 | tail -40
```
Expected: all tests `PASS`, including the pre-existing `TestGetFleetComplianceScores_PicksWorstAgentCoherently` and tenant/harden tests.

- [ ] **Step 8: Run go vet and build**

```bash
cd orchestrator
go vet ./internal/db/... ./internal/testutil/... ./cmd/server/...
go build ./...
```
Expected: no vet output, `BUILD` succeeds.

- [ ] **Step 9: Commit**

```bash
git add orchestrator/internal/db/ioc.go orchestrator/internal/db/ioc_test.go orchestrator/internal/testutil/testdb.go orchestrator/cmd/server/main.go
git commit -m "feat(ioc): add run_iocs table + UpsertRunIOCs/GetRunIOCs storage layer"
```

---

### Task 4: Wire extraction into result ingestion + expose read endpoint

**Files:**
- Modify: `orchestrator/internal/api/handlers.go:1896` (call `ioc.BuildRunIndicators` + `db.UpsertRunIOCs` inside `SubmitScenarioResult`)
- Create: `orchestrator/internal/api/ioc_handlers.go` (new `GetRunIOCs` HTTP handler)
- Modify: `orchestrator/internal/api/routes.go:128` (register the new route)

**Interfaces:**
- Consumes: `ioc.BuildRunIndicators` (Task 2), `db.UpsertRunIOCs`/`db.GetRunIOCs` (Task 3). `raw scenario.RawRunResult` and `stepMap map[string]scenario.Step` are already in scope in `SubmitScenarioResult` at the insertion point.
- Produces: `GET /api/scenarios/runs/{runId}/iocs` (query params `type`, `search`), consumable by sub-project C later.

- [ ] **Step 1: Add the extraction + persistence call to `SubmitScenarioResult`**

In `orchestrator/internal/api/handlers.go`, find this line (around line 1896):

```go
	h.persistVariantResults(r.Context(), raw.RunID, raw.ScenarioID, simResults, dispatchedMeta)
	// Pre-compute per-technique variant summary then, if the run belongs to a
```

Replace with:

```go
	h.persistVariantResults(r.Context(), raw.RunID, raw.ScenarioID, simResults, dispatchedMeta)

	// IOC extraction — parse stdout/stderr/details for indicators (IPs, domains,
	// URLs, hashes, CVEs). Non-fatal: extraction failure must not fail result
	// ingestion, since this is enrichment, not core scoring. Runs on partial
	// runs too — completed steps' output is still real evidence.
	indicators := ioc.BuildRunIndicators(raw.Results, raw.Checks, stepMap)
	if err := db.UpsertRunIOCs(r.Context(), h.db, raw.RunID, raw.ScenarioID, indicators); err != nil {
		log.Printf("[!] ioc extraction: failed to persist for run %s: %v", raw.RunID, err)
	}

	// Pre-compute per-technique variant summary then, if the run belongs to a
```

`ioc` and `db` are already imported in `handlers.go` (used by the existing `LookupIOC` handler and `db.GetFleetComplianceScores` respectively) — no import changes needed.

- [ ] **Step 2: Add the read handler**

Create `orchestrator/internal/api/ioc_handlers.go`:

```go
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/audspect/bas/internal/db"
)

// GetRunIOCs returns the indicators extracted from a run's results.
// GET /api/scenarios/runs/{runId}/iocs?type={ip|domain|url|hash|cve}&search={substring}
func (h *Handler) GetRunIOCs(w http.ResponseWriter, r *http.Request) {
	runID := chi.URLParam(r, "runId")
	typeFilter := r.URL.Query().Get("type")
	search := r.URL.Query().Get("search")

	indicators, err := db.GetRunIOCs(r.Context(), h.db, runID, typeFilter, search)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respond(w, indicators)
}
```

- [ ] **Step 3: Register the route**

In `orchestrator/internal/api/routes.go`, find this line (around line 128):

```go
		r.Get("/api/scenarios/runs/{runId}/forensic.csv", h.GetRunForensicCSV)
```

Add immediately after it:

```go
		r.Get("/api/scenarios/runs/{runId}/forensic.csv", h.GetRunForensicCSV)
		r.Get("/api/scenarios/runs/{runId}/iocs", h.GetRunIOCs)
```

This sits in the same JWT-only "Viewer+Analyst+Admin" group as `/report`, `/export`, `/events` — no new permission.

- [ ] **Step 4: Build and vet**

```bash
cd orchestrator
go build ./... && echo BUILD_OK
go vet ./... && echo VET_OK
```
Expected: `BUILD_OK`, `VET_OK`.

- [ ] **Step 5: Run the full relevant test suite**

```bash
cd orchestrator
go test ./internal/ioc/... ./internal/db/... ./internal/api/... 2>&1 | tail -30
```
Expected: all `ok`. (`internal/api` tests are Docker-Postgres-backed too — same `sharedDB` pattern via `testmain_test.go` — so Docker must be running.)

- [ ] **Step 6: Live end-to-end verification**

Start a throwaway Postgres container and the server (matching this session's established live-verification method):

```bash
docker run -d --name ioc-live-pg -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:16-alpine
sleep 3
cd orchestrator
DATABASE_URL="postgres://postgres:postgres@localhost:55432/postgres?sslmode=disable" \
JWT_SECRET="dev-secret" \
BAS_LICENSE_PATH="" \
HTTP_PORT="8099" \
go run ./cmd/server &
sleep 5
```

Seed a minimal agent + run row (the FK on `scenario_runs.agent_id` requires an existing agent):

```bash
docker exec -i ioc-live-pg psql -U postgres -c \
  "INSERT INTO agents (agent_id) VALUES ('test-agent-ioc');"
docker exec -i ioc-live-pg psql -U postgres -c \
  "INSERT INTO scenario_runs (id, scenario_id, agent_id, status) VALUES ('test-run-ioc-live', 'test-scenario', 'test-agent-ioc', 'running');"
```

Log in and submit a synthetic result containing a known indicator:

```bash
TOKEN=$(curl -s -X POST http://localhost:8099/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ChangeMe!2024"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

curl -s -X POST http://localhost:8099/api/scenarios/result \
  -H "Content-Type: application/json" \
  -d '{
    "runId": "test-run-ioc-live",
    "scenarioId": "test-scenario",
    "agentId": "test-agent-ioc",
    "results": [{
      "taskId": "T1071::live-test",
      "exitCode": 0,
      "stdout": "beacon to 45.33.32.156 then download http://evil.test/payload.exe",
      "stderr": "",
      "durationMs": 100,
      "executedAt": "2026-07-21T00:00:00Z"
    }]
  }'

curl -s http://localhost:8099/api/scenarios/runs/test-run-ioc-live/iocs \
  -H "Authorization: Bearer $TOKEN"
```

Expected: the last `curl` returns a JSON array with two entries — an `ip` (`45.33.32.156`, confidence 95) and a `url` (`http://evil.test/payload.exe`, confidence 100) — each with `techniqueIds` empty (no scenario step defines `T1071::live-test`, so `stepMap` lookup misses — expected per Task 2's `TestBuildRunIndicators_UnknownTaskIDNoTechnique`) and `simulationIds: ["T1071::live-test"]`.

Then filter:

```bash
curl -s "http://localhost:8099/api/scenarios/runs/test-run-ioc-live/iocs?type=url" \
  -H "Authorization: Bearer $TOKEN"
```
Expected: only the `url` entry.

Clean up:

```bash
kill %1 2>/dev/null
docker rm -f ioc-live-pg
```

- [ ] **Step 7: Commit**

```bash
git add orchestrator/internal/api/handlers.go orchestrator/internal/api/ioc_handlers.go orchestrator/internal/api/routes.go
git commit -m "feat(ioc): wire extraction into result ingestion + expose GET /api/scenarios/runs/{runId}/iocs"
```

---

## Final Verification (after all tasks)

- [ ] Run the complete suite once more and confirm nothing regressed:

```bash
cd orchestrator
go build ./... && echo BUILD_OK
go vet ./... && echo VET_OK
go test ./... 2>&1 | tail -60
```
Expected: `BUILD_OK`, `VET_OK`, all packages `ok`.

- [ ] Then proceed to **superpowers:finishing-a-development-branch** to wrap up.
