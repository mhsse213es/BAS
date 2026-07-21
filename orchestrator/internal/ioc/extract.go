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
