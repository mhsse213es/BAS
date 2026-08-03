package endpointrisk

import (
	"embed"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed eol_catalog.yaml
var eolFS embed.FS

// CatalogEntry is one EOL/high-risk software record. Exported so callers
// (internal/api's applicationRiskInput) can read its fields directly.
type CatalogEntry struct {
	ID             string   `yaml:"id"`
	Vendor         string   `yaml:"vendor"`
	Product        string   `yaml:"product"`
	Match          []string `yaml:"match"`
	VersionMax     string   `yaml:"version_max,omitempty"`
	Risk           string   `yaml:"risk"` // critical | high | medium | low
	Reason         string   `yaml:"reason"`
	Recommendation string   `yaml:"recommendation"`
	Reference      string   `yaml:"reference,omitempty"`
}

type eolCatalogFile struct {
	Software []CatalogEntry `yaml:"software"`
}

// Catalog is a small, hand-curated, embedded list of well-known EOL/
// high-risk software (Flash, Java 6/7/8, Python 2, ...), matched against
// installed-software inventory by normalized-name substring. Deliberately
// not exhaustive -- see design spec §2d.
type Catalog struct {
	entries []CatalogEntry
}

// NewCatalog loads and validates the embedded eol_catalog.yaml.
func NewCatalog() (*Catalog, error) {
	data, err := eolFS.ReadFile("eol_catalog.yaml")
	if err != nil {
		return nil, fmt.Errorf("endpointrisk: read eol_catalog.yaml: %w", err)
	}
	var cf eolCatalogFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("endpointrisk: parse eol_catalog.yaml: %w", err)
	}
	seen := map[string]bool{}
	for _, e := range cf.Software {
		if e.ID == "" || len(e.Match) == 0 || e.Risk == "" {
			return nil, fmt.Errorf("endpointrisk: eol entry missing id/match/risk: %+v", e)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("endpointrisk: duplicate eol catalog id %q", e.ID)
		}
		seen[e.ID] = true
	}
	if len(cf.Software) == 0 {
		return nil, fmt.Errorf("endpointrisk: no eol catalog entries loaded")
	}
	return &Catalog{entries: cf.Software}, nil
}

// normalizeAppName lowercases and strips common marketing/vendor noise so
// "Java(TM) 8 Update 451" and "JRE 8" normalize close enough to match the
// same catalog entry's patterns.
func normalizeAppName(name string) string {
	n := strings.ToLower(name)
	for _, noise := range []string{"(tm)", "(r)", "®", "™"} {
		n = strings.ReplaceAll(n, noise, "")
	}
	return strings.Join(strings.Fields(n), " ")
}

// Lookup finds the first catalog entry whose match pattern is a
// case-insensitive substring of appName. When the entry declares
// version_max and appVersion parses as a leading integer, versions above
// version_max don't match (already-upgraded software isn't flagged) -- an
// unparseable version never blocks a match, it only sometimes prevents a
// false positive.
func (c *Catalog) Lookup(appName, appVersion string) (CatalogEntry, bool) {
	normalized := normalizeAppName(appName)
	for _, e := range c.entries {
		for _, m := range e.Match {
			if !strings.Contains(normalized, normalizeAppName(m)) {
				continue
			}
			if e.VersionMax != "" && !versionAtOrBelow(appVersion, e.VersionMax) {
				continue
			}
			return e, true
		}
	}
	return CatalogEntry{}, false
}

// versionAtOrBelow does simple leading-integer comparison only -- "8.0.451"
// vs version_max "8" compares 8 <= 8 -> true.
func versionAtOrBelow(installed, max string) bool {
	iv, iok := leadingInt(installed)
	mv, mok := leadingInt(max)
	if !iok || !mok {
		return true
	}
	return iv <= mv
}

func leadingInt(s string) (int, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(s[:end])
	return v, err == nil
}
