// Package attackdata provides per-technique threat-intelligence enrichment for
// reports. Two layers, kept strictly separate so the report never blurs them:
//
//   - Authoritative: distilled from the MITRE ATT&CK Enterprise STIX bundle by
//     the gen tool (threat-actor groups, associated software/malware, mitigations,
//     description, ATT&CK URL). These are facts published by MITRE.
//   - Curated: an analyst-maintained overlay (CVE/KEV/OWASP/CWE/notes). These have
//     no authoritative per-technique mapping, so they are explicitly illustrative
//     and labelled as such in the report — never auto-derived or fabricated.
//
// Both datasets are embedded so the deployed product stays fully offline.
package attackdata

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed attack_enrichment.json
var rawEnrichment []byte

//go:embed curated_overlay.json
var rawOverlay []byte

//go:embed technique_synonyms.json
var rawSynonyms []byte

//go:embed attack_groups.json
var rawGroups []byte

// Attribution is the MITRE ATT&CK attribution the report must display wherever
// ATT&CK-derived enrichment appears (MITRE's terms of use).
const Attribution = "Threat-intelligence context derived from MITRE ATT&CK®. © The MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation."

// Mitigation is an ATT&CK course-of-action recommended against a technique.
type Mitigation struct {
	Name        string `json:"name"`
	Description string `json:"desc,omitempty"`
}

// D3fendCM is a MITRE D3FEND defensive countermeasure mapped to an offensive
// ATT&CK technique. Authoritative — sourced from the MITRE D3FEND ATT&CK
// mappings at build time, never hand-derived.
type D3fendCM struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Group is one MITRE ATT&CK intrusion-set (threat-actor group), keyed by
// its canonical external ID (G####). Authoritative -- distilled from the
// same STIX bundle as technique enrichment, by the same gen tool. See
// docs/superpowers/specs/2026-08-11-canonical-mitre-actor-identity-design.md.
type Group struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
}

// Enrichment is the threat-intelligence context for one ATT&CK technique.
type Enrichment struct {
	// Authoritative (MITRE ATT&CK).
	TechniqueID string       `json:"id"`
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	URL         string       `json:"url,omitempty"`
	Tactics     []string     `json:"tactics,omitempty"`
	Groups      []string     `json:"groups,omitempty"`
	Software    []string     `json:"software,omitempty"`
	Mitigations []Mitigation `json:"mitigations,omitempty"`
	Detection   string       `json:"detection,omitempty"`

	// Authoritative ATT&CK technique metadata (from the STIX bundle, via gen).
	Version             string   `json:"version,omitempty"`     // x_mitre_version, e.g. "2.1"
	Created             string   `json:"created,omitempty"`     // YYYY-MM-DD
	Modified            string   `json:"modified,omitempty"`    // YYYY-MM-DD
	Platforms           []string `json:"platforms,omitempty"`   // x_mitre_platforms
	PermissionsRequired []string `json:"permissions,omitempty"` // x_mitre_permissions_required
	DataSources         []string `json:"dataSources,omitempty"` // x_mitre_data_sources
	CAPEC               []string `json:"capec,omitempty"`       // external_references (source_name "capec")

	// Authoritative, sourced from separate MITRE/community datasets at build time.
	D3FEND     []D3fendCM `json:"d3fend,omitempty"`     // MITRE D3FEND ATT&CK mappings
	SigmaRules int        `json:"sigmaRules,omitempty"` // SigmaHQ rules tagged for this technique

	// Curated overlay (illustrative, analyst-maintained — NOT authoritative).
	OWASP        []string `json:"owasp,omitempty"`
	CWE          []string `json:"cwe,omitempty"`
	CVEs         []string `json:"cves,omitempty"`
	KEV          bool     `json:"kev,omitempty"`
	AnalystNotes string   `json:"notes,omitempty"`
	Curated      bool     `json:"-"` // any curated field is set

	// Search-only synonym dictionary (technique_synonyms.json). Not ATT&CK
	// authoritative, not part of report enrichment — used solely by the
	// Scenario Builder's Technique Selector search matching.
	Aliases []string `json:"aliases,omitempty"`
}

// HasAuthoritative reports whether MITRE-derived enrichment exists.
func (e *Enrichment) HasAuthoritative() bool {
	return len(e.Groups) > 0 || len(e.Software) > 0 || len(e.Mitigations) > 0 ||
		e.Description != "" || len(e.DataSources) > 0 || len(e.D3FEND) > 0 ||
		len(e.CAPEC) > 0 || len(e.Platforms) > 0
}

// cvssRe extracts a CVSS base score embedded in a curated CVE string such as
// "CVE-2024-30088 (CVSS 7.8)".
var cvssRe = regexp.MustCompile(`(?i)CVSS\s*([0-9]{1,2}(?:\.[0-9])?)`)

// AvgCVSS averages the CVSS base scores the analyst recorded alongside the
// curated CVEs. It NEVER invents a score: only CVEs that carry an explicit
// "(CVSS x.x)" are counted, and it returns (0,0) when none do — so the report
// can omit the line rather than imply a severity that was never supplied.
func (e *Enrichment) AvgCVSS() (avg float64, n int) {
	var sum float64
	for _, c := range e.CVEs {
		m := cvssRe.FindStringSubmatch(c)
		if m == nil {
			continue
		}
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			sum += v
			n++
		}
	}
	if n == 0 {
		return 0, 0
	}
	return sum / float64(n), n
}

// dataSourceEventIDs maps an ATT&CK data component (matched as a lowercase
// substring) to the standard Windows telemetry that records it: Sysmon event IDs
// and Windows Event Log IDs. This is a fixed, documented reference table (Sysmon
// schema + Microsoft Windows Security/System auditing) — deterministic and
// factual, NOT a per-technique MITRE assertion. First match per data source wins
// the listed IDs; results are de-duplicated in first-seen order.
var dataSourceEventIDs = []struct {
	match string
	ids   []string
}{
	{"command execution", []string{"Sysmon 1", "Windows Security 4688", "PowerShell 4104"}},
	{"process creation", []string{"Sysmon 1", "Windows Security 4688"}},
	{"process termination", []string{"Sysmon 5"}},
	{"process access", []string{"Sysmon 10"}},
	{"os api execution", []string{"Sysmon 1", "Windows Security 4688"}},
	{"script", []string{"PowerShell 4104"}},
	{"network connection", []string{"Sysmon 3", "Windows Security 5156"}},
	{"network traffic", []string{"Sysmon 3", "Windows Security 5156"}},
	{"registry", []string{"Sysmon 12-14", "Windows Security 4657"}},
	{"module load", []string{"Sysmon 7"}},
	{"image load", []string{"Sysmon 7"}},
	{"driver", []string{"Sysmon 6"}},
	{"file creation", []string{"Sysmon 11"}},
	{"file modification", []string{"Sysmon 11"}},
	{"file deletion", []string{"Sysmon 23", "Sysmon 26"}},
	{"file access", []string{"Windows Security 4663"}},
	{"dns", []string{"Sysmon 22"}},
	{"named pipe", []string{"Sysmon 17", "Sysmon 18"}},
	{"wmi", []string{"Sysmon 19", "Sysmon 20", "Sysmon 21"}},
	{"service creation", []string{"System 7045", "Windows Security 4697"}},
	{"service modification", []string{"System 7040"}},
	{"scheduled job", []string{"Windows Security 4698"}},
	{"scheduled task", []string{"Windows Security 4698"}},
	{"logon", []string{"Windows Security 4624", "Windows Security 4625"}},
	{"user account", []string{"Windows Security 4720", "Windows Security 4726"}},
}

// DetectionEventIDs translates this technique's authoritative ATT&CK data
// sources into the concrete Windows telemetry (Sysmon + Windows Event Log) that
// records them, via dataSourceEventIDs. Returns nil when no data source maps.
func (e *Enrichment) DetectionEventIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, ds := range e.DataSources {
		low := strings.ToLower(ds)
		for _, row := range dataSourceEventIDs {
			if !strings.Contains(low, row.match) {
				continue
			}
			for _, id := range row.ids {
				if !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
		}
	}
	return out
}

type overlayEntry struct {
	OWASP []string `json:"owasp,omitempty"`
	CWE   []string `json:"cwe,omitempty"`
	CVEs  []string `json:"cves,omitempty"`
	KEV   bool     `json:"kev,omitempty"`
	Notes string   `json:"notes,omitempty"`
}

var (
	once sync.Once
	data map[string]*Enrichment
)

func load() {
	data = make(map[string]*Enrichment)
	var auth map[string]*Enrichment
	if json.Unmarshal(rawEnrichment, &auth) == nil {
		for k, v := range auth {
			data[normalize(k)] = v
		}
	}
	var ov map[string]overlayEntry
	if json.Unmarshal(rawOverlay, &ov) == nil {
		for k, o := range ov {
			if strings.HasPrefix(k, "_") { // documentation keys (e.g. _README)
				continue
			}
			key := normalize(k)
			e := data[key]
			if e == nil {
				e = &Enrichment{TechniqueID: key}
				data[key] = e
			}
			e.OWASP, e.CWE, e.CVEs, e.KEV, e.AnalystNotes = o.OWASP, o.CWE, o.CVEs, o.KEV, o.Notes
			e.Curated = len(o.OWASP)+len(o.CWE)+len(o.CVEs) > 0 || o.KEV || o.Notes != ""
		}
	}
	var syn map[string]json.RawMessage
	if json.Unmarshal(rawSynonyms, &syn) == nil {
		for k, raw := range syn {
			if strings.HasPrefix(k, "_") { // documentation keys (e.g. _README)
				continue
			}
			var aliases []string
			if json.Unmarshal(raw, &aliases) != nil {
				continue // malformed entry — skip rather than fail the whole load
			}
			key := normalize(k)
			e := data[key]
			if e == nil {
				e = &Enrichment{TechniqueID: key}
				data[key] = e
			}
			e.Aliases = aliases
		}
	}
}

// Lookup returns the enrichment for a technique ID (e.g. "T1059.001"), or nil.
// A sub-technique with no record of its own falls back to its parent technique
// so e.g. T1003.099 still surfaces T1003's actors and mitigations.
func Lookup(id string) *Enrichment {
	once.Do(load)
	key := normalize(id)
	if e := data[key]; e != nil {
		return e
	}
	if i := strings.IndexByte(key, '.'); i > 0 {
		if e := data[key[:i]]; e != nil {
			return e
		}
	}
	return nil
}

// TechniqueRef is the minimal matrix projection of a technique.
type TechniqueRef struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
}

// All returns every loaded technique (the authoritative ATT&CK set), id-sorted.
// Used to build the coverage matrix; coverage status is overlaid by the caller.
func All() []TechniqueRef {
	once.Do(load)
	out := make([]TechniqueRef, 0, len(data))
	for _, e := range data {
		if e == nil || e.TechniqueID == "" || e.Name == "" {
			continue
		}
		out = append(out, TechniqueRef{ID: e.TechniqueID, Name: e.Name, Tactics: e.Tactics})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

var (
	groupIdxOnce sync.Once
	groupIdx     map[string][]string // ATT&CK group name → []techniqueID
)

// GroupTechniqueIndex returns the inverted index: ATT&CK group name →
// slice of technique IDs that MITRE attributes to that group. Computed once
// from the embedded authoritative data; safe for concurrent reads after first call.
func GroupTechniqueIndex() map[string][]string {
	once.Do(load)
	groupIdxOnce.Do(func() {
		idx := make(map[string][]string, 200)
		for techID, e := range data {
			if e == nil {
				continue
			}
			for _, g := range e.Groups {
				idx[g] = append(idx[g], techID)
			}
		}
		groupIdx = idx
	})
	return groupIdx
}

// SubtechniqueCounts returns, for every parent technique ID present in the
// loaded set, the number of its loaded sub-techniques (IDs carrying it as a
// dot-prefix, e.g. "T1055" → count of "T1055.001", "T1055.012", ...). A
// technique with no sub-techniques is simply absent from the map — callers
// should treat a missing key as zero.
func SubtechniqueCounts() map[string]int {
	once.Do(load)
	counts := make(map[string]int)
	for id := range data {
		if i := strings.IndexByte(id, '.'); i > 0 {
			counts[id[:i]]++
		}
	}
	return counts
}

func normalize(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

var (
	groupsOnce sync.Once
	groups     []Group
)

func loadGroups() {
	_ = json.Unmarshal(rawGroups, &groups) // malformed/missing -> groups stays nil, callers see an empty dataset
}

// GroupByID returns the canonical MITRE group for an ATT&CK G#### id, or
// nil if unknown. Linear scan -- the embedded dataset is on the order of a
// few hundred groups at most, not a hot path.
func GroupByID(id string) *Group {
	groupsOnce.Do(loadGroups)
	for i := range groups {
		if groups[i].ID == id {
			return &groups[i]
		}
	}
	return nil
}

var (
	groupTokenIdxOnce sync.Once
	groupTokenIdx     map[string]string
)

// GroupCanonicalTokenIndex returns normalized-token -> G#### for every
// group name and alias in the embedded MITRE dataset. A token that maps to
// more than one distinct G#### in MITRE's own data is deliberately
// excluded (mapped to nothing) -- an ambiguous token must never resolve.
// Computed once (sync.Once) and cached; safe for concurrent reads.
func GroupCanonicalTokenIndex() map[string]string {
	groupsOnce.Do(loadGroups)
	groupTokenIdxOnce.Do(func() {
		groupTokenIdx = buildGroupCanonicalTokenIndex(groups)
	})
	return groupTokenIdx
}

// buildGroupCanonicalTokenIndex is the pure core of GroupCanonicalTokenIndex,
// kept separate so tests can exercise the ambiguous-token-exclusion logic
// against small fixture data without depending on the embedded dataset.
func buildGroupCanonicalTokenIndex(gs []Group) map[string]string {
	tokenToIDs := map[string]map[string]bool{}
	add := func(token, id string) {
		if token == "" {
			return
		}
		if tokenToIDs[token] == nil {
			tokenToIDs[token] = map[string]bool{}
		}
		tokenToIDs[token][id] = true
	}
	for _, g := range gs {
		if g.ID == "" {
			continue
		}
		add(normalizeGroupToken(g.Name), g.ID)
		for _, alias := range g.Aliases {
			add(normalizeGroupToken(alias), g.ID)
		}
	}
	idx := make(map[string]string, len(tokenToIDs))
	for token, ids := range tokenToIDs {
		if len(ids) != 1 {
			continue
		}
		for id := range ids {
			idx[token] = id
		}
	}
	return idx
}

// normalizeGroupToken applies the same normalization internal/connector's
// actorKey uses (lowercase, strip spaces and hyphens) so tokens compare
// equal across packages. Duplicated rather than shared because attackdata
// must not import connector (connector already imports attackdata).
func normalizeGroupToken(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", ""))
}
