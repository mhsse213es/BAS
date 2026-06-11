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
	"strings"
	"sync"
)

//go:embed attack_enrichment.json
var rawEnrichment []byte

//go:embed curated_overlay.json
var rawOverlay []byte

// Attribution is the MITRE ATT&CK attribution the report must display wherever
// ATT&CK-derived enrichment appears (MITRE's terms of use).
const Attribution = "Threat-intelligence context derived from MITRE ATT&CK®. © The MITRE Corporation. ATT&CK® is a registered trademark of The MITRE Corporation."

// Mitigation is an ATT&CK course-of-action recommended against a technique.
type Mitigation struct {
	Name        string `json:"name"`
	Description string `json:"desc,omitempty"`
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

	// Curated overlay (illustrative, analyst-maintained — NOT authoritative).
	OWASP        []string `json:"owasp,omitempty"`
	CWE          []string `json:"cwe,omitempty"`
	CVEs         []string `json:"cves,omitempty"`
	KEV          bool     `json:"kev,omitempty"`
	AnalystNotes string   `json:"notes,omitempty"`
	Curated      bool     `json:"-"` // any curated field is set
}

// HasAuthoritative reports whether MITRE-derived enrichment exists.
func (e *Enrichment) HasAuthoritative() bool {
	return len(e.Groups) > 0 || len(e.Software) > 0 || len(e.Mitigations) > 0 || e.Description != ""
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

func normalize(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}
