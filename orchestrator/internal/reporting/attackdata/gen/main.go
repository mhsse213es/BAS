// Command gen distills the MITRE ATT&CK Enterprise STIX bundle into the compact
// per-technique enrichment dataset embedded by the attackdata package.
//
// It is a BUILD-TIME tool, not part of the server. Run it on a host with the
// STIX bundle present (the deployed product stays air-gapped — only the distilled
// JSON ships):
//
//	curl -L -o enterprise-attack.json \
//	  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
//	go run ./internal/reporting/attackdata/gen enterprise-attack.json \
//	  internal/reporting/attackdata/attack_enrichment.json \
//	  [--d3fend=d3fend-attack-map.json] [--sigma=path/to/sigma/rules]
//
// Authoritative, technique-keyed facts emitted from the STIX bundle: threat-actor
// groups, associated software/malware, mitigations, detection guidance,
// description, ATT&CK URL, technique version/created/modified, platforms,
// permissions required, data sources, and CAPEC ids.
//
// Optional authoritative side-inputs (empty when omitted — never fabricated):
//   - --d3fend=FILE : a normalized export of the MITRE D3FEND ATT&CK mappings,
//     shaped {"T1548.002":[{"id":"D3-EAL","name":"Executable Allowlisting"}]}.
//   - --sigma=DIR   : the SigmaHQ rules tree; rules are counted per technique by
//     their `attack.t####` tags.
//
// CVE/KEV/OWASP/CWE/CVSS are NOT derived here — they have no authoritative
// per-technique mapping and live in the analyst-maintained curated overlay.
package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Output schema — must match attackdata.Enrichment's authoritative json tags.
type mitigation struct {
	Name        string `json:"name"`
	Description string `json:"desc,omitempty"`
}

type d3fendCM struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type enrichment struct {
	TechniqueID string       `json:"id"`
	Name        string       `json:"name,omitempty"`
	Description string       `json:"description,omitempty"`
	URL         string       `json:"url,omitempty"`
	Tactics     []string     `json:"tactics,omitempty"`
	Groups      []string     `json:"groups,omitempty"`
	Software    []string     `json:"software,omitempty"`
	Mitigations []mitigation `json:"mitigations,omitempty"`
	Detection   string       `json:"detection,omitempty"`

	Version             string     `json:"version,omitempty"`
	Created             string     `json:"created,omitempty"`
	Modified            string     `json:"modified,omitempty"`
	Platforms           []string   `json:"platforms,omitempty"`
	PermissionsRequired []string   `json:"permissions,omitempty"`
	DataSources         []string   `json:"dataSources,omitempty"`
	CAPEC               []string   `json:"capec,omitempty"`
	D3FEND              []d3fendCM `json:"d3fend,omitempty"`
	SigmaRules          int        `json:"sigmaRules,omitempty"`
}

// STIX object (only the fields we need).
type stixObj struct {
	Type                string   `json:"type"`
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	Revoked             bool     `json:"revoked"`
	Deprecated          bool     `json:"x_mitre_deprecated"`
	Detection           string   `json:"x_mitre_detection"`
	Created             string   `json:"created"`
	Modified            string   `json:"modified"`
	MitreVersion        string   `json:"x_mitre_version"`
	Platforms           []string `json:"x_mitre_platforms"`
	PermissionsRequired []string `json:"x_mitre_permissions_required"`
	DataSources         []string `json:"x_mitre_data_sources"`
	ExternalRefs        []struct {
		SourceName string `json:"source_name"`
		ExternalID string `json:"external_id"`
		URL        string `json:"url"`
	} `json:"external_references"`
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases"`
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"`
	TargetRef        string `json:"target_ref"`
}

type bundle struct {
	Objects []stixObj `json:"objects"`
}

const (
	maxGroups   = 15
	maxSoftware = 15
	maxMitig    = 8
	maxDescLen  = 600
	maxDetLen   = 600
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: gen <enterprise-attack.json> <out.json> [--d3fend=FILE] [--sigma=DIR]")
		os.Exit(2)
	}
	inPath, outPath := os.Args[1], os.Args[2]
	var d3fendPath, sigmaPath string
	for _, a := range os.Args[3:] {
		switch {
		case strings.HasPrefix(a, "--d3fend="):
			d3fendPath = strings.TrimPrefix(a, "--d3fend=")
		case strings.HasPrefix(a, "--sigma="):
			sigmaPath = strings.TrimPrefix(a, "--sigma=")
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %q\n", a)
			os.Exit(2)
		}
	}

	raw, err := os.ReadFile(inPath)
	must(err)
	var b bundle
	must(json.Unmarshal(raw, &b))

	// Index by STIX id, and build technique records keyed by ATT&CK external id.
	stixToExt := map[string]string{} // attack-pattern STIX id -> T####
	techs := map[string]*enrichment{}
	names := map[string]string{} // intrusion-set/malware/tool/course-of-action STIX id -> name
	mitigDesc := map[string]string{}
	srcType := map[string]string{} // STIX id -> type (for relationship classification)

	for i := range b.Objects {
		o := &b.Objects[i]
		srcType[o.ID] = o.Type
		switch o.Type {
		case "attack-pattern":
			if o.Revoked || o.Deprecated {
				continue
			}
			extID, url := "", ""
			var capec []string
			for _, r := range o.ExternalRefs {
				if r.SourceName == "mitre-attack" && r.ExternalID != "" {
					extID, url = r.ExternalID, r.URL
				}
				if r.SourceName == "capec" && r.ExternalID != "" {
					capec = append(capec, r.ExternalID)
				}
			}
			if extID == "" {
				continue
			}
			var tactics []string
			for _, kc := range o.KillChainPhases {
				if kc.KillChainName == "mitre-attack" {
					tactics = append(tactics, kc.PhaseName)
				}
			}
			stixToExt[o.ID] = extID
			techs[extID] = &enrichment{
				TechniqueID:         extID,
				Name:                o.Name,
				Description:         trimText(o.Description, maxDescLen),
				URL:                 url,
				Tactics:             tactics,
				Detection:           trimText(o.Detection, maxDetLen),
				Version:             o.MitreVersion,
				Created:             isoDate(o.Created),
				Modified:            isoDate(o.Modified),
				Platforms:           o.Platforms,
				PermissionsRequired: o.PermissionsRequired,
				DataSources:         dedupeSort(o.DataSources),
				CAPEC:               dedupeSort(capec),
			}
		case "intrusion-set", "malware", "tool":
			names[o.ID] = o.Name
		case "course-of-action":
			names[o.ID] = o.Name
			mitigDesc[o.ID] = trimText(o.Description, 200)
		}
	}

	// Second pass: relationships attach groups, software and mitigations.
	for i := range b.Objects {
		o := &b.Objects[i]
		if o.Type != "relationship" {
			continue
		}
		extID, ok := stixToExt[o.TargetRef]
		if !ok {
			continue
		}
		t := techs[extID]
		if t == nil {
			continue
		}
		switch o.RelationshipType {
		case "uses":
			src := names[o.SourceRef]
			if src == "" {
				continue
			}
			switch srcType[o.SourceRef] {
			case "intrusion-set":
				t.Groups = append(t.Groups, src)
			case "malware", "tool":
				t.Software = append(t.Software, src)
			}
		case "mitigates":
			if srcType[o.SourceRef] == "course-of-action" {
				if n := names[o.SourceRef]; n != "" {
					t.Mitigations = append(t.Mitigations, mitigation{Name: n, Description: mitigDesc[o.SourceRef]})
				}
			}
		}
	}

	// Normalise: dedupe, sort, cap.
	for _, t := range techs {
		t.Groups = capList(dedupeSort(t.Groups), maxGroups)
		t.Software = capList(dedupeSort(t.Software), maxSoftware)
		t.Mitigations = capMitig(dedupeMitig(t.Mitigations), maxMitig)
	}

	// Authoritative side-inputs (optional, never fabricated).
	if d3fendPath != "" {
		m := loadD3fend(d3fendPath)
		n := 0
		for id, cms := range m {
			if t := techs[strings.ToUpper(id)]; t != nil {
				t.D3FEND = cms
				n++
			}
		}
		fmt.Printf("merged D3FEND countermeasures for %d techniques from %s\n", n, d3fendPath)
	}
	if sigmaPath != "" {
		counts := countSigma(sigmaPath)
		n := 0
		for id, c := range counts {
			if t := techs[strings.ToUpper(id)]; t != nil {
				t.SigmaRules = c
				n++
			}
		}
		fmt.Printf("counted SigmaHQ rules for %d techniques from %s\n", n, sigmaPath)
	}

	out, err := json.MarshalIndent(techs, "", " ")
	must(err)
	must(os.WriteFile(outPath, out, 0o644))
	fmt.Printf("wrote %d techniques to %s (%d bytes)\n", len(techs), outPath, len(out))
}

// isoDate reduces a STIX timestamp ("2017-12-14T16:46:06.044Z") to its date
// (YYYY-MM-DD). Returns "" when the input is empty or too short.
func isoDate(ts string) string {
	if len(ts) < 10 {
		return ""
	}
	return ts[:10]
}

// loadD3fend reads a normalized MITRE D3FEND ATT&CK-mapping file shaped
// {"T1548.002":[{"id":"D3-EAL","name":"Executable Allowlisting"}]}.
func loadD3fend(path string) map[string][]d3fendCM {
	raw, err := os.ReadFile(path)
	must(err)
	var m map[string][]d3fendCM
	must(json.Unmarshal(raw, &m))
	return m
}

// sigmaTagRe matches a SigmaHQ ATT&CK technique tag, e.g. "attack.t1548.002".
var sigmaTagRe = regexp.MustCompile(`(?i)attack\.(t\d{4}(?:\.\d{3})?)`)

// countSigma walks a SigmaHQ rules tree and counts, per ATT&CK technique, how
// many rule files carry that technique's tag. A rule counts once per technique
// even if the tag appears multiple times.
func countSigma(dir string) map[string]int {
	counts := map[string]int{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if ext := strings.ToLower(filepath.Ext(p)); ext != ".yml" && ext != ".yaml" {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil // skip unreadable rule, keep counting
		}
		seen := map[string]bool{}
		for _, m := range sigmaTagRe.FindAllStringSubmatch(string(raw), -1) {
			tech := strings.ToUpper(m[1])
			if !seen[tech] {
				seen[tech] = true
				counts[tech]++
			}
		}
		return nil
	})
	must(err)
	return counts
}

func trimText(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= max {
		return s
	}
	cut := s[:max]
	if i := strings.LastIndex(cut, ". "); i > max/2 {
		return cut[:i+1]
	}
	return cut + "…"
}

func dedupeSort(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func dedupeMitig(in []mitigation) []mitigation {
	seen := map[string]bool{}
	var out []mitigation
	for _, m := range in {
		if m.Name == "" || seen[m.Name] {
			continue
		}
		seen[m.Name] = true
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func capList(in []string, n int) []string {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func capMitig(in []mitigation, n int) []mitigation {
	if len(in) > n {
		return in[:n]
	}
	return in
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
