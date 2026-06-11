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
//	  internal/reporting/attackdata/attack_enrichment.json
//
// Only authoritative, technique-keyed facts are emitted: threat-actor groups,
// associated software/malware, mitigations, detection guidance, description and
// the ATT&CK URL. CVE/KEV/OWASP/CWE are NOT derived here — they have no
// authoritative per-technique mapping and live in the analyst-maintained curated
// overlay instead.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Output schema — must match attackdata.Enrichment's authoritative json tags.
type mitigation struct {
	Name        string `json:"name"`
	Description string `json:"desc,omitempty"`
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
}

// STIX object (only the fields we need).
type stixObj struct {
	Type         string `json:"type"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Description  string `json:"description"`
	Revoked      bool   `json:"revoked"`
	Deprecated   bool   `json:"x_mitre_deprecated"`
	Detection    string `json:"x_mitre_detection"`
	ExternalRefs []struct {
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
		fmt.Fprintln(os.Stderr, "usage: gen <enterprise-attack.json> <out.json>")
		os.Exit(2)
	}
	inPath, outPath := os.Args[1], os.Args[2]

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
			for _, r := range o.ExternalRefs {
				if r.SourceName == "mitre-attack" && r.ExternalID != "" {
					extID, url = r.ExternalID, r.URL
					break
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
				TechniqueID: extID,
				Name:        o.Name,
				Description: trimText(o.Description, maxDescLen),
				URL:         url,
				Tactics:     tactics,
				Detection:   trimText(o.Detection, maxDetLen),
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

	out, err := json.MarshalIndent(techs, "", " ")
	must(err)
	must(os.WriteFile(outPath, out, 0o644))
	fmt.Printf("wrote %d techniques to %s (%d bytes)\n", len(techs), outPath, len(out))
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
