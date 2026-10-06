package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
)

// metaFileName is the dataset-metadata file written next to the data files.
// Output schema -- must match attackdata.DatasetMeta's json tags.
const metaFileName = "attack_dataset_meta.json"

// datasetMeta records which ATT&CK release the embedded dataset was
// distilled from. Every field comes from the input bundle itself: the
// version and name from its x-mitre-collection object, the hash from its
// bytes. A missing collection or version leaves AttackVersion null -- the
// file name and comments are never consulted.
type datasetMeta struct {
	AttackVersion      *string `json:"attack_version"`
	Domain             *string `json:"domain"`
	CollectionName     string  `json:"collection_name,omitempty"`
	CollectionID       string  `json:"collection_id,omitempty"`
	CollectionModified string  `json:"collection_modified,omitempty"`
	SourceBundleSHA256 string  `json:"source_bundle_sha256"`
}

type metaObj struct {
	Type     string   `json:"type"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Version  string   `json:"x_mitre_version"`
	Modified string   `json:"modified"`
	Domains  []string `json:"x_mitre_domains"`
}

// collectionDomains maps MITRE's collection names to their domain ids.
var collectionDomains = map[string]string{
	"Enterprise ATT&CK": "enterprise-attack",
	"Mobile ATT&CK":     "mobile-attack",
	"ICS ATT&CK":        "ics-attack",
}

func readDatasetMeta(path string) (datasetMeta, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return datasetMeta{}, err
	}
	return datasetMetaFromBytes(raw)
}

func datasetMetaFromBytes(raw []byte) (datasetMeta, error) {
	var b struct {
		Objects []metaObj `json:"objects"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		return datasetMeta{}, err
	}
	sum := sha256.Sum256(raw)
	m := datasetMeta{SourceBundleSHA256: hex.EncodeToString(sum[:])}

	// Domain fallback: the single domain every attack-pattern declares.
	common := map[string]int{}
	patterns := 0
	for _, o := range b.Objects {
		switch o.Type {
		case "x-mitre-collection":
			if m.CollectionID != "" {
				continue // first collection object wins; bundles carry one
			}
			m.CollectionID, m.CollectionName, m.CollectionModified = o.ID, o.Name, o.Modified
			if o.Version != "" {
				v := o.Version
				m.AttackVersion = &v
			}
		case "attack-pattern":
			patterns++
			for _, d := range o.Domains {
				common[d]++
			}
		}
	}
	if d, ok := collectionDomains[m.CollectionName]; ok {
		m.Domain = &d
	} else {
		var only []string
		for d, n := range common {
			if n == patterns {
				only = append(only, d)
			}
		}
		if patterns > 0 && len(only) == 1 {
			m.Domain = &only[0]
		}
	}
	return m, nil
}

func writeDatasetMeta(m datasetMeta, path string) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // Encode appends the trailing newline
	enc.SetEscapeHTML(false)     // keep "ATT&CK" readable
	enc.SetIndent("", " ")
	if err := enc.Encode(m); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}
