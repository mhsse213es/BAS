package attackdata

import (
	_ "embed"
	"encoding/json"
	"sync"
)

// attack_dataset_meta.json is written by the gen tool from the input STIX
// bundle itself (its x-mitre-collection object and a hash of its bytes).
//
//go:embed attack_dataset_meta.json
var rawDatasetMeta []byte

// Meta describes which ATT&CK release the embedded dataset was distilled
// from. Empty strings mean unknown; nothing here is ever inferred.
type Meta struct {
	AttackVersion      string // x_mitre_version of the bundle's collection, e.g. "16.1"
	Domain             string // e.g. "enterprise-attack"
	SourceBundleSHA256 string // sha256 of the exact bundle bytes the gen tool read
}

// Known reports whether the dataset's ATT&CK version is recorded.
func (m Meta) Known() bool { return m.AttackVersion != "" }

var (
	metaOnce sync.Once
	meta     Meta
)

// DatasetMeta returns the embedded dataset's provenance.
func DatasetMeta() Meta {
	metaOnce.Do(func() { meta = parseDatasetMeta(rawDatasetMeta) })
	return meta
}

func parseDatasetMeta(raw []byte) Meta {
	var m struct {
		AttackVersion      *string `json:"attack_version"`
		Domain             *string `json:"domain"`
		SourceBundleSHA256 string  `json:"source_bundle_sha256"`
	}
	if json.Unmarshal(raw, &m) != nil {
		return Meta{}
	}
	out := Meta{SourceBundleSHA256: m.SourceBundleSHA256}
	if m.AttackVersion != nil {
		out.AttackVersion = *m.AttackVersion
	}
	if m.Domain != nil {
		out.Domain = *m.Domain
	}
	return out
}
