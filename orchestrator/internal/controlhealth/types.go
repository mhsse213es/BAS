package controlhealth

// CategoryDef is one control category — the unit executives and auditors
// think in (Endpoint Protection, Identity & Access, ...), as opposed to the
// technical data sources internal/analytics is organized around today.
type CategoryDef struct {
	ID   string `yaml:"id" json:"id"`
	Name string `yaml:"name" json:"name"`
}

// techniqueMapping is one curated YAML entry: an ATT&CK base technique ID
// (no sub-technique suffix) plus the one category it primarily validates and
// any number of categories it also touches. A technique often validates
// multiple controls (T1059 PowerShell touches Endpoint Protection,
// Application Control, and Detection & Response) — forcing a single category
// per technique would make the health model dependent on arbitrary curation
// calls, so both primary and secondary are preserved. Executive health
// rollup (ComputeSummary, Task 4) reads primary only; secondary is stored
// for future drill-down consumers.
type techniqueMapping struct {
	ID        string   `yaml:"id"`
	Primary   string   `yaml:"primary"`
	Secondary []string `yaml:"secondary"`
}

// taxonomyFile is the full parsed shape of categories.yaml.
type taxonomyFile struct {
	Categories []CategoryDef      `yaml:"categories"`
	Techniques []techniqueMapping `yaml:"techniques"`
}
