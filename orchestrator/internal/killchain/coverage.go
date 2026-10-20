package killchain

import (
	"fmt"
	"sort"
)

// Maturity is how far a scenario has been validated. The levels are ordered.
// A scenario has one level: the highest one whose evidence is present.
type Maturity int

const (
	MaturityCataloged Maturity = iota
	MaturityFixtureTested
	MaturityAdapterTested
	MaturityLabValidated
	MaturityLiveValidated
)

// String returns the reporting label for a level.
func (m Maturity) String() string {
	switch m {
	case MaturityCataloged:
		return "cataloged"
	case MaturityFixtureTested:
		return "fixture-tested"
	case MaturityAdapterTested:
		return "adapter-tested"
	case MaturityLabValidated:
		return "lab-validated"
	case MaturityLiveValidated:
		return "live-validated"
	}
	return "unknown"
}

// Proof names the evidence behind each level. A level is reached only when its
// reference is non-empty. A declared level is never trusted on its own.
type Proof struct {
	// CatalogEntry: the scenario is defined and signed.
	CatalogEntry bool `json:"catalogEntry"`
	// FixtureTestID: a deterministic fixture test covers the scenario's logic.
	FixtureTestID string `json:"fixtureTestId,omitempty"`
	// AdapterTestID: an adapter test covers integration and evidence handling.
	AdapterTestID string `json:"adapterTestId,omitempty"`
	// LabRunID: a lab run record with ground truth, from a controlled environment.
	LabRunID string `json:"labRunId,omitempty"`
	// LiveRunID: an authorised run record against the supported product.
	LiveRunID string `json:"liveRunId,omitempty"`
}

// Level derives the maturity from the proof. It stops at the first missing
// level, so a live run with no lab run still reports the lower level it can prove.
func (p Proof) Level() Maturity {
	level := MaturityCataloged
	if !p.CatalogEntry {
		return level
	}
	if p.FixtureTestID != "" {
		level = MaturityFixtureTested
	} else {
		return level
	}
	if p.AdapterTestID != "" {
		level = MaturityAdapterTested
	} else {
		return level
	}
	if p.LabRunID != "" {
		level = MaturityLabValidated
	} else {
		return level
	}
	if p.LiveRunID != "" {
		level = MaturityLiveValidated
	}
	return level
}

// Entry is one scenario's coverage, placed on each reporting dimension.
type Entry struct {
	ScenarioID string `json:"scenarioId"`
	Domain     string `json:"domain"`
	Platform   string `json:"platform"`
	Control    string `json:"control"`
	Campaign   string `json:"campaign"`
	// Unsupported: the product, platform or evidence source is not available here.
	// It is reported as a count, never as coverage.
	Unsupported bool  `json:"unsupported,omitempty"`
	Proof       Proof `json:"proof"`
}

// Counts holds how many entries sit at each level, plus the unsupported count.
// It contains no percentage, because a combined figure would hide the levels.
type Counts struct {
	Cataloged     int `json:"cataloged"`
	FixtureTested int `json:"fixtureTested"`
	AdapterTested int `json:"adapterTested"`
	LabValidated  int `json:"labValidated"`
	LiveValidated int `json:"liveValidated"`
	Unsupported   int `json:"unsupported"`
	Total         int `json:"total"`
}

func (c *Counts) add(e Entry) {
	c.Total++
	if e.Unsupported {
		c.Unsupported++
		return
	}
	switch e.Proof.Level() {
	case MaturityCataloged:
		c.Cataloged++
	case MaturityFixtureTested:
		c.FixtureTested++
	case MaturityAdapterTested:
		c.AdapterTested++
	case MaturityLabValidated:
		c.LabValidated++
	case MaturityLiveValidated:
		c.LiveValidated++
	}
}

// Row is one line of a dimension table.
type Row struct {
	Name   string `json:"name"`
	Counts Counts `json:"counts"`
}

// Report is the coverage report, one table per dimension.
type Report struct {
	Domains   []Row  `json:"domains"`
	Platforms []Row  `json:"platforms"`
	Controls  []Row  `json:"controls"`
	Campaigns []Row  `json:"campaigns"`
	Overall   Counts `json:"overall"`
}

// Build produces the report. Every dimension is a separate table, sorted by name,
// so the output is stable. An entry with no domain, platform, control or
// campaign is grouped under "unassigned" rather than dropped.
func Build(entries []Entry) Report {
	var r Report
	r.Domains = table(entries, func(e Entry) string { return e.Domain })
	r.Platforms = table(entries, func(e Entry) string { return e.Platform })
	r.Controls = table(entries, func(e Entry) string { return e.Control })
	r.Campaigns = table(entries, func(e Entry) string { return e.Campaign })
	for _, e := range entries {
		r.Overall.add(e)
	}
	return r
}

func table(entries []Entry, key func(Entry) string) []Row {
	by := map[string]*Counts{}
	for _, e := range entries {
		k := key(e)
		if k == "" {
			k = "unassigned"
		}
		if by[k] == nil {
			by[k] = &Counts{}
		}
		by[k].add(e)
	}
	names := make([]string, 0, len(by))
	for n := range by {
		names = append(names, n)
	}
	sort.Strings(names)
	rows := make([]Row, 0, len(names))
	for _, n := range names {
		rows = append(rows, Row{Name: n, Counts: *by[n]})
	}
	return rows
}

// Regressions compares two snapshots by scenario ID. It returns one message for
// each scenario whose level fell, or that disappeared. A scenario newly marked
// unsupported is also reported, because its coverage has been lost.
func Regressions(before, after []Entry) []string {
	now := map[string]Entry{}
	for _, e := range after {
		now[e.ScenarioID] = e
	}
	var out []string
	for _, b := range before {
		a, ok := now[b.ScenarioID]
		if !ok {
			out = append(out, fmt.Sprintf("%s: removed from coverage", b.ScenarioID))
			continue
		}
		if a.Unsupported && !b.Unsupported {
			out = append(out, fmt.Sprintf("%s: now unsupported", b.ScenarioID))
			continue
		}
		if a.Proof.Level() < b.Proof.Level() {
			out = append(out, fmt.Sprintf("%s: fell from %s to %s", b.ScenarioID, b.Proof.Level(), a.Proof.Level()))
		}
	}
	sort.Strings(out)
	return out
}
