package reporting

import (
	"fmt"
	"sort"
	"strings"

	"github.com/audspect/bas/internal/reporting/attackdata"
)

// threatIntel renders the MITRE ATT&CK threat-intelligence context for one
// finding's technique: the threat actors and malware known to use it, the
// recommended mitigations, and the ATT&CK reference — turning a raw FAIL into
// "this is real adversary behaviour, used by X, mitigated by Y". Curated
// CVE/KEV/OWASP/CWE context is rendered in a clearly-labelled illustrative block
// so it is never mistaken for an authoritative per-technique mapping.
func (d *rpt) threatIntel(techID string) {
	e := attackdata.Lookup(techID)
	if e == nil || (!e.HasAuthoritative() && !e.Curated) {
		return
	}
	pdf := d.pdf
	d.ensure(12)
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 7.5)
	pdf.SetX(margin + 4)
	d.cellT(0, 4.4, "Threat Intelligence (MITRE ATT&CK)")
	pdf.Ln(4.2)

	if len(e.Groups) > 0 {
		d.tiLine("Known threat actors", strings.Join(capStr(e.Groups, 10), ", "), cInk)
	}
	if len(e.Software) > 0 {
		d.tiLine("Associated malware/tools", strings.Join(capStr(e.Software, 10), ", "), cInk)
	}
	if len(e.Mitigations) > 0 {
		names := make([]string, 0, len(e.Mitigations))
		for _, m := range e.Mitigations {
			names = append(names, m.Name)
		}
		d.tiLine("Mitigations (ATT&CK)", strings.Join(capStr(names, 6), "; "), cInk)
	}
	if e.URL != "" {
		d.tiLine("ATT&CK reference", e.URL, cAccent)
	}

	if e.Curated {
		var parts []string
		if len(e.CWE) > 0 {
			parts = append(parts, "CWE: "+strings.Join(e.CWE, ", "))
		}
		if len(e.CVEs) > 0 {
			parts = append(parts, "CVEs: "+strings.Join(e.CVEs, ", "))
		}
		if e.KEV {
			parts = append(parts, "CISA KEV: listed")
		}
		if len(e.OWASP) > 0 {
			parts = append(parts, "OWASP: "+strings.Join(e.OWASP, ", "))
		}
		if len(parts) > 0 {
			d.tiLine("Illustrative (analyst-curated, not authoritative)", strings.Join(parts, "   ·   "), cMuted)
		}
		if e.AnalystNotes != "" {
			d.tiLine("Analyst note", e.AnalystNotes, cMuted)
		}
	}
	pdf.Ln(0.5)
}

// tiLine renders one indented "label: value" line inside a threat-intel block.
func (d *rpt) tiLine(label, val string, valCol rgb) {
	pdf := d.pdf
	d.ensure(6)
	y := pdf.GetY()
	d.text(cMuted)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetXY(margin+6, y)
	d.cellT(40, 4, label)
	d.text(valCol)
	pdf.SetFont("Helvetica", "", 7.5)
	pdf.SetX(margin + 48)
	d.mcellT(contentW-48, 4, val, "", "L", false)
}

// knowledgeGraph renders the adversary roll-up the ART review asked for: which
// threat actors and malware are known to use the techniques that went
// unprevented in this run, ranked by how many of those techniques they cover.
// This is the graph relationship (findings → techniques → actors/malware) in the
// tabular form a PDF supports; it answers "which threat actors can exploit these
// gaps?" from authoritative ATT&CK data only.
func (d *rpt) knowledgeGraph(rep *FullReport) {
	if len(rep.TopFindings) == 0 {
		return
	}
	actors := map[string]map[string]bool{}
	malware := map[string]map[string]bool{}
	add := func(m map[string]map[string]bool, name, tech string) {
		if m[name] == nil {
			m[name] = map[string]bool{}
		}
		m[name][tech] = true
	}
	for _, f := range rep.TopFindings {
		e := attackdata.Lookup(f.TechniqueID)
		if e == nil {
			continue
		}
		for _, g := range e.Groups {
			add(actors, g, f.TechniqueID)
		}
		for _, s := range e.Software {
			add(malware, s, f.TechniqueID)
		}
	}
	if len(actors) == 0 && len(malware) == 0 {
		return
	}

	pdf := d.pdf
	d.ensure(20)
	d.separator()
	d.text(cNavy)
	pdf.SetFont("Helvetica", "B", 9.5)
	pdf.SetX(margin)
	d.cellT(0, 5, "Adversary Knowledge Graph")
	pdf.Ln(5.2)
	d.text(cMuted)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetX(margin)
	d.mcellT(contentW, 4, "Threat actors and malware known (per MITRE ATT&CK) to use the techniques that went unprevented in this run, ranked by how many of those techniques they cover — the real-world adversaries these gaps expose you to.", "", "L", false)
	pdf.Ln(1.5)

	if rows := rankCoverage(actors, 8); len(rows) > 0 {
		d.kgGroup("Threat actors that use these techniques", rows)
	}
	if rows := rankCoverage(malware, 8); len(rows) > 0 {
		d.kgGroup("Malware / tools that implement these techniques", rows)
	}

	d.text(cMuted)
	pdf.SetFont("Helvetica", "I", 6.5)
	pdf.SetX(margin)
	d.mcellT(contentW, 3.4, attackdata.Attribution, "", "L", false)
	pdf.Ln(1)
}

type kgRow struct {
	name  string
	techs []string
}

// rankCoverage sorts names by coverage (descending), then alphabetically, and
// caps to n.
func rankCoverage(m map[string]map[string]bool, n int) []kgRow {
	rows := make([]kgRow, 0, len(m))
	for name, set := range m {
		techs := make([]string, 0, len(set))
		for t := range set {
			techs = append(techs, t)
		}
		sort.Strings(techs)
		rows = append(rows, kgRow{name: name, techs: techs})
	}
	sort.Slice(rows, func(i, j int) bool {
		if len(rows[i].techs) != len(rows[j].techs) {
			return len(rows[i].techs) > len(rows[j].techs)
		}
		return rows[i].name < rows[j].name
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

func (d *rpt) kgGroup(title string, rows []kgRow) {
	pdf := d.pdf
	d.ensure(8)
	d.text(cInk)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetX(margin + 2)
	d.cellT(0, 4.4, title)
	pdf.Ln(4.4)
	for _, r := range rows {
		d.ensure(5.5)
		y := pdf.GetY()
		d.text(cNavy)
		pdf.SetFont("Helvetica", "B", 7.5)
		pdf.SetXY(margin+6, y)
		d.cellT(46, 4, r.name)
		d.text(cMuted)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetX(margin + 54)
		d.mcellT(contentW-54, 4, fmt.Sprintf("%d technique(s): %s", len(r.techs), strings.Join(r.techs, ", ")), "", "L", false)
	}
	pdf.Ln(1)
}

// capStr caps a slice for display, appending "+N more" when truncated.
func capStr(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string{}, in[:n]...)
	return append(out, fmt.Sprintf("+%d more", len(in)-n))
}
