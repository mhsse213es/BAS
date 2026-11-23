package compliance

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// swiftCSCF2027IDs is the control list of SWIFT CSCF v2027 (10 July 2026), copied from the SWIFT PDF.
// An "A" suffix marks an Advisory control; the other 26 are Mandatory.
var swiftCSCF2027IDs = []string{
	"1.1", "1.2", "1.3", "1.4", "1.5",
	"2.1", "2.2", "2.3", "2.4", "2.5A", "2.6", "2.7", "2.8", "2.9", "2.10", "2.11A",
	"3.1",
	"4.1", "4.2",
	"5.1", "5.2", "5.3A", "5.4",
	"6.1", "6.2", "6.3", "6.4", "6.5A",
	"7.1", "7.2", "7.3A", "7.4A",
}

type swiftFile struct {
	ID       string `yaml:"id"`
	Controls []struct {
		ID         string   `yaml:"id"`
		Name       string   `yaml:"name"`
		Techniques []string `yaml:"techniques"`
	} `yaml:"controls"`
}

func TestSWIFTCSCF2027_MatchesPublishedControlList(t *testing.T) {
	m, err := NewMapper()
	if err != nil {
		t.Fatalf("NewMapper: %v", err)
	}
	var total int
	for _, fw := range m.Frameworks() {
		if fw.ID == "SWIFT_CSCF_2027" {
			total = fw.TotalControls
		}
	}
	if total != 32 {
		t.Fatalf("SWIFT_CSCF_2027 loaded with %d controls, want 32", total)
	}

	raw, err := os.ReadFile("mappings/swift_cscf.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fw swiftFile
	if err := yaml.Unmarshal(raw, &fw); err != nil {
		t.Fatal(err)
	}
	if len(fw.Controls) != len(swiftCSCF2027IDs) {
		t.Fatalf("file has %d controls, published list has %d", len(fw.Controls), len(swiftCSCF2027IDs))
	}
	advisory := 0
	for i, c := range fw.Controls {
		if c.ID != swiftCSCF2027IDs[i] {
			t.Errorf("control %d is %q, published list has %q", i, c.ID, swiftCSCF2027IDs[i])
		}
		isAdvisory := strings.HasSuffix(c.ID, "A")
		if isAdvisory {
			advisory++
		}
		if isAdvisory != strings.Contains(c.Name, "(Advisory)") {
			t.Errorf("control %s: advisory suffix and name disagree on type (%q)", c.ID, c.Name)
		}
	}
	if advisory != 6 {
		t.Errorf("%d advisory controls, published v2027 has 6", advisory)
	}
}

func TestSWIFTCSCF2027_TechniquesExistInATTACKData(t *testing.T) {
	raw, err := os.ReadFile("mappings/swift_cscf.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fw swiftFile
	if err := yaml.Unmarshal(raw, &fw); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../reporting/attackdata/attack_enrichment.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fw.Controls {
		if len(c.Techniques) == 0 {
			t.Errorf("control %s has no techniques", c.ID)
		}
		for _, tid := range c.Techniques {
			if !strings.Contains(string(data), `"`+tid+`"`) {
				t.Errorf("control %s: technique %s not found in ATT&CK data", c.ID, tid)
			}
		}
	}
}
