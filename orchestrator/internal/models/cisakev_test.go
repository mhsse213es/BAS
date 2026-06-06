package models

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var cveIDRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// TestKEVMapWellFormed guards the curated CVE↔technique bridge: keys are
// uppercase base techniques, values are well-formed CVE IDs, and there are no
// empty lists or duplicates within a technique.
func TestKEVMapWellFormed(t *testing.T) {
	for tech, cves := range cvesByTechnique {
		if tech != strings.ToUpper(tech) {
			t.Errorf("technique key %q should be uppercase", tech)
		}
		if strings.Contains(tech, ".") {
			t.Errorf("technique key %q should be a base technique (no sub-technique suffix)", tech)
		}
		if len(cves) == 0 {
			t.Errorf("%s has an empty CVE list", tech)
		}
		seen := map[string]bool{}
		for _, c := range cves {
			if !cveIDRe.MatchString(c) {
				t.Errorf("%s maps to malformed CVE id %q", tech, c)
			}
			if seen[c] {
				t.Errorf("%s has duplicate CVE %q", tech, c)
			}
			seen[c] = true
		}
	}
}

func TestLookupCVEsResolvesSubtechniques(t *testing.T) {
	base := LookupCVEs("T1190")
	sub := LookupCVEs("T1190.001")
	if len(base) == 0 || len(sub) != len(base) {
		t.Fatalf("sub-technique should resolve to base mapping: base=%v sub=%v", base, sub)
	}

	// Spot-check well-known exploited CVEs.
	cases := map[string]string{
		"T1190": "CVE-2021-44228", // Log4Shell
		"T1210": "CVE-2020-1472",  // Zerologon
		"T1068": "CVE-2021-34527", // PrintNightmare
		"T1203": "CVE-2022-30190", // Follina
	}
	for tech, want := range cases {
		if !slices.Contains(LookupCVEs(tech), want) {
			t.Errorf("LookupCVEs(%s) = %v, want to include %s", tech, LookupCVEs(tech), want)
		}
	}

	if LookupCVEs("T9999") != nil {
		t.Errorf("unmapped technique should return nil")
	}
}
