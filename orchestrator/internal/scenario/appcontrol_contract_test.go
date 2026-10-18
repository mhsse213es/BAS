package scenario

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var contractFamilyRe = regexp.MustCompile(`APPCTL_FAMILY: ([a-z_]+)`)

// contractFields are the labels every family contract must carry.
var contractFields = []string{
	"Control under test", "Technique", "Prerequisites", "Expected-result source",
	"Expected outcome", "Evidence requirements", "Cleanup",
	"Unsupported conditions", "Known blind spots",
}

// TestAppControlContracts_EveryFamilyHasContract fails when a family the
// scenario emits has no contract section, or when a contract section is
// missing a required field. The families are read from the scenario itself,
// so a new family cannot ship without a contract.
func TestAppControlContracts_EveryFamilyHasContract(t *testing.T) {
	scenarioPath := filepath.Join("..", "..", "..", "scenarios", "appcontrol-efficacy.yaml")
	docPath := filepath.Join("..", "..", "..", "docs", "appcontrol-test-contracts.md")

	raw, err := os.ReadFile(scenarioPath)
	if err != nil {
		t.Fatalf("read scenario: %v", err)
	}
	doc, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("read contracts: %v", err)
	}

	families := map[string]bool{}
	for _, m := range contractFamilyRe.FindAllStringSubmatch(string(raw), -1) {
		families[m[1]] = true
	}
	if len(families) == 0 {
		t.Fatal("scenario emits no APPCTL_FAMILY markers; the check would be vacuous")
	}

	sections := splitContractSections(string(doc))

	for fam := range families {
		body, ok := sections[fam]
		if !ok {
			t.Errorf("family %s is emitted by the scenario but has no contract section", fam)
			continue
		}
		for _, field := range contractFields {
			if !strings.Contains(body, "**"+field) {
				t.Errorf("contract for %s is missing field %q", fam, field)
			}
		}
	}
	for name := range sections {
		if !families[name] {
			t.Errorf("contract section %s has no matching family in the scenario", name)
		}
	}
}

// splitContractSections returns each "## <family>" section body, keyed by the
// family name. Sections that are not family names are ignored.
func splitContractSections(doc string) map[string]string {
	out := map[string]string{}
	var name string
	var b strings.Builder
	flush := func() {
		if name != "" {
			out[name] = b.String()
		}
		b.Reset()
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.HasPrefix(line, "## ") {
			flush()
			heading := strings.TrimSpace(strings.TrimPrefix(line, "## "))
			if regexp.MustCompile(`^[a-z_]+$`).MatchString(heading) {
				name = heading
			} else {
				name = ""
			}
			continue
		}
		if name != "" {
			b.WriteString(line + "\n")
		}
	}
	flush()
	return out
}
