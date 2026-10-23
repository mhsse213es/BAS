package property

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nonTestSources returns the source of every non-test .go file in the package.
func nonTestSources() (map[string]string, error) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		out[f] = string(b)
	}
	return out, nil
}

func TestNoPropertyNamesBankResources(t *testing.T) {
	banned := []string{"beneficiary", "kyc", "settle", "ledger", "account number", "ifsc", "upi", "labels.json"}
	files, err := nonTestSources()
	if err != nil {
		t.Fatal(err)
	}
	for name, src := range files {
		low := strings.ToLower(src)
		for _, w := range banned {
			if strings.Contains(low, w) {
				t.Errorf("%s mentions %q", name, w)
			}
		}
	}
}

func TestAllListsPropertiesInSpecOrder(t *testing.T) {
	want := []string{"P-OWN-1", "P-OWN-2", "P-OWN-3", "P-ROLE-1", "P-ROLE-2", "P-AUTH-1", "P-AUTH-2", "P-MC-1",
		"P-IDEM-1", "P-IDEM-2", "P-STATE-1", "P-STATE-2", "P-RACE-1"}
	var got []string
	for _, p := range All() {
		got = append(got, p.ID())
		if p.Class() == "" {
			t.Errorf("%s has no class", p.ID())
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v want %v", got, want)
	}
}
