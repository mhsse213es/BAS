package reporting

import (
	"testing"

	"github.com/audspect/bas/internal/models"
)

// Benign harness chatter ("Hello from PowerShell", "operation completed
// successfully") carries no security meaning and must be suppressed from the
// Evidence line; genuinely informative output is kept. Applies to every framework.
func TestHumanizeEvidence(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"benign hello", "Hello from PowerShell", ""},
		{"benign success", "The operation completed successfully.", ""},
		{"empty", "", ""},
		{"informative error", "Access to the path 'C:\\secret' is denied", "Access to the path 'C:\\secret' is denied"},
		{"artifact path", "Wrote dump to C:\\Windows\\Temp\\lsass.dmp", "Wrote dump to C:\\Windows\\Temp\\lsass.dmp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := humanizeEvidence(models.SimulationResult{RawOutput: c.raw})
			if got != c.want {
				t.Errorf("humanizeEvidence(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestMaturityScore(t *testing.T) {
	cases := []struct {
		pct  int
		want int
	}{
		{0, 0}, {4, 0}, {5, 1}, {49, 5}, {50, 5}, {55, 6}, {95, 10}, {100, 10}, {120, 10},
	}
	for _, c := range cases {
		if got := maturityScore(c.pct); got != c.want {
			t.Errorf("maturityScore(%d) = %d, want %d", c.pct, got, c.want)
		}
	}
}

func TestAssetClass(t *testing.T) {
	cases := []struct{ os, want string }{
		{"Windows Server 2022 Standard", "Server (inferred from OS)"},
		{"Windows 11 Pro 23H2", "Workstation (inferred from OS)"},
		{"Ubuntu 22.04 LTS", "Endpoint (inferred from OS)"},
		{"", "—"},
	}
	for _, c := range cases {
		if got := assetClass(c.os); got != c.want {
			t.Errorf("assetClass(%q) = %q, want %q", c.os, got, c.want)
		}
	}
}

func TestBusinessCriticality(t *testing.T) {
	cases := []struct{ env, want string }{
		{"Production", "High — production endpoint"},
		{"prod-dc", "High — production endpoint"},
		{"Staging", "Standard — non-production"},
		{"", "Not classified"},
	}
	for _, c := range cases {
		if got := businessCriticality(c.env); got != c.want {
			t.Errorf("businessCriticality(%q) = %q, want %q", c.env, got, c.want)
		}
	}
}
