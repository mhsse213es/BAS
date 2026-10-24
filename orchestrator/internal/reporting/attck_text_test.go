package reporting

import "testing"

func TestCleanATTCKText(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"markdown link keeps label", "Adversaries may abuse [schtasks](https://attack.mitre.org/software/S0111) to run.", "Adversaries may abuse schtasks to run."},
		{"citation marker removed", "Can run directly. (Citation: Stack Overflow) More text.", "Can run directly. More text."},
		{"html tags removed", "Monitor <code>svchost.exe</code> for changes.", "Monitor svchost.exe for changes."},
		{"whitespace collapsed", "a   b\n\nc  ", "a b c"},
		{"plain text untouched", "Plain sentence.", "Plain sentence."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cleanATTCKText(c.in); got != c.want {
				t.Errorf("cleanATTCKText(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
