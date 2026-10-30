package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

// A previous signed release is listed on a "#prev" line. Its hash is recognised as an
// outdated release, never as a current one. The signature covers the whole file.
func TestLoadManifest_PreviousReleaseHashesAreSeparate(t *testing.T) {
	const cur = "1111111111111111111111111111111111111111111111111111111111111111"
	const prev = "2222222222222222222222222222222222222222222222222222222222222222"
	const other = "3333333333333333333333333333333333333333333333333333333333333333"
	path := filepath.Join(t.TempDir(), "BINARIES.sha256")
	body := cur + "  bas-agent-windows-amd64.exe\n" +
		"#prev " + prev + "  bas-agent-windows-amd64.exe\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	m := LoadManifest(path)
	if !m.HashKnown(cur) {
		t.Fatal("current hash must be trusted")
	}
	if m.HashKnown(prev) {
		t.Fatal("previous-release hash must not count as a current trusted hash")
	}
	if !m.HashPreviousRelease(prev) {
		t.Fatal("previous-release hash must be recognised as an outdated release")
	}
	if m.HashPreviousRelease(cur) || m.HashPreviousRelease(other) {
		t.Fatal("current or unknown hash must not be reported as previous release")
	}
}

func TestNextAgentState(t *testing.T) {
	cases := []struct {
		state         string
		trusted, prev bool
		want          string
		why           string
	}{
		{"active", true, false, "active", "current binary keeps an active agent active"},
		{"outdated", true, false, "active", "upgrade recovery: current binary returns the agent to active"},
		{"active", false, true, "outdated", "older signed release degrades, it does not quarantine"},
		{"outdated", false, true, "outdated", "still an older release"},
		{"active", false, false, "quarantined", "unknown binary is a security quarantine"},
		{"outdated", false, false, "quarantined", "an outdated agent with an unknown binary escalates to quarantine"},
		{"quarantined", true, false, "quarantined", "a trusted binary never releases a security quarantine"},
		{"quarantined", false, true, "quarantined", "quarantine is sticky even for a previous release"},
		{"retired", true, false, "retired", "retired is sticky"},
		{"restricted", false, false, "restricted", "operator restriction is not changed by binary checks"},
	}
	for _, c := range cases {
		if got := NextAgentState(c.state, c.trusted, c.prev); got != c.want {
			t.Errorf("%s (trusted=%v prev=%v): got %q want %q: %s", c.state, c.trusted, c.prev, got, c.want, c.why)
		}
	}
}
