package integrity

import "testing"

const (
	revCurrent  = "1111111111111111111111111111111111111111111111111111111111111111"
	revPrevious = "2222222222222222222222222222222222222222222222222222222222222222"
	revBad      = "3333333333333333333333333333333333333333333333333333333333333333"
	revUnlisted = "4444444444444444444444444444444444444444444444444444444444444444"
)

func TestParseRevokedLines(t *testing.T) {
	m := parseManifestLines([]string{
		revCurrent + "  bas-agent-linux-amd64",
		"#prev " + revPrevious + "  bas-agent-linux-amd64",
		"#revoked " + revBad + "  bas-agent-linux-amd64",
	})
	if !m.HashRevoked(revBad) {
		t.Fatal("#revoked line not parsed")
	}
	if m.HashRevoked(revCurrent) || m.HashRevoked(revPrevious) || m.HashRevoked(revUnlisted) {
		t.Fatal("hashes without a #revoked line must not be revoked")
	}
	if !m.HashPreviousRelease(revPrevious) {
		t.Fatal("#prev line must still parse alongside #revoked")
	}
}

func TestTrustedHashExcludesRevoked(t *testing.T) {
	// A hash that is listed as current AND revoked is not Verified.
	m := parseManifestLines([]string{
		revCurrent + "  bas-agent-linux-amd64",
		revBad + "  bas-agent-windows-amd64.exe",
		"#revoked " + revBad + "  bas-agent-windows-amd64.exe",
	})
	if !m.TrustedHash(revCurrent) {
		t.Fatal("current, unrevoked hash must be trusted")
	}
	if m.TrustedHash(revBad) {
		t.Fatal("revoked hash must not be trusted even when it is a current entry")
	}
	if m.TrustedHash(revUnlisted) {
		t.Fatal("unknown hash must not be trusted")
	}
}

func TestNextAgentStateRevocation(t *testing.T) {
	cases := []struct {
		name                       string
		state                      string
		trusted, previous, revoked bool
		want                       string
	}{
		{"revoked and trusted quarantines", "active", true, false, true, "quarantined"},
		{"revoked previous release quarantines", "outdated", false, true, true, "quarantined"},
		{"revoked active agent quarantines", "active", false, false, true, "quarantined"},
		{"unrevoked previous stays outdated", "active", false, true, false, "outdated"},
		{"unrevoked current returns to active", "outdated", true, false, false, "active"},
		{"operator quarantine is not released by a revoke check", "quarantined", true, false, false, "quarantined"},
		{"retired stays retired even if revoked", "retired", false, false, true, "retired"},
	}
	for _, c := range cases {
		if got := NextAgentState(c.state, c.trusted, c.previous, c.revoked); got != c.want {
			t.Errorf("%s: NextAgentState(%q, trusted=%v, previous=%v, revoked=%v) = %q, want %q",
				c.name, c.state, c.trusted, c.previous, c.revoked, got, c.want)
		}
	}
}
