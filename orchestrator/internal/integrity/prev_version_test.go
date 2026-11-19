package integrity

import "testing"

const hexA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// The signed manifest records the version of the release before it, so the server can default the fleet minimum
// agent version to it. A "#prev-version" line must not be mistaken for a "#prev" hash line.
func TestPrevVersionLine(t *testing.T) {
	m := parseManifestLines([]string{
		hexA + "  bas-agent-linux-amd64",
		"#prev-version 1.9.9.3",
		"#prev " + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "  bas-agent-linux-amd64",
	})
	if got := m.PreviousReleaseVersion(); got != "1.9.9.3" {
		t.Fatalf("PreviousReleaseVersion = %q, want 1.9.9.3", got)
	}
	if !m.HashPreviousRelease("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Error("the #prev hash line stopped being read")
	}
	if len(m.prev) != 1 {
		t.Errorf("prev hashes = %d, want 1: the version line must not count as a hash", len(m.prev))
	}
}

func TestPrevVersionAbsentOrUnreadableIsEmpty(t *testing.T) {
	for _, lines := range [][]string{
		{hexA + "  f"},
		{"#prev-version"},
		{"#prev-version not-a-version"},
		{"#prev-version 1.9.9.3 extra"},
	} {
		if got := parseManifestLines(lines).PreviousReleaseVersion(); got != "" {
			t.Errorf("%v: PreviousReleaseVersion = %q, want empty", lines, got)
		}
	}
	if got := (&Manifest{}).PreviousReleaseVersion(); got != "" {
		t.Errorf("zero manifest: %q", got)
	}
}

// RevokedHashes lists the signed revocations so the console can show them as irreversible.
func TestRevokedHashesSorted(t *testing.T) {
	m := parseManifestLines([]string{
		"#revoked " + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" + "  f",
		"#revoked " + hexA + "  f",
	})
	got := m.RevokedHashes()
	if len(got) != 2 || got[0] != hexA {
		t.Fatalf("RevokedHashes = %v, want 2 sorted hashes starting with %s", got, hexA)
	}
}
