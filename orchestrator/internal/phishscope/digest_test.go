package phishscope

import (
	"strings"
	"testing"
)

// The fingerprint must not depend on entry order or letter case, or the same
// configuration would look like a change on every restart.
func TestDigest_StableAcrossOrderAndCase(t *testing.T) {
	a := Digest(Scope{Users: []string{"Alice@Contoso.example", "bob@contoso.example"}, ClientIDs: []string{goodGUID}})
	b := Digest(Scope{Users: []string{"bob@contoso.example", "alice@contoso.example"}, ClientIDs: []string{strings.ToUpper(goodGUID)}})
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprint differs for the same allowlist: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
}

// Adding or removing one entry must change the fingerprint.
func TestDigest_ChangesWhenAnEntryChanges(t *testing.T) {
	base := Digest(Scope{Users: []string{"alice@contoso.example"}})
	added := Digest(Scope{Users: []string{"alice@contoso.example", "bob@contoso.example"}})
	if base.Fingerprint == added.Fingerprint {
		t.Error("adding a user did not change the fingerprint")
	}
}

// User principal names are never recorded in clear. Only per-entry hashes are.
func TestDigest_UsersAreHashedNotStored(t *testing.T) {
	d := Digest(Scope{Users: []string{"alice@contoso.example"}})
	for _, h := range d.UserHashes {
		if strings.Contains(h, "alice") || strings.Contains(h, "@") {
			t.Errorf("user hash %q leaks the principal name", h)
		}
	}
	if len(d.UserHashes) != 1 {
		t.Errorf("UserHashes = %d, want 1", len(d.UserHashes))
	}
}

// Client IDs are recorded in clear, because they identify apps, not people.
func TestDigest_ClientIDsRecordedInClear(t *testing.T) {
	d := Digest(Scope{ClientIDs: []string{goodGUID}})
	if len(d.ClientIDs) != 1 || d.ClientIDs[0] != goodGUID {
		t.Errorf("ClientIDs = %v, want [%s]", d.ClientIDs, goodGUID)
	}
}

// An unconfigured allowlist has a fingerprint too, so "cleared" is itself a
// recorded change rather than a missing row.
func TestDigest_EmptyHasStableFingerprint(t *testing.T) {
	a := Digest(Scope{})
	b := Digest(Scope{})
	if a.Fingerprint == "" || a.Fingerprint != b.Fingerprint {
		t.Errorf("empty fingerprint = %q, want a stable non-empty value", a.Fingerprint)
	}
}
