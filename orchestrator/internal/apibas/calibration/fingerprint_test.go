package calibration

import (
	"slices"
	"testing"
)

// The fingerprint is a drift detector. These tests check what it compares and what it
// ignores, using fixed attribute sets rather than the live machine.

func fixedFingerprint(attrs map[string]string, unavailable ...string) Fingerprint {
	f := Fingerprint{Attributes: attrs, Sources: map[string]string{}, Unavailable: unavailable}
	for k := range attrs {
		f.Sources[k] = "test"
	}
	slices.Sort(f.Unavailable)
	f.Digest = f.computeDigest()
	return f
}

func baseAttrs() map[string]string {
	return map[string]string{
		"goos": "windows", "goarch": "amd64", "go_version": "go1.26.8", "num_cpu": "8",
		"cpu_model": "Intel64 Family 6 Model 142", "memory_total_bytes": "17179869184", "os_version": "10.0.19045",
	}
}

func TestLiveFingerprintMatchesItself(t *testing.T) {
	a, b := CollectFingerprint(), CollectFingerprint()
	if a.Digest == "" || !a.Matches(b) {
		t.Fatal("the same environment did not match itself")
	}
	if !a.DigestIsConsistent() {
		t.Fatal("collected digest does not follow from its attributes")
	}
}

// Every collected attribute is either read with a source or listed as unavailable.
func TestEveryAttributeIsReadOrRecordedUnavailable(t *testing.T) {
	f := CollectFingerprint()
	for _, name := range osAttributeNames {
		_, read := f.Attributes[name]
		listed := slices.Contains(f.Unavailable, name)
		if read == listed {
			t.Errorf("%s: read=%v unavailable=%v; want exactly one", name, read, listed)
		}
		if read && f.Sources[name] == "" {
			t.Errorf("%s was read without a recorded source", name)
		}
	}
}

// A changed attribute is a different environment.
func TestChangedAttributeDoesNotMatch(t *testing.T) {
	a := fixedFingerprint(baseAttrs())
	changed := baseAttrs()
	changed["memory_total_bytes"] = "8589934592"
	if a.Matches(fixedFingerprint(changed)) {
		t.Fatal("different memory size matched")
	}
}

func TestChangedCPUModelDoesNotMatch(t *testing.T) {
	a := fixedFingerprint(baseAttrs())
	changed := baseAttrs()
	changed["cpu_model"] = "AMD Ryzen 7"
	if a.Matches(fixedFingerprint(changed)) {
		t.Fatal("different CPU model matched")
	}
}

// A Go toolchain change alters timing, so it requalifies.
func TestChangedGoVersionDoesNotMatch(t *testing.T) {
	a := fixedFingerprint(baseAttrs())
	changed := baseAttrs()
	changed["go_version"] = "go1.27.0"
	if a.Matches(fixedFingerprint(changed)) {
		t.Fatal("different Go version matched")
	}
}

// An attribute that stops being readable changes the digest, so it requalifies.
func TestNewlyUnavailableAttributeDoesNotMatch(t *testing.T) {
	a := fixedFingerprint(baseAttrs())
	without := baseAttrs()
	delete(without, "os_version")
	if a.Matches(fixedFingerprint(without, "os_version")) {
		t.Fatal("platform that stopped reporting os_version matched")
	}
}

// The label is display-only. Renaming a machine does not requalify it.
func TestLabelDoesNotAffectMatch(t *testing.T) {
	fp := fixedFingerprint(baseAttrs())
	a := Profile{Label: "lab-one", Fingerprint: fp}
	b := Profile{Label: "renamed-laptop", Fingerprint: fp}
	if !a.Matches(b) {
		t.Fatal("renaming the label changed the match")
	}
}

// An empty digest never matches, so an unrecorded environment cannot pass as recorded.
func TestEmptyDigestNeverMatches(t *testing.T) {
	var empty Fingerprint
	if empty.Matches(empty) || empty.Matches(fixedFingerprint(baseAttrs())) {
		t.Fatal("an empty fingerprint matched")
	}
}

// An edited attribute without a matching digest is detected.
func TestEditedAttributeIsInconsistent(t *testing.T) {
	f := fixedFingerprint(baseAttrs())
	f.Attributes["num_cpu"] = "64"
	if f.DigestIsConsistent() {
		t.Fatal("edited attribute still followed its digest")
	}
}

// A record with an edited fingerprint fails verification.
func TestRecordWithEditedFingerprintFailsVerification(t *testing.T) {
	rec := sealed(t)
	rec.Profile.Fingerprint = fixedFingerprint(baseAttrs())
	rec.Profile.Fingerprint.Attributes["num_cpu"] = "64"
	if err := Verify(rec); err == nil {
		t.Fatal("record with an edited fingerprint verified")
	}
}
