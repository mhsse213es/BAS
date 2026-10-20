package calibration

import (
	"errors"
	"testing"
)

// Deterministic integrity tests. The records are built from fixed sample values, so no
// timing is measured. Each test edits a record and expects the verification to fail.

func testThresholds() Thresholds {
	return Thresholds{
		DeclaredBaselineMs: 0.14, Tolerance: 4, CeilingMs: 250, MinRatio: 5, MaxCV: 0.5,
		AttackMaxMs: 5000, NoiseFloorMs: 1, Alpha: 0.01, MinSeparationRatio: 5,
		Warmup: 3, Trials: 10, Rounds: 3,
	}
}

func rounds(k int, base, att []float64) []RoundSamples {
	out := make([]RoundSamples, k)
	for i := range out {
		out[i] = RoundSamples{BaselineMs: append([]float64(nil), base...), AttackMs: append([]float64(nil), att...)}
	}
	return out
}

func cycle(n int, vals ...float64) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = vals[i%len(vals)]
	}
	return out
}

// sealed returns a record whose verdict was computed from its own samples.
func sealed(t *testing.T) Record {
	t.Helper()
	th := testThresholds()
	base := cycle(10, 0.13, 0.14, 0.15)
	vuln := rounds(3, base, cycle(10, 1290, 1300, 1310))
	fixed := rounds(3, base, cycle(10, 0.1, 0.2, 0.3))
	q := Evaluate(th, vuln, fixed)
	return Record{
		ScenarioID: "API-BAS-ABUSE-002", Version: 1, Profile: Profile{Label: "test-machine", Fingerprint: CollectFingerprint()},
		Thresholds: th, Vulnerable: Build{Rounds: vuln}, Fixed: Build{Rounds: fixed},
		Qualified: q.Qualified, QualificationReasons: q.Reasons,
		Separation: Separation{P: q.P, Ratio: q.Ratio, VulnMedianMs: q.VulnMedianMs, FixedMedianMs: q.FixedMedianMs},
	}
}

func TestSealedRecordVerifies(t *testing.T) {
	rec := sealed(t)
	if !rec.Qualified {
		t.Fatalf("test fixture did not qualify: %v", rec.QualificationReasons)
	}
	if err := Verify(rec); err != nil {
		t.Fatalf("sealed record failed verification: %v", err)
	}
}

// Changing the samples under a stored verdict is detected.
func TestTamperedSamplesFailVerification(t *testing.T) {
	rec := sealed(t)
	rec.Vulnerable.Rounds[0].AttackMs = cycle(10, 0.2)
	rec.Vulnerable.Rounds[1].AttackMs = cycle(10, 0.2)
	rec.Vulnerable.Rounds[2].AttackMs = cycle(10, 0.2)
	if err := Verify(rec); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("tampered samples verified: %v", err)
	}
}

// Flipping the stored verdict is detected, in either direction.
func TestFlippedVerdictFailsVerification(t *testing.T) {
	rec := sealed(t)
	rec.Qualified = false
	if err := Verify(rec); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("flipped verdict verified: %v", err)
	}
	bad := rec
	bad.Qualified = true
	bad.QualificationReasons = nil
	bad.Vulnerable.Rounds = rounds(3, cycle(10, 0.14), cycle(10, 0.1))
	bad.Fixed.Rounds = rounds(3, cycle(10, 0.14), cycle(10, 0.1))
	if err := Verify(bad); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("qualified record with no separation verified: %v", err)
	}
}

// A stored p-value that does not match the samples is detected.
func TestWrongPValueFailsVerification(t *testing.T) {
	rec := sealed(t)
	rec.Separation.P = 0.5
	if err := Verify(rec); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("wrong p-value verified: %v", err)
	}
}

// A threshold edited after measurement changes the verdict, so verification fails.
func TestEditedThresholdFailsVerification(t *testing.T) {
	rec := sealed(t)
	rec.Thresholds.CeilingMs = 5000
	if err := Verify(rec); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("edited threshold verified: %v", err)
	}
}

// Write refuses a record that does not verify, so tampering cannot be stored.
func TestWriteRefusesTamperedRecord(t *testing.T) {
	rec := sealed(t)
	rec.Qualified = false
	if _, err := Write(t.TempDir(), rec); err == nil {
		t.Fatal("tampered record was written")
	}
}

// A record with no samples cannot claim to be qualified.
func TestQualifiedWithoutSamplesIsRefused(t *testing.T) {
	rec := Record{ScenarioID: "API-BAS-ABUSE-002", Version: 1, Profile: Profile{Label: "m", Fingerprint: CollectFingerprint()}, Qualified: true}
	if err := Verify(rec); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("qualified record with no samples verified: %v", err)
	}
}

// Legacy records with no samples verify as unqualified, so they can only refuse timing.
func TestLegacyRecordVerifiesUnqualified(t *testing.T) {
	rec := Record{ScenarioID: "API-BAS-ABUSE-002", Version: 1, Profile: Profile{Label: "m", Fingerprint: CollectFingerprint()}}
	if err := Verify(rec); err != nil {
		t.Fatalf("legacy unqualified record refused: %v", err)
	}
}
