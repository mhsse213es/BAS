package license

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSetInitial_ThenCurrent(t *testing.T) {
	want := Info{State: StateGrace, DaysRemaining: 3}
	SetInitial(want)
	got := Current()
	if got.State != want.State || got.DaysRemaining != want.DaysRemaining {
		t.Errorf("Current() = %+v, want %+v", got, want)
	}
}

func TestStartMonitor_PicksUpStateChangeOnTick(t *testing.T) {
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	defer func() { PublicKeyPEM = orig }()

	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")
	writeLic := func(expiresAt string) {
		lic := SignForTest(priv, License{Customer: "Acme", CustomerID: "acme-1", ExpiresAt: expiresAt})
		data, _ := json.Marshal(lic)
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}
	}

	// Start valid, well in the future.
	writeLic(time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02"))
	SetInitial(Info{State: StateValid})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

	// Flip the file to an already-locked license (deep in the past) —
	// signed fresh, so this is a legitimate renewal/downgrade, not tampering.
	writeLic(time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if Current().State == StateLocked {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Current().State never became StateLocked after license file changed; last seen: %+v", Current())
}

func TestStartMonitor_OnLockFiresExactlyOnceOnTransition(t *testing.T) {
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	defer func() { PublicKeyPEM = orig }()

	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")
	lic := SignForTest(priv, License{Customer: "Acme", CustomerID: "acme-1", ExpiresAt: time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02")})
	data, _ := json.Marshal(lic)
	if err := os.WriteFile(licPath, data, 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	SetInitial(Info{State: StateGrace}) // start NOT blocked, so the first tick is the transition

	// onLock runs on the monitor's goroutine; atomic so the read below doesn't race it.
	var calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, func() { calls.Add(1) })

	time.Sleep(200 * time.Millisecond) // several ticks — onLock must still fire only once
	if n := calls.Load(); n != 1 {
		t.Errorf("onLock called %d times, want exactly 1", n)
	}
}

// TestStartMonitor_TamperedExpiryAfterStartup_NeverRestoresAccess is the
// core acceptance criterion: editing expires_at in bas.lic while the
// orchestrator is already running, without re-signing, must never produce
// StateValid again — even though the file still parses as valid JSON with
// a well-formed, far-future date.
func TestStartMonitor_TamperedExpiryAfterStartup_NeverRestoresAccess(t *testing.T) {
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	defer func() { PublicKeyPEM = orig }()

	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")

	// Genuinely signed, already locked (grace period long over).
	lic := SignForTest(priv, License{
		Customer:   "Acme",
		CustomerID: "acme-1",
		ExpiresAt:  time.Now().UTC().Add(-30 * 24 * time.Hour).Format("2006-01-02"),
	})
	data, err := json.Marshal(lic)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(licPath, data, 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	SetInitial(Info{State: StateLocked})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

	// Simulate the attack: edit expires_at directly in the raw JSON bytes,
	// to a far-future date, WITHOUT touching signature. This is exactly
	// what an attacker with filesystem access to bas.lic would do.
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	raw["expires_at"] = "2099-12-31"
	tampered, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if err := os.WriteFile(licPath, tampered, 0644); err != nil {
		t.Fatalf("write tampered license: %v", err)
	}

	// Give the monitor several ticks to pick up the tampered file.
	time.Sleep(200 * time.Millisecond)

	if got := Current().State; got == StateValid {
		t.Fatalf("Current().State = %q after tampering with expires_at and no re-signing — access must never be restored this way", got)
	}
	if got := Current().State; got != StateInvalid {
		t.Errorf("Current().State = %q, want %q (tampered signature must fail closed into Invalid)", got, StateInvalid)
	}
}

// TestStartMonitor_TamperedCustomerIDOrFeatures_FailsClosed covers the
// other fields the signature protects: editing customer_id or features
// without re-signing must also be rejected, not just expires_at.
func TestStartMonitor_TamperedCustomerIDOrFeatures_FailsClosed(t *testing.T) {
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	defer func() { PublicKeyPEM = orig }()

	cases := []struct {
		name string
		edit func(raw map[string]any)
	}{
		{"customer_id", func(raw map[string]any) { raw["customer_id"] = "someone-elses-id" }},
		{"features", func(raw map[string]any) { raw["features"] = []string{"enterprise-everything"} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			licPath := filepath.Join(dir, "bas.lic")
			lic := SignForTest(priv, License{
				Customer:   "Acme",
				CustomerID: "acme-1",
				ExpiresAt:  time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02"),
				Features:   []string{"base"},
			})
			data, err := json.Marshal(lic)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := os.WriteFile(licPath, data, 0644); err != nil {
				t.Fatalf("write license: %v", err)
			}
			SetInitial(Info{State: StateValid})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

			var raw map[string]any
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatalf("unmarshal raw: %v", err)
			}
			tc.edit(raw)
			tampered, err := json.Marshal(raw)
			if err != nil {
				t.Fatalf("marshal tampered: %v", err)
			}
			if err := os.WriteFile(licPath, tampered, 0644); err != nil {
				t.Fatalf("write tampered license: %v", err)
			}

			time.Sleep(200 * time.Millisecond)

			if got := Current().State; got != StateInvalid {
				t.Errorf("Current().State = %q after tampering with %s, want %q", got, tc.name, StateInvalid)
			}
		})
	}
}

// TestStartMonitor_FileDeletedOrCorrupted_FailsClosed_NotLastKnownState
// proves the monitor no longer "keeps the last known state" on a read or
// parse error — a deleted or corrupted license must flip OUT of
// StateValid, not silently preserve it.
func TestStartMonitor_FileDeletedOrCorrupted_FailsClosed_NotLastKnownState(t *testing.T) {
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	defer func() { PublicKeyPEM = orig }()

	t.Run("deleted", func(t *testing.T) {
		dir := t.TempDir()
		licPath := filepath.Join(dir, "bas.lic")
		lic := SignForTest(priv, License{Customer: "Acme", CustomerID: "acme-1", ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02")})
		data, _ := json.Marshal(lic)
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}
		SetInitial(Info{State: StateValid})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

		if err := os.Remove(licPath); err != nil {
			t.Fatalf("remove license: %v", err)
		}
		time.Sleep(200 * time.Millisecond)

		if got := Current().State; got != StateInvalid {
			t.Errorf("Current().State = %q after deleting bas.lic, want %q", got, StateInvalid)
		}
	})

	t.Run("corrupted", func(t *testing.T) {
		dir := t.TempDir()
		licPath := filepath.Join(dir, "bas.lic")
		lic := SignForTest(priv, License{Customer: "Acme", CustomerID: "acme-1", ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02")})
		data, _ := json.Marshal(lic)
		if err := os.WriteFile(licPath, data, 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}
		SetInitial(Info{State: StateValid})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

		if err := os.WriteFile(licPath, []byte("{not valid json"), 0644); err != nil {
			t.Fatalf("corrupt license: %v", err)
		}
		time.Sleep(200 * time.Millisecond)

		if got := Current().State; got != StateInvalid {
			t.Errorf("Current().State = %q after corrupting bas.lic, want %q", got, StateInvalid)
		}
	})
}

// TestStartMonitor_RecoversWhenOriginalValidLicenseRestored proves recovery
// goes through the SAME strict verification as any other tick: restoring
// the exact original, correctly-signed bytes brings access back; this is
// not a special weaker path, so a forged "restoration" would not work.
func TestStartMonitor_RecoversWhenOriginalValidLicenseRestored(t *testing.T) {
	priv, pubPEM := GenerateTestKeypair()
	orig := PublicKeyPEM
	PublicKeyPEM = pubPEM
	defer func() { PublicKeyPEM = orig }()

	dir := t.TempDir()
	licPath := filepath.Join(dir, "bas.lic")
	lic := SignForTest(priv, License{Customer: "Acme", CustomerID: "acme-1", ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02")})
	validBytes, err := json.Marshal(lic)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(licPath, validBytes, 0644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	SetInitial(Info{State: StateValid})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	StartMonitor(ctx, licPath, 20*time.Millisecond, nil)

	// Corrupt it, confirm it goes Invalid.
	if err := os.WriteFile(licPath, []byte("garbage"), 0644); err != nil {
		t.Fatalf("corrupt license: %v", err)
	}
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) && Current().State != StateInvalid {
		time.Sleep(10 * time.Millisecond)
	}
	if got := Current().State; got != StateInvalid {
		t.Fatalf("Current().State = %q after corruption, want %q", got, StateInvalid)
	}

	// Restore the exact original, validly-signed bytes.
	if err := os.WriteFile(licPath, validBytes, 0644); err != nil {
		t.Fatalf("restore license: %v", err)
	}
	deadline = time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if Current().State == StateValid {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Current().State never recovered to %q after restoring the original valid license; last seen: %+v", StateValid, Current())
}

// TestStartMonitor_DevModeBypass_NeverEnforces documents and locks in the
// one intentional exception: with PublicKeyPEM still the KEYGEN_REQUIRED
// placeholder (local dev, keygen.sh never run), StartMonitor must not
// start a ticker at all — otherwise a dev build with no bas.lic ever
// configured would fail closed into StateInvalid five minutes after
// Check() deliberately let it start with enforcement disabled.
func TestStartMonitor_DevModeBypass_NeverEnforces(t *testing.T) {
	orig := PublicKeyPEM
	PublicKeyPEM = "KEYGEN_REQUIRED"
	defer func() { PublicKeyPEM = orig }()

	SetInitial(Info{State: StateValid})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// licPath deliberately points at a file that will never exist — if
	// the monitor started anyway, this would fail-closed into Invalid.
	StartMonitor(ctx, filepath.Join(t.TempDir(), "never-created.lic"), 20*time.Millisecond, nil)

	time.Sleep(200 * time.Millisecond)
	if got := Current().State; got != StateValid {
		t.Errorf("Current().State = %q in KEYGEN_REQUIRED dev mode, want %q (monitor must not run at all)", got, StateValid)
	}
}
