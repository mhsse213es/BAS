package dbsim

import (
	"testing"
	"time"
)

func passedRecord(t *testing.T, at time.Time) TargetRecord {
	t.Helper()
	reg, err := validPGReg().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	return TargetRecord{TargetRegistration: reg, CreatedAt: at.Add(-time.Hour),
		IdentityCheck: IdentityCheckState{Checked: true, Passed: true, At: at, By: "u1"}}
}

// I4: a pass expires. The default maximum age is a placeholder (24h) for an open
// user decision; the clock and the age are injected.
func TestPassedCheckExpires(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	max := 24 * time.Hour
	if DefaultIdentityCheckMaxAge != 24*time.Hour {
		t.Fatalf("placeholder default changed: %v", DefaultIdentityCheckMaxAge)
	}
	cases := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"fresh", now.Add(-time.Minute), true},
		{"just inside", now.Add(-max + time.Nanosecond), true},
		{"exactly the max age fails closed", now.Add(-max), false},
		{"stale", now.Add(-max - time.Second), false},
		{"timestamp in the future", now.Add(time.Minute), false},
		{"zero timestamp", time.Time{}, false},
	}
	for _, c := range cases {
		r := passedRecord(t, c.at)
		if got := r.ToTargetAt(now, max).ReadOnlyIdentityVerified; got != c.want {
			t.Errorf("%s: verified=%v want %v", c.name, got, c.want)
		}
	}
	// A non-positive max age never verifies (fail closed).
	r := passedRecord(t, now.Add(-time.Second))
	for _, m := range []time.Duration{0, -time.Hour} {
		if r.ToTargetAt(now, m).ReadOnlyIdentityVerified {
			t.Errorf("max age %v verified", m)
		}
	}
	// ToTarget uses the default age and the real clock.
	if !passedRecord(t, time.Now().Add(-time.Minute)).ToTarget().ReadOnlyIdentityVerified {
		t.Error("a fresh pass must verify through ToTarget")
	}
	if passedRecord(t, time.Now().Add(-25*time.Hour)).ToTarget().ReadOnlyIdentityVerified {
		t.Error("a 25h-old pass must not verify through ToTarget")
	}
}

func TestSameConfigDetectsAnyBoundFieldChange(t *testing.T) {
	base := passedRecord(t, time.Now())
	if !base.SameConfig(base) {
		t.Fatal("identical record differs")
	}
	for name, mut := range map[string]func(r *TargetRecord){
		"created":    func(r *TargetRecord) { r.CreatedAt = r.CreatedAt.Add(time.Second) },
		"credential": func(r *TargetRecord) { r.CredentialRef = "dbcred:other" },
		"identity":   func(r *TargetRecord) { r.ExpectedIdentity = "1" },
		"host":       func(r *TargetRecord) { r.Host = "x.example.com" },
		"port":       func(r *TargetRecord) { r.Port = 1 },
		"database":   func(r *TargetRecord) { r.Database = "x" },
		"tls":        func(r *TargetRecord) { r.TLSMode = "disable" },
		"engine":     func(r *TargetRecord) { r.Engine = "mysql" },
		"mode":       func(r *TargetRecord) { r.Mode = ModeLab },
		"id":         func(r *TargetRecord) { r.ID = "other" },
		"agent":      func(r *TargetRecord) { r.AgentID = "fedcba9876543210" },
	} {
		c := base
		mut(&c)
		if base.SameConfig(c) {
			t.Errorf("%s change not detected", name)
		}
	}
	// The check result itself is not part of the binding.
	c := base
	c.IdentityCheck = IdentityCheckState{}
	if !base.SameConfig(c) {
		t.Error("the check state must not be part of the binding")
	}
}
