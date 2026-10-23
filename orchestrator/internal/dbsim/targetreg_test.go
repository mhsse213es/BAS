package dbsim

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func validPGReg() TargetRegistration {
	return TargetRegistration{
		ID: "prod-pg-1", DisplayName: "Prod PG 1", Engine: "postgresql", Host: "db1.example.com", Port: 5432,
		Database: "app", CredentialRef: "dbcred:prod-pg-ro", ExpectedIdentity: "7312345678901234567", Mode: ModeClient,
	}
}

func validMyReg() TargetRegistration {
	r := validPGReg()
	r.ID, r.Engine, r.Port = "prod-my-1", "mysql", 3306
	r.ExpectedIdentity = "3B0F6E7A-1111-2222-3333-444455556666"
	return r
}

func TestRegistrationNormalizeStoresIdentityAndDefaults(t *testing.T) {
	r, err := validPGReg().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if r.ExpectedIdentity != "7312345678901234567" || r.DBServerHost != "db1.example.com" || r.TLSMode != "" {
		t.Fatalf("%+v", r)
	}
	// MySQL server_uuid is normalised to the lower case the server reports.
	m, err := validMyReg().Normalize()
	if err != nil || m.ExpectedIdentity != "3b0f6e7a-1111-2222-3333-444455556666" {
		t.Fatalf("%+v %v", m, err)
	}
	// An explicit DB server host/IP is kept; a missing display name defaults to the id; a missing port to the engine default.
	x := validPGReg()
	x.DBServerHost, x.DisplayName, x.Port = "10.0.0.5", "", 0
	got, err := x.Normalize()
	if err != nil || got.DBServerHost != "10.0.0.5" || got.DisplayName != "prod-pg-1" || got.Port != 5432 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRegistrationRefusesWhatCannotBeTrusted(t *testing.T) {
	mut := func(f func(r *TargetRegistration)) TargetRegistration { r := validPGReg(); f(&r); return r }
	bad := map[string]TargetRegistration{
		"no id":                  mut(func(r *TargetRegistration) { r.ID = "" }),
		"upper id":               mut(func(r *TargetRegistration) { r.ID = "Prod" }),
		"id with space":          mut(func(r *TargetRegistration) { r.ID = "a b" }),
		"bad engine":             mut(func(r *TargetRegistration) { r.Engine = "oracle" }),
		"mariadb":                mut(func(r *TargetRegistration) { r.Engine = "mariadb" }),
		"no host":                mut(func(r *TargetRegistration) { r.Host = "" }),
		"host with scheme":       mut(func(r *TargetRegistration) { r.Host = "postgres://db" }),
		"host with space":        mut(func(r *TargetRegistration) { r.Host = "db 1" }),
		"host with path":         mut(func(r *TargetRegistration) { r.Host = "db/x" }),
		"bad db server host":     mut(func(r *TargetRegistration) { r.DBServerHost = "a;b" }),
		"port too big":           mut(func(r *TargetRegistration) { r.Port = 70000 }),
		"negative port":          mut(func(r *TargetRegistration) { r.Port = -1 }),
		"bad tls":                mut(func(r *TargetRegistration) { r.TLSMode = "require" }),
		"database with quote":    mut(func(r *TargetRegistration) { r.Database = `a"b` }),
		"no credential":          mut(func(r *TargetRegistration) { r.CredentialRef = "" }),
		"raw password as ref":    mut(func(r *TargetRegistration) { r.CredentialRef = "hunter2" }),
		"wrong prefix":           mut(func(r *TargetRegistration) { r.CredentialRef = "cred:x" }),
		"upper credential":       mut(func(r *TargetRegistration) { r.CredentialRef = "dbcred:Prod" }),
		"empty credential name":  mut(func(r *TargetRegistration) { r.CredentialRef = "dbcred:" }),
		"no identity (R6)":       mut(func(r *TargetRegistration) { r.ExpectedIdentity = "" }),
		"blank identity":         mut(func(r *TargetRegistration) { r.ExpectedIdentity = "   " }),
		"pg identity not number": mut(func(r *TargetRegistration) { r.ExpectedIdentity = "abc" }),
		"pg identity is a uuid":  mut(func(r *TargetRegistration) { r.ExpectedIdentity = "3b0f6e7a-1111-2222-3333-444455556666" }),
		"no mode":                mut(func(r *TargetRegistration) { r.Mode = "" }),
		"bad mode":               mut(func(r *TargetRegistration) { r.Mode = "prod" }),
		"client lab-confirmed":   mut(func(r *TargetRegistration) { r.Mode, r.LabConfirmed = ModeClient, true }),
		"long display name":      mut(func(r *TargetRegistration) { r.DisplayName = strings.Repeat("x", 101) }),
		"control in name":        mut(func(r *TargetRegistration) { r.DisplayName = "a\nb" }),
	}
	for name, r := range bad {
		if _, err := r.Normalize(); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, ErrTargetInvalid) {
			t.Errorf("%s: error does not wrap ErrTargetInvalid: %v", name, err)
		}
	}
	m := validMyReg()
	m.ExpectedIdentity = "7312345678901234567"
	if _, err := m.Normalize(); err == nil {
		t.Error("mysql target with a numeric (PostgreSQL-shaped) identity accepted")
	}
	// A secret never fits in any field the API stores: the reference is the only credential slot and it is validated.
	if _, err := mut(func(r *TargetRegistration) { r.CredentialRef = "dbcred:ok-ref" }).Normalize(); err != nil {
		t.Errorf("valid reference refused: %v", err)
	}
}

func TestToTargetCarriesTrustOnlyFromTheStoredRecord(t *testing.T) {
	reg, _ := validPGReg().Normalize()
	rec := TargetRecord{TargetRegistration: reg}
	tg := rec.ToTarget()
	if tg.ReadOnlyIdentityVerified || tg.LabConfirmed || tg.Mode != ModeClient || tg.ExpectedIdentity != reg.ExpectedIdentity ||
		tg.CredentialRef != reg.CredentialRef || tg.Host != reg.Host || tg.Engine != "postgresql" {
		t.Fatalf("a fresh client record must not be verified: %+v", tg)
	}
	rec.IdentityCheck = IdentityCheckState{Checked: true, Passed: true, At: time.Now(), By: "u1"}
	if !rec.ToTarget().ReadOnlyIdentityVerified {
		t.Fatal("a passed check on a client target must verify it")
	}
	rec.IdentityCheck.Passed = false
	if rec.ToTarget().ReadOnlyIdentityVerified {
		t.Fatal("a failed check must not verify")
	}
	rec.IdentityCheck = IdentityCheckState{Passed: true} // Checked=false: never recorded
	if rec.ToTarget().ReadOnlyIdentityVerified {
		t.Fatal("Passed without Checked must not verify")
	}
	// Lab flags: only a lab target can be lab-confirmed, and never verified for client use.
	lab := validPGReg()
	lab.Mode, lab.LabConfirmed = ModeLab, true
	lreg, err := lab.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	lt := TargetRecord{TargetRegistration: lreg, IdentityCheck: IdentityCheckState{Checked: true, Passed: true}}.ToTarget()
	if !lt.LabConfirmed || lt.ReadOnlyIdentityVerified {
		t.Fatalf("lab target flags: %+v", lt)
	}
}

func TestAuthorizeIdentityCheck(t *testing.T) {
	now := fixedNow
	exp := now.Add(time.Minute)
	tg := goodTarget(ModeClient)
	tg.CredentialRef = "dbcred:x"
	tg.ReadOnlyIdentityVerified = false // the check is what establishes it
	if err := AuthorizeIdentityCheck(tg, now, exp); err != nil {
		t.Fatalf("an unverified client target must be checkable: %v", err)
	}
	lab := goodTarget(ModeLab)
	lab.CredentialRef = "dbcred:x"
	if err := AuthorizeIdentityCheck(lab, now, exp); err != nil {
		t.Fatalf("lab target: %v", err)
	}
	for name, mut := range map[string]func(t *Target){
		"no identity":    func(t *Target) { t.ExpectedIdentity = " " },
		"bad engine":     func(t *Target) { t.Engine = "oracle" },
		"bad mode":       func(t *Target) { t.Mode = "prod" },
		"no credentials": func(t *Target) { t.CredentialRef = "" },
	} {
		x := goodTarget(ModeClient)
		x.CredentialRef = "dbcred:x"
		mut(&x)
		if AuthorizeIdentityCheck(x, now, exp) == nil {
			t.Errorf("%s: authorised", name)
		}
	}
	if AuthorizeIdentityCheck(tg, now, time.Time{}) == nil || AuthorizeIdentityCheck(tg, now, now) == nil {
		t.Error("a check with no/expired expiry was authorised")
	}
}

func TestClientModeSettingIsReadFailClosed(t *testing.T) {
	for _, c := range []struct {
		val   string
		found bool
		err   error
		want  bool
	}{
		{"true", true, nil, true},
		{"false", true, nil, false},
		{"", false, nil, false},                 // never set: default OFF
		{"true", true, errors.New("db"), false}, // read error: OFF even if a value came back
		{"TRUE", true, nil, false},              // only the exact value turns it on
		{"1", true, nil, false},
		{"yes", true, nil, false},
		{" true", true, nil, false},
		{"true", false, nil, false},
	} {
		if got := ClientModeFromSetting(c.val, c.found, c.err); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
}

func TestTargetSchemaIsIdempotentAndHoldsNoSecrets(t *testing.T) {
	all := strings.ToLower(strings.Join(append(append([]string{}, TargetsSchemaSQL...), SettingsSchemaSQL...), "\n"))
	for _, s := range append(append([]string{}, TargetsSchemaSQL...), SettingsSchemaSQL...) {
		u := strings.ToUpper(s)
		if !strings.Contains(u, "IF NOT EXISTS") {
			t.Errorf("statement is not idempotent: %s", s)
		}
	}
	for _, bad := range []string{"password", "secret", "token", "private_key"} {
		if strings.Contains(all, bad) {
			t.Errorf("schema has a %q column: credentials are references only", bad)
		}
	}
	for _, want := range []string{"expected_identity", "credential_ref", "identity_check_passed", "identity_check_by", "identity_check_at", "db_server_host", "mode"} {
		if !strings.Contains(all, want) {
			t.Errorf("schema lacks %s", want)
		}
	}
}
