package dbprobe

import (
	"sort"
	"strings"
	"testing"
)

func TestIdentityProbeIsPlainReadOnlyAndClientAllowed(t *testing.T) {
	d, ok := LookupProbe(ProbeCheckReadOnlyIdentity)
	if !ok {
		t.Fatal("check_readonly_identity missing from the catalog")
	}
	if d.Class != ClassReadOnly || d.LabOnly || d.FixtureParam != "" || d.RequiredFixture != "" || len(d.ParamSchema) != 0 {
		t.Fatalf("must be a plain parameter-free read_only probe: %+v", d)
	}
	s := validSpec()
	s.ProbeID, s.Mode = ProbeCheckReadOnlyIdentity, ModeClient
	if err := ValidateSpec(s); err != nil {
		t.Fatalf("client spec refused: %v", err)
	}
	if err := CheckSpec(s, d, "7001", "7001", Policy{ClientEnabled: true}); err != nil {
		t.Fatalf("client gate refused the identity check: %v", err)
	}
	// Still never a free-form or fixture-carrying probe.
	s.Params = map[string]string{"sql": "select 1"}
	if ValidateSpec(s) == nil {
		t.Error("a parameter was accepted")
	}
	s.Params, s.FixtureID = nil, "accounts"
	if CheckSpec(s, d, "7001", "7001", Policy{ClientEnabled: true, LabMutationAllowed: true}) == nil {
		t.Error("a fixture was accepted in client mode")
	}
}

// Every catalog probe is checked against the client-mode gate: exactly the
// plain read_only, non-LabOnly, fixture-free probes may run. A new probe must be
// added here deliberately.
var clientModeAllowed = []string{
	ProbeCheckReadOnlyIdentity, "auth_check", "read_audit_config", "read_grants", "read_restricted_table", "read_roles",
}

func TestClientModeAllowedProbeSetIsExact(t *testing.T) {
	all := Policy{ClientEnabled: true, LabMutationAllowed: true}
	var got []string
	for _, id := range ProbeIDs() {
		d, _ := LookupProbe(id)
		s := validSpec()
		s.ProbeID, s.Mode, s.FixtureID = id, ModeClient, d.RequiredFixture
		if d.FixtureParam != "" {
			s.FixtureID = "accounts"
		}
		if err := CheckSpec(s, d, "7001", "7001", all); err == nil {
			got = append(got, id)
			if d.Class != ClassReadOnly || d.LabOnly || d.FixtureParam != "" || d.RequiredFixture != "" {
				t.Errorf("%s allowed in client mode but is not a plain read-only probe", id)
			}
		}
		// A non-read-only probe is refused even for a mislabelled definition.
		if d.Class != ClassReadOnly {
			label := d
			label.Class = ClassReadOnly
			if CheckSpec(s, label, "7001", "7001", all) == nil {
				t.Errorf("%s: mislabelled definition accepted in client mode", id)
			}
		}
	}
	sort.Strings(got)
	want := append([]string(nil), clientModeAllowed...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("client-mode probe set\n got  %v\n want %v", got, want)
	}
}

func TestIdentityChecksNote(t *testing.T) {
	if got, want := IdentityChecksNote(IdentityNo, IdentityYes, IdentityUnknown, IdentityNo),
		"identity_checks=can_write=no,can_ddl=yes,can_admin=unknown,can_audit=no"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestIdentityVerdictNeverClearOnUnknown(t *testing.T) {
	cases := []struct {
		w, d, a, au string
		class       string
	}{
		{IdentityNo, IdentityNo, IdentityNo, IdentityNo, ""},
		{IdentityYes, IdentityNo, IdentityNo, IdentityNo, ""}, // a definite finding
		{IdentityNo, IdentityUnknown, IdentityNo, IdentityNo, "identity_check_incomplete"},
		{"", IdentityNo, IdentityNo, IdentityNo, "identity_check_incomplete"},
		{IdentityYes, IdentityUnknown, IdentityNo, IdentityNo, ""},
	}
	for _, c := range cases {
		if got := IdentityVerdict(c.w, c.d, c.a, c.au); got != c.class {
			t.Errorf("%+v -> %q, want %q", c, got, c.class)
		}
	}
}

func rows(spec ...string) []PrivRow {
	var out []PrivRow
	for _, s := range spec {
		p := strings.SplitN(s, "|", 3)
		out = append(out, PrivRow{Scope: p[0], Schema: p[1], Privilege: p[2]})
	}
	return out
}

func TestClassifyMySQLPrivileges(t *testing.T) {
	cases := []struct {
		name string
		in   []PrivRow
		want [4]string // write, ddl, admin, audit
	}{
		{"usage only", rows("G||USAGE"), [4]string{"no", "no", "no", "no"}},
		{"select everywhere", rows("G||USAGE", "S|app|SELECT", "T|app|SELECT", "C|app|SELECT", "G||SHOW VIEW"), [4]string{"no", "no", "no", "no"}},
		{"global insert", rows("G||USAGE", "G||INSERT"), [4]string{"yes", "no", "no", "yes"}},
		{"schema update on app", rows("G||USAGE", "S|app|UPDATE"), [4]string{"yes", "no", "no", "no"}},
		{"table delete on mysql schema", rows("G||USAGE", "T|mysql|DELETE"), [4]string{"yes", "no", "no", "yes"}},
		{"wildcard schema write", rows("G||USAGE", "S|%|INSERT"), [4]string{"yes", "no", "no", "yes"}},
		{"column insert", rows("G||USAGE", "C|app|INSERT"), [4]string{"yes", "no", "no", "no"}},
		{"alter on app", rows("G||USAGE", "S|app|ALTER"), [4]string{"no", "yes", "no", "no"}},
		{"global drop", rows("G||USAGE", "G||DROP"), [4]string{"no", "yes", "no", "yes"}},
		{"create user", rows("G||USAGE", "G||CREATE USER"), [4]string{"no", "no", "yes", "no"}},
		{"grant option", rows("G||USAGE", "G||GRANT OPTION"), [4]string{"no", "no", "yes", "no"}},
		{"dynamic admin", rows("G||USAGE", "G||CONNECTION_ADMIN"), [4]string{"no", "no", "yes", "no"}},
		{"audit admin", rows("G||USAGE", "G||AUDIT_ADMIN"), [4]string{"no", "no", "yes", "yes"}},
		{"system variables admin", rows("G||USAGE", "G||SYSTEM_VARIABLES_ADMIN"), [4]string{"no", "no", "yes", "yes"}},
		{"super", rows("G||SUPER"), [4]string{"yes", "yes", "yes", "yes"}},
		{"all privileges", rows("G||ALL PRIVILEGES"), [4]string{"yes", "yes", "yes", "yes"}},
		// An unrecognised privilege could be anything: nothing that is not yes becomes no.
		{"unknown privilege", rows("G||USAGE", "G||SOMETHING_NEW"), [4]string{"unknown", "unknown", "unknown", "unknown"}},
		{"unknown does not hide a yes", rows("G||INSERT", "G||SOMETHING_NEW"), [4]string{"yes", "unknown", "unknown", "yes"}},
		{"lower case is normalised", rows("g||usage", "s|App|insert"), [4]string{"yes", "no", "no", "no"}},
		// No grantee row at all means the match failed: unobservable, never "holds nothing".
		{"no rows", nil, [4]string{"unknown", "unknown", "unknown", "unknown"}},
		{"bad scope", rows("X||SELECT"), [4]string{"unknown", "unknown", "unknown", "unknown"}},
	}
	for _, c := range cases {
		w, d, a, au := ClassifyMySQLPrivileges(c.in)
		if got := [4]string{w, d, a, au}; got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
