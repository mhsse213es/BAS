package dbsim

import (
	"strings"
	"testing"
)

func identityResult(note string) DBProbeResult {
	return DBProbeResult{Notes: []string{"rows_read=0", note}}
}

const clearNote = "identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no"

func TestIdentityProbeIsInTheRegistryAsPlainReadOnly(t *testing.T) {
	e, ok := LookupProbeEntry(ProbeCheckReadOnlyIdentity)
	if !ok {
		t.Fatal("registry has no check_readonly_identity")
	}
	if e.Class != ClassReadOnly || e.LabOnly || e.FixtureParam != "" || e.RequiredFixture != "" || len(e.ParamSchema) != 0 {
		t.Fatalf("must be a plain parameter-free read_only probe: %+v", e)
	}
}

func TestEvaluateReadOnlyIdentityPassesOnlyWhenEveryCapabilityIsNo(t *testing.T) {
	v := EvaluateReadOnlyIdentity("postgresql", identityResult(clearNote))
	if !v.Passed || len(v.Reasons) != 0 {
		t.Fatalf("a clear identity must pass: %+v", v)
	}
	if v := EvaluateReadOnlyIdentity("mysql", identityResult(clearNote)); !v.Passed {
		t.Fatalf("mysql: %+v", v)
	}
}

func TestEvaluateReadOnlyIdentityFailsOnAnyCapability(t *testing.T) {
	for _, c := range []struct{ note, reason string }{
		{"identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=no", "write"},
		{"identity_checks=can_write=no,can_ddl=yes,can_admin=no,can_audit=no", "schema"},
		{"identity_checks=can_write=no,can_ddl=no,can_admin=yes,can_audit=no", "administer"},
		{"identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=yes", "audit"},
		{"identity_checks=can_write=yes,can_ddl=yes,can_admin=yes,can_audit=yes", "write"},
	} {
		v := EvaluateReadOnlyIdentity("postgresql", identityResult(c.note))
		if v.Passed || len(v.Reasons) == 0 || !strings.Contains(strings.Join(v.Reasons, ";"), c.reason) {
			t.Errorf("%s: %+v", c.note, v)
		}
	}
}

// Default-safe: missing, malformed, partial, unknown or contradictory evidence
// can never pass.
func TestEvaluateReadOnlyIdentityNeverPassesOnMissingEvidence(t *testing.T) {
	cases := map[string]DBProbeResult{
		"no notes":       {},
		"other notes":    {Notes: []string{"rows_read=3"}},
		"unknown value":  identityResult("identity_checks=can_write=unknown,can_ddl=no,can_admin=no,can_audit=no"),
		"all unknown":    identityResult("identity_checks=can_write=unknown,can_ddl=unknown,can_admin=unknown,can_audit=unknown"),
		"missing field":  identityResult("identity_checks=can_write=no,can_ddl=no,can_admin=no"),
		"extra field":    identityResult("identity_checks=can_write=no,can_ddl=no,can_admin=no,can_audit=no,can_x=no"),
		"empty value":    identityResult("identity_checks=can_write=,can_ddl=no,can_admin=no,can_audit=no"),
		"na not allowed": identityResult("identity_checks=can_write=na,can_ddl=no,can_admin=no,can_audit=no"),
		"upper case":     identityResult("identity_checks=can_write=No,can_ddl=no,can_admin=no,can_audit=no"),
		"duplicate key":  identityResult("identity_checks=can_write=no,can_write=no,can_admin=no,can_audit=no"),
		"error class":    {Notes: []string{clearNote}, ErrorClass: "identity_check_incomplete"},
		"other error":    {Notes: []string{clearNote}, ErrorClass: "connect_failed"},
		"denied":         {Notes: []string{clearNote}, Denied: true},
		"safety":         {Notes: []string{clearNote}, SafetyIncident: true},
		"residual":       {Notes: []string{clearNote}, CleanupStatus: CleanupResidual},
	}
	for name, res := range cases {
		if v := EvaluateReadOnlyIdentity("postgresql", res); v.Passed || len(v.Reasons) == 0 {
			t.Errorf("%s: must not pass: %+v", name, v)
		}
	}
	// Unsupported engine never passes.
	if v := EvaluateReadOnlyIdentity("oracle", identityResult(clearNote)); v.Passed {
		t.Error("an unsupported engine must not pass")
	}
	// The first occurrence of the note wins; a later forged clear line cannot override it.
	res := DBProbeResult{Notes: []string{"identity_checks=can_write=yes,can_ddl=no,can_admin=no,can_audit=no", clearNote}}
	if v := EvaluateReadOnlyIdentity("postgresql", res); v.Passed {
		t.Error("a later forged clear note overrode the first one")
	}
}
