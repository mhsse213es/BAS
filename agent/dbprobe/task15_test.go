package dbprobe

import (
	"strings"
	"testing"
)

func TestTask15ProbesAreCataloged(t *testing.T) {
	for _, c := range []struct {
		id      string
		class   ProbeClass
		fixture string
		labOnly bool
	}{
		{ProbeTryDisableAudit, ClassBoundedSynthetic, AuditTamperFixtureKind, false},
		{ProbeTryWriteFixture, ClassBoundedSynthetic, WriteFixtureKind, false},
		{ProbeCheckExportPrivileges, ClassReadOnly, "", true},
	} {
		d, ok := LookupProbe(c.id)
		if !ok || d.Class != c.class || d.RequiredFixture != c.fixture || d.LabOnly != c.labOnly {
			t.Fatalf("%s: %+v ok=%v", c.id, d, ok)
		}
		// No parameter selects a statement, a table or a mode.
		if len(d.ParamSchema) != 0 || d.FixtureParam != "" || d.FixedTable != "" || len(d.Engines) != 2 {
			t.Errorf("%s must take no parameter and support both engines: %+v", c.id, d)
		}
		if d.Class == ClassMutation {
			t.Errorf("%s must never be class mutation (B5 would veto it; user decision option A)", c.id)
		}
	}
}

// DB-08 is the SESSION-scoped attempt only. The registry exposes no parameter,
// mode or recovery plan that could turn it into a global or persistent change,
// and the fixed statement list contains no such statement.
func TestAuditProbeHasNoPersistentOrGlobalDisablePath(t *testing.T) {
	d, _ := LookupProbe(ProbeTryDisableAudit)
	if len(d.ParamSchema) != 0 {
		t.Fatalf("the audit probe must expose no parameter: %v", d.ParamSchema)
	}
	s := validSpec()
	s.ProbeID, s.Mode, s.FixtureID = ProbeTryDisableAudit, ModeLab, AuditTamperFixtureKind
	for _, p := range []string{"statement", "sql", "mode", "recovery_plan", "actual", "global", "persist", "setting", "param"} {
		s.Params = map[string]string{p: "x"}
		if ValidateSpec(s) == nil {
			t.Errorf("parameter %q accepted by the audit probe", p)
		}
	}
	want := map[string]string{
		"postgresql": "SET log_statement = 'none'",
		"mysql":      "SET SESSION sql_log_off = 1",
	}
	for eng, sql := range want {
		got, ok := AuditTamperStatement(eng)
		if !ok || got != sql {
			t.Errorf("%s: statement %q ok=%v, want exactly %q", eng, got, ok, sql)
		}
		up := strings.ToUpper(got)
		for _, bad := range []string{"ALTER SYSTEM", "GLOBAL", "PERSIST", "RELOAD", "PLUGIN", "CONFIG", "INSTALL", "UNINSTALL"} {
			if strings.Contains(up, bad) {
				t.Errorf("%s: statement %q contains forbidden %q", eng, got, bad)
			}
		}
	}
	if _, ok := AuditTamperStatement("oracle"); ok {
		t.Error("an unknown engine must have no statement")
	}
	if n := len(AuditTamperStatements()); n != 2 {
		t.Errorf("the fixed list must be exactly the two session statements, got %d", n)
	}
}

func TestMutationProbesRefusedInClientMode(t *testing.T) {
	all := Policy{ClientEnabled: true, LabMutationAllowed: true}
	for _, id := range []string{ProbeTryDisableAudit, ProbeTryWriteFixture, ProbeCheckExportPrivileges} {
		d, _ := LookupProbe(id)
		s := validSpec()
		s.ProbeID, s.FixtureID = id, d.RequiredFixture
		s.Mode = ModeClient
		if err := ValidateSpec(s); err == nil {
			t.Errorf("%s: ValidateSpec accepted client mode", id)
		}
		if err := CheckSpec(s, d, "7001", "7001", all); err == nil {
			t.Errorf("%s: CheckSpec accepted client mode", id)
		}
		s.Mode = ModeLab
		if err := ValidateSpec(s); err != nil {
			t.Errorf("%s: lab spec rejected: %v", id, err)
		}
		if err := CheckSpec(s, d, "7001", "7001", Policy{}); err == nil {
			t.Errorf("%s: lab mode without the agent-local allowance accepted", id)
		}
		if err := CheckSpec(s, d, "7001", "7001", Policy{LabMutationAllowed: true}); err != nil {
			t.Errorf("%s: lab + allowance refused: %v", id, err)
		}
	}
}

func TestTask15RequiredFixtures(t *testing.T) {
	for _, c := range []struct{ probe, fixture string }{
		{ProbeTryDisableAudit, AuditTamperFixtureKind},
		{ProbeTryWriteFixture, WriteFixtureKind},
	} {
		s := validSpec()
		s.ProbeID, s.Mode, s.FixtureID = c.probe, ModeLab, ""
		if ValidateSpec(s) == nil {
			t.Errorf("%s without its fixture accepted", c.probe)
		}
		s.FixtureID = "classified-pii"
		if ValidateSpec(s) == nil {
			t.Errorf("%s with the wrong fixture accepted", c.probe)
		}
	}
	// DB-11 reads no fixture; naming one is refused.
	s := validSpec()
	s.ProbeID, s.Mode, s.FixtureID = ProbeCheckExportPrivileges, ModeLab, "accounts"
	if ValidateSpec(s) == nil {
		t.Error("check_export_privileges accepted a fixture id")
	}
}

func TestTask15StepNotesRender(t *testing.T) {
	if got := AuditTamperStepsNote("ok", "ok", "denied"); got != "audit_tamper_steps=create=ok,baseline=ok,attempt=denied" {
		t.Errorf("%q", got)
	}
	if got := WriteAttemptStepsNote("denied", "denied", "denied", "unchanged"); got != "write_attempt_steps=insert=denied,update=denied,delete=denied,fingerprint=unchanged" {
		t.Errorf("%q", got)
	}
	if got := ExportChecksNote("no", "no", "no", "no", "12"); got != "export_checks=file_write=no,program_exec=no,file_read=no,bulk_select=no,dump_privs=12" {
		t.Errorf("%q", got)
	}
}

func TestWriteStatementsAreFixedAndTargetOnlyTheResolvedTable(t *testing.T) {
	for _, sql := range []string{WriteInsertSQL, WriteUpdateSQL, WriteDeleteSQL} {
		if strings.Count(sql, "%s") != 1 {
			t.Errorf("%q must have exactly one table placeholder", sql)
		}
		up := strings.ToUpper(sql)
		for _, bad := range []string{"DROP", "TRUNCATE", "ALTER", "GRANT", "CREATE", ";"} {
			if strings.Contains(up, bad) {
				t.Errorf("%q contains %q", sql, bad)
			}
		}
	}
	if !strings.HasPrefix(WriteInsertSQL, "INSERT INTO ") || !strings.HasPrefix(WriteUpdateSQL, "UPDATE ") || !strings.HasPrefix(WriteDeleteSQL, "DELETE FROM ") {
		t.Error("statement kinds")
	}
}
