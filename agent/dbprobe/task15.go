package dbprobe

import "strconv"

// Probe ids and fixed fixture addressing of the Task 15 probes (DB-08, DB-10,
// DB-11). All three are lab-only. None takes a parameter: nothing a caller sends
// can select a statement, a table, a setting or a mode.
const (
	ProbeTryDisableAudit       = "try_disable_audit"
	ProbeTryWriteFixture       = "try_write_fixture"
	ProbeCheckExportPrivileges = "check_export_privileges"

	// AuditTamperFixtureKind is the (otherwise unused) fixture try_disable_audit
	// rides on, as auth_after_revoke does: its id names the throwaway account and
	// the fixture lifecycle gives the account verified cleanup.
	AuditTamperFixtureKind = "empty"
	// WriteFixtureKind / WriteFixtureTable are the fixture and table
	// try_write_fixture attacks (fixtures.KindAccounts and its accounts table; a
	// fixtures test pins the equality).
	WriteFixtureKind  = "accounts"
	WriteFixtureTable = "accounts"
)

// auditTamperSQL is the COMPLETE list of statements try_disable_audit can run to
// tamper with auditing: one per engine, both SESSION scoped. There is no
// ALTER SYSTEM, SET GLOBAL, SET PERSIST, plugin or configuration-file change and
// no parameter, mode or code path that selects another statement. A statement
// that succeeds only changes the throwaway account's own connection, which is
// closed immediately afterwards.
var auditTamperSQL = map[string]string{
	"postgresql": "SET log_statement = 'none'",
	"mysql":      "SET SESSION sql_log_off = 1",
}

// AuditTamperStatement returns the fixed session-scoped statement for engine.
func AuditTamperStatement(engine string) (string, bool) {
	s, ok := auditTamperSQL[engine]
	return s, ok
}

// AuditTamperStatements returns every statement the audit probe can ever run.
func AuditTamperStatements() []string {
	out := make([]string, 0, len(auditTamperSQL))
	for _, s := range auditTamperSQL {
		out = append(out, s)
	}
	return out
}

// The three write attempts of try_write_fixture, fixed text. The single %s is the
// quoted, adapter-resolved name of the active fixture's accounts table; nothing
// else is variable. They are expected to be DENIED for a SELECT-only account.
const (
	WriteInsertSQL = "INSERT INTO %s (id, synthetic, account_ref, display_name, email, balance_cents) " +
		"VALUES (9001, 'BAS-SIM-WRITE', 'BAS-SIM-ACCT-9001', 'BAS-SIM Write Attempt', 'bas-sim-write@example.invalid', 1)"
	WriteUpdateSQL = "UPDATE %s SET balance_cents = balance_cents + 1 WHERE id = 1"
	WriteDeleteSQL = "DELETE FROM %s WHERE id = 2"
)

// Step outcomes of try_disable_audit, reported in one typed note
// "audit_tamper_steps=create=<v>,baseline=<v>,attempt=<v>". The orchestrator
// parses it with dbsim.Notes.AuditTamper (same vocabulary).
const (
	AuditTamperStepsKey = "audit_tamper_steps"

	TamperStepOK      = "ok"
	TamperStepFailed  = "failed"
	TamperStepSkipped = "skipped"

	// Attempt outcomes.
	TamperAttemptDenied  = "denied"  // the engine refused with the exact permission code
	TamperAttemptAllowed = "allowed" // the session-scoped statement succeeded
	TamperAttemptError   = "error"   // any other failure: never read as a denial
)

// AuditTamperStepsNote renders the try_disable_audit step note.
func AuditTamperStepsNote(create, baseline, attempt string) string {
	return AuditTamperStepsKey + "=create=" + create + ",baseline=" + baseline + ",attempt=" + attempt
}

// Step outcomes of try_write_fixture, reported in one typed note
// "write_attempt_steps=insert=<v>,update=<v>,delete=<v>,fingerprint=<v>".
const (
	WriteAttemptStepsKey = "write_attempt_steps"

	WriteDenied  = "denied"
	WriteAllowed = "allowed"
	WriteError   = "error"
	WriteSkipped = "skipped"

	// Fingerprint outcomes (state of the fixture table before vs after).
	FingerprintUnchanged = "unchanged"
	FingerprintChanged   = "changed"
	FingerprintError     = "error"
	FingerprintSkipped   = "skipped"

	// WriteFixtureChangedKey is added (as "fixture_changed=true") when any write
	// succeeded: the fixture is dirty.
	WriteFixtureChangedKey = "fixture_changed"
)

// WriteAttemptStepsNote renders the try_write_fixture step note.
func WriteAttemptStepsNote(insert, update, del, fingerprint string) string {
	return WriteAttemptStepsKey + "=insert=" + insert + ",update=" + update + ",delete=" + del + ",fingerprint=" + fingerprint
}

// Values of the check_export_privileges note
// "export_checks=file_write=<v>,program_exec=<v>,file_read=<v>,bulk_select=<v>,dump_privs=<v>".
const (
	ExportChecksKey = "export_checks"

	ExportYes     = "yes"
	ExportNo      = "no"
	ExportUnknown = "unknown" // the check could not be observed
	ExportNA      = "na"      // the engine has no such privilege (MySQL program_exec)
)

// ExportChecksNote renders the check_export_privileges typed note. dumpPrivs is
// a count rendered by the caller, or ExportUnknown.
func ExportChecksNote(fileWrite, programExec, fileRead, bulkSelect, dumpPrivs string) string {
	return ExportChecksKey + "=file_write=" + fileWrite + ",program_exec=" + programExec +
		",file_read=" + fileRead + ",bulk_select=" + bulkSelect + ",dump_privs=" + dumpPrivs
}

// ExportCount renders a non-negative count for the dump_privs field.
func ExportCount(n int64) string {
	if n < 0 {
		return ExportUnknown
	}
	return strconv.FormatInt(n, 10)
}

// ExportVerdict grades the five export checks into the result fields. Any of the
// three server-file/program capabilities held is Allowed (Denied=false, no error
// class: a definite finding even if another check was unobservable). Otherwise
// every check must have been observed; one that was not makes the result an
// incomplete observation (error class set), never a clear one.
func ExportVerdict(fileWrite, programExec, fileRead, bulkSelect, dumpPrivs string) (errorClass string, denied bool) {
	if fileWrite == ExportYes || programExec == ExportYes || fileRead == ExportYes {
		return "", false
	}
	for _, v := range []string{fileWrite, programExec, fileRead, bulkSelect, dumpPrivs} {
		if v == ExportUnknown || v == "" {
			return "export_check_incomplete", false
		}
	}
	return "", true
}
