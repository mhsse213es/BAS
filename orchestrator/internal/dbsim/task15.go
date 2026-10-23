package dbsim

import "fmt"

// Task 15 grading helpers (DB-08 try_disable_audit, DB-10 try_write_fixture,
// DB-11 check_export_privileges). Enforcement comes only from complete, mutually
// consistent evidence (the typed step note AND the result fields); anything
// missing, malformed or contradictory is not evidence, so the result is
// Enforcement Unknown and the run is never a PASS. A definite finding (a
// permitted tamper statement, a permitted write, a held privilege) is Allowed
// even when other evidence is missing (ruling R-U).

// Fixed limitation sentences recorded on every result of the probe.
const (
	tamperLimitation = "DB-08 attempts ONLY a session-scoped audit change (PostgreSQL SET log_statement, MySQL SET SESSION sql_log_off) as a throwaway no-privilege account. No global or persistent audit disablement (ALTER SYSTEM, SET GLOBAL/PERSIST, plugin or configuration change) and no recovery-plan mode exists in this product; actual audit disablement is NOT tested. A denied statement is expected to be audit-logged with the marker, but that is unverified until the lab shows it."
	writeLimitation  = "DB-10 attempts one INSERT, UPDATE and DELETE as a throwaway SELECT-only account on the synthetic accounts fixture. Prevention is graded from the exact permission-denied codes and an unchanged table fingerprint (row count and checksum computed on the server); a denied statement is expected to be audit-logged with the marker, but that is unverified until the lab shows it."
	exportLimitation = "DB-11 reads the catalog privileges of the connected account only; no export, backup, file or program operation is performed and no SIEM expectation applies. The specification's \"controlled operation if authorized\" mode is NOT built. Privileges that arrive through database roles may not be visible and are then reported unknown."
)

// task15Limitation is the fixed sentence for the probe, or "".
func task15Limitation(probeID string) string {
	switch probeID {
	case ProbeTryDisableAudit:
		return tamperLimitation
	case ProbeTryWriteFixture:
		return writeLimitation
	case ProbeCheckExportPrivileges:
		return exportLimitation
	}
	return ""
}

// task15Gap returns a non-empty reason when the probe's result does not carry
// complete, consistent evidence for an Enforcement verdict.
func task15Gap(o Outcome) string {
	if !o.ProbeRan {
		return ""
	}
	switch o.ProbeID {
	case ProbeTryDisableAudit:
		return tamperGap(o)
	case ProbeTryWriteFixture:
		return writeGap(o)
	case ProbeCheckExportPrivileges:
		return exportGap(o)
	}
	return ""
}

// Task15EvidenceGap is task15Gap for the wiring layer: when it is non-empty the
// statement evidence is incomplete, so a missing SIEM alert says nothing about
// detection and no correlation is attempted.
func Task15EvidenceGap(o Outcome) string { return task15Gap(o) }

func tamperGap(o Outcome) string {
	r, ok := ParseNotes(o.Probe.Notes).AuditTamper()
	switch {
	case !ok:
		return "the create/baseline/attempt step note is missing or malformed"
	case r.Create != TamperStepOK || r.Baseline != TamperStepOK:
		return fmt.Sprintf("a precondition step did not succeed (create=%s baseline=%s)", r.Create, r.Baseline)
	case r.Attempt == TamperAttemptDenied && !o.Probe.Denied:
		return "the step note reports a denial the result does not"
	case r.Attempt == TamperAttemptAllowed && (o.Probe.Denied || o.Probe.ErrorClass != ""):
		return "the step note reports a permitted statement the result contradicts"
	case r.Attempt != TamperAttemptDenied && r.Attempt != TamperAttemptAllowed:
		return "the attempt outcome is " + r.Attempt
	}
	return ""
}

func writeGap(o Outcome) string {
	r, ok := ParseNotes(o.Probe.Notes).WriteAttempts()
	if !ok {
		return "the insert/update/delete/fingerprint step note is missing or malformed"
	}
	changed, haveChanged := ParseNotes(o.Probe.Notes).Bool(WriteFixtureChangedKey)
	anyAllowed, allDenied := false, true
	for _, v := range r.Outcomes() {
		if v == WriteAllowed {
			anyAllowed = true
		}
		if v != WriteDenied {
			allDenied = false
		}
	}
	if anyAllowed {
		// A permitted write is a definite finding whatever else was or was not
		// observed; the result fields must agree with it.
		if o.Probe.Denied || o.Probe.ErrorClass != "" {
			return "the step note reports a permitted write the result contradicts"
		}
		return ""
	}
	if haveChanged && changed {
		return "fixture_changed=true is reported although every write is recorded as not permitted"
	}
	if !allDenied {
		return fmt.Sprintf("a write attempt was not observed as denied (insert=%s update=%s delete=%s)", r.Insert, r.Update, r.Delete)
	}
	if r.Fingerprint != FingerprintUnchanged {
		return "fixture state check inconsistent: every write was reported denied but the fingerprint is " + r.Fingerprint
	}
	if !o.Probe.Denied {
		return "the step note reports three denials the result does not"
	}
	return ""
}

func exportGap(o Outcome) string {
	r, ok := ParseNotes(o.Probe.Notes).ExportChecks()
	if !ok {
		return "the export_checks note is missing or malformed"
	}
	if r.Held() {
		if o.Probe.Denied || o.Probe.ErrorClass != "" {
			return "the export_checks note reports a held privilege the result contradicts"
		}
		return ""
	}
	if !r.Complete() {
		return "an export check could not be observed"
	}
	if !o.Probe.Denied {
		return "the export_checks note reports no privilege held but the result is not clear"
	}
	return ""
}

// writeDirty reports whether try_write_fixture accepted a write (the fixture is
// dirty).
func writeDirty(o Outcome) bool {
	if o.ProbeID != ProbeTryWriteFixture || !o.ProbeRan {
		return false
	}
	r, ok := ParseNotes(o.Probe.Notes).WriteAttempts()
	if !ok {
		return false
	}
	for _, v := range r.Outcomes() {
		if v == WriteAllowed {
			return true
		}
	}
	return false
}
