package dbsim

import "fmt"

// ProbeCheckReadOnlyIdentity is the catalog probe whose result decides whether a
// registered target may ever run in client mode (spec R4/R8). It is a plain
// read_only, parameter-free probe, allowed in client mode and lab mode.
const ProbeCheckReadOnlyIdentity = "check_readonly_identity"

// Values of the check_readonly_identity note
// "identity_checks=can_write=<v>,can_ddl=<v>,can_admin=<v>,can_audit=<v>" (same
// strings as the agent's dbprobe.Identity* constants).
const (
	IdentityChecksKey = "identity_checks"

	IdentityYes     = "yes"
	IdentityNo      = "no"
	IdentityUnknown = "unknown"
)

// IdentityChecks is the parsed identity_checks note.
type IdentityChecks struct {
	CanWrite, CanDDL, CanAdmin, CanAudit string
}

// IdentityChecks returns the parsed check_readonly_identity note (strict: every
// field present exactly once with a known value, nothing else).
func (n Notes) IdentityChecks() (IdentityChecks, bool) {
	v, ok := n.kv[IdentityChecksKey]
	if !ok {
		return IdentityChecks{}, false
	}
	three := oneOf(IdentityYes, IdentityNo, IdentityUnknown)
	m, ok := strictKV(v, map[string]func(string) bool{
		"can_write": three, "can_ddl": three, "can_admin": three, "can_audit": three,
	})
	if !ok {
		return IdentityChecks{}, false
	}
	return IdentityChecks{CanWrite: m["can_write"], CanDDL: m["can_ddl"], CanAdmin: m["can_admin"], CanAudit: m["can_audit"]}, true
}

// IdentityCheckResult is the verdict of the read-only identity check.
type IdentityCheckResult struct {
	// Passed is true only when every capability was positively observed to be
	// absent. It is the value stored as the target's "last identity check".
	Passed bool
	// Reasons lists why the check did not pass (empty when it passed). The text
	// names capabilities and never contains row data or credentials.
	Reasons []string
}

// EvaluateReadOnlyIdentity decides whether the account a check_readonly_identity
// probe connected as is a read-only identity.
//
// It PASSES only when all of these hold: the engine is supported; the result
// carries no error class, denial, safety incident or residual cleanup; and the
// strict identity_checks note says "no" to all four questions (can this account
// write data, change the schema, administer accounts or touch audit settings).
//
// It FAILS, never passes, on anything else: a missing, malformed, duplicated or
// partial note; any "yes"; any "unknown" (an unobservable capability is not an
// absent one); a later forged note (the first occurrence wins).
//
// What it checks is exactly what the probe reports: table/column write
// privileges, schema CREATE/ALTER/DROP/ownership, superuser/role-administration
// attributes and audit-parameter control (see agent/dbprobe/postgres/identity.go
// and mysql/identity.go). What it does NOT check: sequence/function/large-object
// privileges, privileges reachable only through a role the session has not
// activated, row-level security effects, or anything about the network path.
// A passing check is evidence about the account at check time, not a guarantee
// for later; the target registry records when and by whom it was taken.
func EvaluateReadOnlyIdentity(engine string, res DBProbeResult) IdentityCheckResult {
	var reasons []string
	fail := func(f string, a ...any) { reasons = append(reasons, fmt.Sprintf(f, a...)) }
	if engine != "postgresql" && engine != "mysql" {
		fail("engine %q is not supported", engine)
	}
	if res.ErrorClass != "" {
		fail("probe reported error class %q", res.ErrorClass)
	}
	if res.Denied {
		fail("probe was denied")
	}
	if res.SafetyIncident {
		fail("probe reported a safety incident")
	}
	if res.CleanupStatus != "" && res.CleanupStatus != CleanupNotApplicable {
		fail("unexpected cleanup status %q", res.CleanupStatus)
	}
	c, ok := ParseNotes(res.Notes).IdentityChecks()
	if !ok {
		fail("no well-formed identity_checks observation")
		return IdentityCheckResult{Reasons: reasons}
	}
	for _, q := range []struct{ name, v string }{
		{"can write data", c.CanWrite}, {"can change the schema", c.CanDDL},
		{"can administer accounts", c.CanAdmin}, {"can change audit settings", c.CanAudit},
	} {
		switch q.v {
		case IdentityNo:
		case IdentityYes:
			fail("identity %s", q.name)
		default:
			fail("could not observe whether the identity %s", q.name)
		}
	}
	return IdentityCheckResult{Passed: len(reasons) == 0, Reasons: reasons}
}
