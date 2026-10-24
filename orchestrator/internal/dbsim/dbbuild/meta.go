package dbbuild

import (
	"fmt"

	"github.com/audspect/bas/internal/dbsim"
	"github.com/audspect/bas/internal/scenario"
)

// probeText is the fixed per-probe wording used for the report meta. The
// shipped scenarios carry no structured objective/precondition fields (only a
// free-text description), so the text is fixed per probe.
var probeText = map[string]struct{ objective, action string }{
	"auth_check":              {"Authentication policy of the database account is enforced", "named probe auth_check (read-only authentication check)"},
	"read_roles":              {"Database roles are enumerable and reviewed", "named probe read_roles (read-only role listing)"},
	"read_grants":             {"Granted privileges conform to the stated access policy", "named probe read_grants (read-only grant listing compared with policy)"},
	"read_restricted_table":   {"An account without access cannot read a restricted table", "named probe read_restricted_table (read of a table the account must not read)"},
	"read_audit_config":       {"Database auditing is configured and covers security-relevant events", "named probe read_audit_config (read-only audit configuration summary)"},
	"suspicious_read":         {"A suspicious read of a synthetic fixture is detected", "named probe suspicious_read (read of a seeded synthetic fixture)"},
	"auth_after_revoke":       {"A revoked account can no longer authenticate", "named probe auth_after_revoke (new login attempt after the revoke)"},
	"read_classified_fixture": {"A read of sensitive-looking data is recognised by data classification", "named probe read_classified_fixture (bounded read of a synthetic classified table)"},
	"try_disable_audit":       {"A session cannot switch off or weaken database auditing", "named probe try_disable_audit (attempt to disable auditing in the session scope)"},
	"bounded_synthetic_read":  {"A bounded bulk read of synthetic data is detected", "named probe bounded_synthetic_read (bounded read of a seeded synthetic fixture)"},
	"try_write_fixture":       {"A restricted account cannot write or delete data", "named probe try_write_fixture (attempted write against a synthetic fixture)"},
	"check_export_privileges": {"The account does not hold backup or export privileges", "named probe check_export_privileges (read-only catalog check)"},
}

// MetaFor builds the report meta for one compiled probe step of a shipped
// scenario, with the expectations from dbsim.ExpectationFor. It fails closed:
// a nil scenario, a scenario outside the dbsim product line, an unknown
// scenario id or a probe without an expectation is an error.
func MetaFor(sc *scenario.Scenario, spec dbsim.DBProbeSpec) (dbsim.ScenarioMeta, error) {
	if sc == nil {
		return dbsim.ScenarioMeta{}, fmt.Errorf("dbbuild: nil scenario")
	}
	if sc.ProductLine != scenario.ProductLineDBSim {
		return dbsim.ScenarioMeta{}, fmt.Errorf("dbbuild: scenario %q is not a dbsim scenario", sc.ID)
	}
	e, ok := dbsim.ExpectationFor(sc.ID, spec.ProbeID)
	if !ok {
		return dbsim.ScenarioMeta{}, fmt.Errorf("dbbuild: no expectation for scenario %q probe %q", sc.ID, spec.ProbeID)
	}
	txt, ok := probeText[spec.ProbeID]
	if !ok {
		return dbsim.ScenarioMeta{}, fmt.Errorf("dbbuild: no description for probe %q", spec.ProbeID)
	}
	return dbsim.ScenarioMeta{
		ID: sc.ID, Version: "1",
		ControlObjective:      txt.objective,
		Preconditions:         "Confirmed lab or approved target registered server-side; agent-local dbsim allowance in place",
		SyntheticDataManifest: "Synthetic data only; no real data is read, written or retained",
		ActionAttempted:       txt.action,
		ExpectedPrevention:    e.ExpectedPrevention,
		ExpectDetection:       e.ExpectDetection, ExpectResponse: e.ExpectDetection,
		ExpectAudit: e.ExpectAudit, ExpectAuditConfig: e.ExpectAuditConfig,
		RequireObservation: e.RequireObservation, RequirePolicyDiff: e.RequirePolicyDiff,
		ExpectClassification: e.ExpectClassification,
		Engine:               spec.Engine, TargetID: spec.TargetID, Mode: spec.Mode,
	}, nil
}
