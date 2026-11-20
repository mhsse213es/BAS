package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"audspect/agent/dbprobe"
)

// runAuditRoleRoundtrip is DB-04-06. It grants SELECT on the fixture accounts
// table to the fixture role, then revokes it, each statement in its own
// transaction and tagged with the marker. The schema is dropped by fixture
// teardown whatever happens here, so a failed revoke cannot outlive the run.
// Lab mode only, and only with the run's seeded fixture.
func (a *Adapter) runAuditRoleRoundtrip(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	fx, err := a.labFixture(def, spec, mode)
	if err != nil {
		return res, err
	}
	schema, role, err := fixtureNames(fx.ID)
	if err != nil {
		return res, err
	}
	qtbl, err := quoteTable(schema + ".accounts")
	if err != nil {
		return res, err
	}
	qrole := pgx.Identifier{role}.Sanitize()
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	step := func(sql string) error {
		return a.inTxn(ctx, a.mode, dbprobe.ClassBoundedSynthetic, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
			return a.s.Exec(ctx, comment+sql)
		})
	}
	if err := step("GRANT SELECT ON " + qtbl + " TO " + qrole); err != nil {
		res.ErrorClass = "role_grant_failed"
		res.Notes = append(res.Notes, "role: granted=failed revoked=skipped")
		return res, err
	}
	if err := step("REVOKE SELECT ON " + qtbl + " FROM " + qrole); err != nil {
		res.ErrorClass = "role_revoke_failed"
		res.Notes = append(res.Notes, "role: granted=ok revoked=failed")
		return res, err
	}
	res.Notes = append(res.Notes, "role: granted=ok revoked=ok")
	return res, nil
}
