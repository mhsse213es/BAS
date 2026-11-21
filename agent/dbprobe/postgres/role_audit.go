package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"audspect/agent/dbprobe"
)

// runAuditRoleRoundtrip is DB-04-06. It grants SELECT on the fixture accounts
// table to the fixture role, then revokes it, both statements in one
// transaction, committed only when both succeed, and tagged with the marker. The schema is dropped by fixture
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
	var granted, revoked bool
	err = a.inCommitTxn(ctx, a.mode, dbprobe.ClassBoundedSynthetic, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
		if err := a.s.Exec(ctx, comment+"GRANT SELECT ON "+qtbl+" TO "+qrole); err != nil {
			return err
		}
		granted = true
		if err := a.s.Exec(ctx, comment+"REVOKE SELECT ON "+qtbl+" FROM "+qrole); err != nil {
			return err
		}
		revoked = true
		return nil
	})
	switch {
	case err == nil:
		res.Notes = append(res.Notes, "role: granted=ok revoked=ok")
		return res, nil
	case !granted:
		res.ErrorClass = "role_grant_failed"
		res.Notes = append(res.Notes, "role: granted=failed revoked=skipped rolled_back=true")
	case !revoked:
		res.ErrorClass = "role_revoke_failed"
		res.Notes = append(res.Notes, "role: granted=ok revoked=failed rolled_back=true")
	default:
		res.ErrorClass = "role_commit_failed"
		res.Notes = append(res.Notes, "role: granted=ok revoked=ok committed=failed")
	}
	return res, err
}
