package postgres

import (
	"context"
	"time"

	"audspect/agent/dbprobe"
)

// runAuditDDLRoundtrip is DB-04-08. It runs one CREATE TABLE and one DROP TABLE
// of a synthetic table inside the run's fixture schema. Each statement is its own
// transaction, committed only when both succeed, and carries the marker comment.
// Lab mode only, and only with the run's seeded fixture.
func (a *Adapter) runAuditDDLRoundtrip(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	fx, err := a.labFixture(def, spec, mode)
	if err != nil {
		return res, err
	}
	schema, _, err := fixtureNames(fx.ID)
	if err != nil {
		return res, err
	}
	qtbl, err := quoteTable(schema + ".dbsim_ddl_probe")
	if err != nil {
		return res, err
	}
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	var created, dropped bool
	err = a.inCommitTxn(ctx, a.mode, dbprobe.ClassBoundedSynthetic, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
		if err := a.s.Exec(ctx, comment+"CREATE TABLE "+qtbl+" (id int)"); err != nil {
			return err
		}
		created = true
		if err := a.s.Exec(ctx, comment+"DROP TABLE "+qtbl); err != nil {
			return err
		}
		dropped = true
		return nil
	})
	switch {
	case err == nil:
		res.Notes = append(res.Notes, "ddl: created=ok dropped=ok")
		return res, nil
	case !created:
		res.ErrorClass = "ddl_create_failed"
		res.Notes = append(res.Notes, "ddl: created=failed dropped=skipped rolled_back=true")
	case !dropped:
		res.ErrorClass = "ddl_drop_failed"
		res.Notes = append(res.Notes, "ddl: created=ok dropped=failed rolled_back=true")
	default:
		res.ErrorClass = "ddl_commit_failed"
		res.Notes = append(res.Notes, "ddl: created=ok dropped=ok committed=failed")
	}
	return res, err
}
