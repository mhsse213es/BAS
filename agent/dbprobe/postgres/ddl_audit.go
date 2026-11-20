package postgres

import (
	"context"
	"time"

	"audspect/agent/dbprobe"
)

// runAuditDDLRoundtrip is DB-04-08. It runs one CREATE TABLE and one DROP TABLE
// of a synthetic table inside the run's fixture schema. Each statement is its own
// transaction and carries the marker comment, so the audit trail can show both.
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
	step := func(sql string) error {
		return a.inTxn(ctx, a.mode, dbprobe.ClassBoundedSynthetic, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
			return a.s.Exec(ctx, comment+sql)
		})
	}
	if err := step("CREATE TABLE " + qtbl + " (id int)"); err != nil {
		res.ErrorClass = "ddl_create_failed"
		res.Notes = append(res.Notes, "ddl: created=failed dropped=skipped")
		return res, err
	}
	if err := step("DROP TABLE " + qtbl); err != nil {
		res.ErrorClass = "ddl_drop_failed"
		res.Notes = append(res.Notes, "ddl: created=ok dropped=failed")
		return res, err
	}
	res.Notes = append(res.Notes, "ddl: created=ok dropped=ok")
	return res, nil
}
