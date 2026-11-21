package postgres

import (
	"context"
	"time"

	"audspect/agent/dbprobe"
)

// runAuditReloadConf is DB-04-05. It makes one marker-tagged privileged call,
// SELECT pg_reload_conf(). The call changes no data and is rolled back with its
// transaction. Lab mode only, and only with the run's seeded fixture.
func (a *Adapter) runAuditReloadConf(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if _, err := a.labFixture(def, spec, mode); err != nil {
		return res, err
	}
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)
	err := a.inTxn(ctx, a.mode, dbprobe.ClassBoundedSynthetic, spec.Limits, spec.Marker, func(ctx context.Context, comment string) error {
		return a.s.Exec(ctx, comment+"SELECT pg_reload_conf()")
	})
	if err != nil {
		res.ErrorClass = "reload_failed"
		res.Notes = append(res.Notes, "reload: called=failed")
		return res, err
	}
	res.Notes = append(res.Notes, "reload: called=ok")
	return res, nil
}
