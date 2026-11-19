package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"audspect/agent/dbprobe"
)

// runAuthFailedLogin is DB-04-04: create a throwaway login account, attempt one
// login with a WRONG password, and report whether the server refused it. The
// account is the same lifecycle object DB-06 uses (a.acct), so the existing
// cleanup drops it. The real password is generated locally and never returned;
// the wrong password is a second local value. Lab-only, through RequiredFixture.
func (a *Adapter) runAuthFailedLogin(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if mode != dbprobe.ModeLab {
		return res, errors.New("dbprobe/postgres: auth_failed_login refused outside lab mode")
	}
	fx, err := a.Current()
	if err != nil {
		return res, errors.New("dbprobe/postgres: auth_failed_login needs the run's seeded fixture")
	}
	if fx.Kind != def.RequiredFixture || spec.FixtureID != fx.Kind {
		return res, errors.New("dbprobe/postgres: the active fixture is not the one this probe requires")
	}
	name, err := dbprobe.ThrowawayAccountName(fx.ID)
	if err != nil {
		return res, err
	}
	pw, err := dbprobe.NewThrowawayPassword()
	if err != nil {
		return res, err
	}
	wrong := pw + "x" // differs from the real password by construction
	qn := pgx.Identifier{name}.Sanitize()
	if err := a.refuseSecondAccount(); err != nil {
		return res, err
	}

	ctx, cancel := dbprobe.WithDeadline(ctx, spec.Limits)
	defer cancel()
	a.secrets = append(a.secrets, pw, wrong)
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)

	// 1. CREATE the throwaway login account, tracked for cleanup before the send.
	a.acct = acctState{name: name, mayExist: true}
	if err := a.s.Exec(ctx, "CREATE ROLE "+qn+" LOGIN PASSWORD '"+pw+"'"); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			a.acct.mayExist = false
		}
		if isCtxErr(err) || ctx.Err() != nil {
			a.markBroken()
		}
		res.ErrorClass = "account_create_failed"
		return res, nil
	}

	// 2. One login with the wrong password, as the throwaway account.
	sess, err := a.dialAs(ctx, name, wrong)
	switch {
	case err == nil:
		closeSession(sess)
		res.ErrorClass = "login_allowed" // a finding: the server accepted a wrong password
	case isLoginDenied(err) && ctx.Err() == nil:
		res.Denied = true
		res.ErrorClass = "auth_failed"
	default:
		res.ErrorClass = "login_error" // never read as a denial
	}
	return res, nil
}
