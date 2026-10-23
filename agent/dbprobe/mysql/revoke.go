package mysql

import (
	"context"
	"errors"
	"strings"
	"time"

	drv "github.com/go-sql-driver/mysql"

	"audspect/agent/dbprobe"
)

// acctState tracks the throwaway login account auth_after_revoke creates for
// this run (R-AL). It is the adapter's created-objects undo record for that
// account: Cleanup drops exactly name, and only when mayExist.
type acctState struct {
	name string
	// mayExist is set just before the CREATE is sent (so a lost acknowledgement
	// is still cleaned up) and cleared again only when the server definitively
	// refused the CREATE, i.e. this call created nothing and must never drop it.
	mayExist bool
}

func dialMySQL(ctx context.Context, cfg dbprobe.ConnectionConfig) (session, error) {
	mc, _, err := buildConfig(cfg)
	if err != nil {
		return nil, err
	}
	return openSession(ctx, mc)
}

// dialAs opens a NEW connection to the registered target as user.
func (a *Adapter) dialAs(ctx context.Context, user, password string) (session, error) {
	cfg := a.target
	cfg.User, cfg.Password = user, password
	if a.dial != nil {
		return a.dial(ctx, cfg)
	}
	return dialMySQL(ctx, cfg)
}

func closeSession(s session) {
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Close(ctx)
}

// isLoginDenied reports whether a connection error is the server refusing the
// login itself: error 1045 (access denied) or 3118 (account is locked).
// Everything else (network, TLS, timeout, too many connections, host not allowed,
// unknown database, ...) is not evidence about the revoke.
func isLoginDenied(err error) bool {
	var me *drv.MySQLError
	return errors.As(err, &me) && (me.Number == 1045 || me.Number == 3118)
}

// addSecret extends the adapter's error scrubber with one more literal.
func (a *Adapter) addSecret(secret string) {
	prev := a.scrub
	a.scrub = func(s string) string {
		if prev != nil {
			s = prev(s)
		}
		return strings.ReplaceAll(s, secret, "[redacted]")
	}
}

// runAuthAfterRevoke is DB-06: create a throwaway login account named from the
// fixture id, prove it can log in (baseline), lock it, prove a NEW connection is
// refused. It never touches any other account. The generated password is a
// local value only: it joins the scrubber and is never returned, noted or
// logged. The marker rides on the baseline statement only (a failed login has no
// statement to carry it).
func (a *Adapter) runAuthAfterRevoke(ctx context.Context, def dbprobe.ProbeDef, spec dbprobe.DBProbeSpec, mode dbprobe.ExecMode) (dbprobe.ProbeResult, error) {
	var res dbprobe.ProbeResult
	if mode != dbprobe.ModeLab {
		return res, errors.New("dbprobe/mysql: auth_after_revoke refused outside lab mode")
	}
	fx, err := a.Current()
	if err != nil {
		return res, errors.New("dbprobe/mysql: auth_after_revoke needs the run's seeded fixture")
	}
	if fx.Kind != def.RequiredFixture || spec.FixtureID != fx.Kind {
		return res, errors.New("dbprobe/mysql: the active fixture is not the one this probe requires")
	}
	name, err := dbprobe.ThrowawayAccountName(fx.ID)
	if err != nil {
		return res, err
	}
	lit, err := userLit(name)
	if err != nil {
		return res, err
	}
	pw, err := dbprobe.NewThrowawayPassword()
	if err != nil {
		return res, err
	}

	ctx, cancel := dbprobe.WithDeadline(ctx, spec.Limits)
	defer cancel()
	a.addSecret(pw)
	res.AgentTime = time.Now().UTC()
	res.Notes = append(res.Notes, a.notes...)

	create, baseline, revoke, reconnect := dbprobe.RevokeStepSkipped, dbprobe.RevokeStepSkipped, dbprobe.RevokeStepSkipped, dbprobe.RevokeStepSkipped
	finish := func(class string) (dbprobe.ProbeResult, error) {
		res.ErrorClass = class
		res.Notes = append(res.Notes, dbprobe.RevokeStepsNote(create, baseline, revoke, reconnect))
		return res, nil
	}
	detail := func(step string, err error) {
		res.Notes = append(res.Notes, "revoke_detail: "+step+": "+dbprobe.TruncateUTF8(a.wrap(step, err).Error(), 200))
	}

	// 1. CREATE the throwaway login account (no privileges granted beyond server defaults). The
	// password is hex, so splicing it into the literal cannot break out; the
	// statement cannot take bound parameters.
	a.acct = acctState{name: name, mayExist: true}
	if err := a.s.Exec(ctx, "CREATE USER "+lit+" IDENTIFIED BY '"+pw+"'"); err != nil {
		var me *drv.MySQLError
		if errors.As(err, &me) {
			a.acct.mayExist = false // refused by the server: nothing was created
		}
		if isCtxErr(err) || ctx.Err() != nil {
			a.markBroken()
		}
		create = dbprobe.RevokeStepFailed
		detail("create", err)
		return finish("account_create_failed")
	}
	create = dbprobe.RevokeStepOK

	// 2. BASELINE: a NEW connection as the account runs one tagged statement.
	base, err := a.dialAs(ctx, name, pw)
	if err == nil {
		var rows [][]any
		rows, err = base.Query(ctx, markerComment(spec.Marker)+" "+sqlClock, 1)
		closeSession(base)
		if err == nil && len(rows) == 1 && len(rows[0]) == 1 {
			res.DBTime = toTime(rows[0][0])
		}
	}
	if err != nil {
		baseline = dbprobe.RevokeStepFailed
		detail("baseline", err)
		return finish("baseline_failed")
	}
	baseline = dbprobe.RevokeStepOK

	// 3. REVOKE the login (lock the account; cleanup of both is the DROP).
	if err := a.s.Exec(ctx, "ALTER USER "+lit+" ACCOUNT LOCK"); err != nil {
		revoke = dbprobe.RevokeStepFailed
		detail("revoke", err)
		return finish("revoke_failed")
	}
	revoke = dbprobe.RevokeStepOK

	// 4. A NEW connection as the same account.
	again, err := a.dialAs(ctx, name, pw)
	switch {
	case err == nil:
		closeSession(again)
		reconnect = dbprobe.RevokeReconnectConnected // Allowed: the revoke did not hold
		return finish("")
	case isLoginDenied(err) && ctx.Err() == nil:
		reconnect = dbprobe.RevokeReconnectDenied
		res.Denied = true
		return finish("auth_failed")
	default:
		reconnect = dbprobe.RevokeReconnectError // never read as a denial
		detail("reconnect", err)
		return finish("reconnect_error")
	}
}
