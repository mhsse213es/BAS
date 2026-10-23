package fixtures

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"audspect/agent/dbprobe"
	"audspect/agent/protocol"
)

// CleanupTimeout bounds teardown plus verification. Cleanup always runs under
// a fresh context of this length, never the (possibly cancelled) run context.
const CleanupTimeout = 45 * time.Second

// Cleanup statuses (same strings as protocol.DBCleanup*).
const (
	StatusOK       = protocol.DBCleanupOK
	StatusResidual = protocol.DBCleanupResidual
	StatusFailed   = protocol.DBCleanupFailed
)

// ErrSafetyIncident is returned when fixture cleanup or its verification
// failed or left residual objects (spec 8 gate 4). It is never swallowed: a run
// that returns it cannot report normal completion. Detail is bounded and
// built from already-redacted adapter errors; it never carries credentials.
type ErrSafetyIncident struct {
	FixtureID string
	Status    string // StatusResidual or StatusFailed
	Residual  []string
	Detail    string
	// Cause is the error (or panic) of the run itself when it also failed.
	Cause error
}

func (e *ErrSafetyIncident) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "fixture cleanup safety incident (fixture %s, status %s)", e.FixtureID, e.Status)
	if len(e.Residual) > 0 {
		fmt.Fprintf(&b, ", residual %v", e.Residual)
	}
	if e.Detail != "" {
		b.WriteString(": " + e.Detail)
	}
	if e.Cause != nil {
		b.WriteString("; run also failed: " + dbprobe.TruncateUTF8(e.Cause.Error(), 300))
	}
	return b.String()
}

// Unwrap exposes the run's own error so errors.Is still matches it.
func (e *ErrSafetyIncident) Unwrap() error { return e.Cause }

// VerifyClean proves the fixture is gone: it inspects the fixture's schema and
// accounts and returns every object that is present now but was not in the
// recorded pre-test state as Residual. An adapter that cannot inspect, or an
// inspection that fails, is an error: unverifiable never reads as clean.
func VerifyClean(ctx context.Context, ad dbprobe.Adapter, fx dbprobe.Fixture) (dbprobe.CleanupResult, error) {
	var out dbprobe.CleanupResult
	insp, ok := ad.(dbprobe.FixtureInspector)
	if !ok {
		return out, errors.New("fixtures: adapter cannot inspect fixture state; cleanup cannot be verified")
	}
	now, err := insp.InspectFixture(ctx, fx)
	if err != nil {
		return out, fmt.Errorf("fixtures: cleanup verification failed: %w", err)
	}
	pre := map[string]bool{}
	for _, o := range fx.PreState {
		pre[o] = true
	}
	for _, o := range now {
		if !pre[o] {
			out.Residual = append(out.Residual, o)
		}
	}
	sort.Strings(out.Residual)
	return out, nil
}

// WithFixture seeds spec, runs fn, then always runs Cleanup and VerifyClean
// under a fresh bounded context, even when fn errors, panics or the run
// context is cancelled. A panic is re-raised after cleanup. When cleanup or
// verification fails or leaves residual objects the returned error is an
// *ErrSafetyIncident (wrapping fn's own error, if any) and the CleanupResult
// carries the Residual: callers must treat the run as unusable.
//
// A refused Seed (nothing sent to the database) returns that refusal without a
// cleanup attempt; a Seed that failed part-way is cleaned up like any other.
func WithFixture(ctx context.Context, ad dbprobe.Adapter, spec dbprobe.FixtureSpec,
	fn func(dbprobe.Fixture) error) (dbprobe.CleanupResult, error) {

	fx, seedErr := Seed(ctx, ad, spec)
	if seedErr != nil && fx.ID == "" {
		return dbprobe.CleanupResult{}, seedErr
	}

	var runErr error = seedErr
	var panicVal any
	panicked := false
	if seedErr == nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked, panicVal = true, r
				}
			}()
			runErr = fn(fx)
		}()
	}

	res, inc := teardown(ctx, ad, fx)
	if inc != nil {
		switch {
		case panicked:
			inc.Cause = fmt.Errorf("run panicked: %v", panicVal)
		case runErr != nil:
			inc.Cause = runErr
		}
		if panicked {
			panic(inc)
		}
		return res, inc
	}
	if panicked {
		panic(panicVal)
	}
	return res, runErr
}

// teardown runs Cleanup then VerifyClean under a fresh bounded context and
// folds both into one result. It never panics.
func teardown(parent context.Context, ad dbprobe.Adapter, fx dbprobe.Fixture) (dbprobe.CleanupResult, *ErrSafetyIncident) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(parent), CleanupTimeout)
	defer cancel()

	var errs []string
	res, err := safeCleanup(cctx, ad, fx)
	if err != nil {
		errs = append(errs, "cleanup: "+err.Error())
	}
	if res.Error != "" && (err == nil || res.Error != err.Error()) {
		errs = append(errs, res.Error)
	}
	ver, verr := safeVerify(cctx, ad, fx)
	if verr != nil {
		errs = append(errs, verr.Error())
	}

	seen := map[string]bool{}
	var residual []string
	for _, r := range append(append([]string(nil), res.Residual...), ver.Residual...) {
		if !seen[r] {
			seen[r] = true
			residual = append(residual, r)
		}
	}
	sort.Strings(residual)
	res.Residual = residual
	if len(errs) > 0 {
		res.Error = dbprobe.TruncateUTF8(strings.Join(errs, "; "), 300)
	}

	switch {
	case len(residual) > 0:
		return res, &ErrSafetyIncident{FixtureID: fx.ID, Status: StatusResidual, Residual: residual, Detail: res.Error}
	case len(errs) > 0:
		return res, &ErrSafetyIncident{FixtureID: fx.ID, Status: StatusFailed, Detail: res.Error}
	}
	return res, nil
}

func safeCleanup(ctx context.Context, ad dbprobe.Adapter, fx dbprobe.Fixture) (res dbprobe.CleanupResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("adapter cleanup panicked: %v", r)
		}
	}()
	return ad.Cleanup(ctx, fx)
}

func safeVerify(ctx context.Context, ad dbprobe.Adapter, fx dbprobe.Fixture) (res dbprobe.CleanupResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("cleanup verification panicked: %v", r)
		}
	}()
	return VerifyClean(ctx, ad, fx)
}
