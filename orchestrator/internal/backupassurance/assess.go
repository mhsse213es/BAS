package backupassurance

import (
	"context"
	"fmt"

	"github.com/audspect/bas/internal/controlval"
)

// Dependencies bundles the 6 fake-backed observers AssessBackup needs. A
// nil field means "no observer configured for this check" -- distinct
// from an observer that ran and returned an error (different operational
// cause, same ERROR verdict).
type Dependencies struct {
	DeletionProtection  DeletionProtectionObserver
	Immutability        ImmutabilityObserver
	OfflineIsolation    OfflineIsolationObserver
	PrivilegeSeparation PrivilegeSeparationObserver
	RestoreIntegrity    RestoreIntegrityObserver
	RPORTO              RPORTOObserver
}

// AssessBackup always returns exactly 6 results, in allChecks' fixed
// order, under every failure mode (spec section D). Not a generic
// reflection-based dispatch loop -- 6 is a closed, final set, so each
// check gets its own explicit call site; the shared evaluate() helper
// carries the nil-check, panic-recovery, and classification logic once.
func AssessBackup(ctx context.Context, deps Dependencies) []CheckResult {
	return []CheckResult{
		evaluate(CheckDeletionProtection, deps.DeletionProtection == nil, func() (bool, bool, string, string, error) {
			return deps.DeletionProtection.ObserveDeletionProtection(ctx)
		}),
		evaluate(CheckImmutability, deps.Immutability == nil, func() (bool, bool, string, string, error) {
			return deps.Immutability.ObserveImmutability(ctx)
		}),
		evaluate(CheckOfflineIsolation, deps.OfflineIsolation == nil, func() (bool, bool, string, string, error) {
			return deps.OfflineIsolation.ObserveOfflineIsolation(ctx)
		}),
		evaluate(CheckPrivilegeSeparation, deps.PrivilegeSeparation == nil, func() (bool, bool, string, string, error) {
			return deps.PrivilegeSeparation.ObservePrivilegeSeparation(ctx)
		}),
		evaluate(CheckRestoreIntegrity, deps.RestoreIntegrity == nil, func() (bool, bool, string, string, error) {
			return deps.RestoreIntegrity.ObserveRestoreIntegrity(ctx)
		}),
		evaluate(CheckRPORTO, deps.RPORTO == nil, func() (bool, bool, string, string, error) {
			return deps.RPORTO.ObserveRPORTO(ctx)
		}),
	}
}

// evaluate carries the nil-check, panic-recovery, and classification
// logic shared by all 6 checks. call's signature is (tested, outcome
// bool, observerID, reason string, err error).
func evaluate(check Check, observerNil bool, call func() (bool, bool, string, string, error)) (result CheckResult) {
	defer func() {
		if r := recover(); r != nil {
			result = CheckResult{Check: check, Verdict: controlval.VerdictError, Reason: fmt.Sprintf("observer panicked: %v", r), Simulated: simulated, Observer: "panicked"}
		}
	}()
	if observerNil {
		return CheckResult{Check: check, Verdict: controlval.VerdictError, Reason: "no observer configured for this check", Simulated: simulated, Observer: "unconfigured"}
	}
	tested, outcome, observerID, reason, err := call()
	verdict, skipReason, finalReason := classifyObserverResult(tested, outcome, reason, err)
	return CheckResult{Check: check, Verdict: verdict, SkipReason: skipReason, Reason: finalReason, Simulated: simulated, Observer: observerID}
}
