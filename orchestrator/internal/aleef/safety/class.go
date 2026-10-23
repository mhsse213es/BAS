// Package safety is the gate between ALEEF and a customer's environment. It
// holds the engagement record (who authorised what, where and until when), the
// transaction safety classes, and the Guard that enforces both on every
// outgoing request together with the request budget, rate and concurrency
// limits, circuit breaker and kill switch.
//
// Everything here fails closed: an unknown class, an unmatched path, an
// unlisted origin or a malformed engagement is a refusal, never a warning.
// Errors never contain request bodies, headers or tokens.
//
// Invariant for callers: the Guard only sees requests made through its
// Transport. Code that builds its own http.Client or Transport (for example the
// API BAS runner's client-certificate and lab-admin clients) bypasses it, so
// such paths must be refused by the caller; internal/aleef/exec does this.
// Only an exactly *http.Client can be wrapped by WrapDoer.
//
// The package may import model and targetscope only; it must not import the
// benchmark side (bank, bank/sealed, bench).
package safety

import (
	"errors"
	"strings"

	"github.com/audspect/bas/internal/aleef/model"
)

// Class is an operation's transaction safety class.
type Class string

const (
	ClassRead       Class = "read"
	ClassSetupSafe  Class = "setup_safe"
	ClassReversible Class = "reversible"
	ClassMoney      Class = "money"
	ClassNotifying  Class = "notifying"
	ClassUnknown    Class = "unknown"
)

// Refusals. Every one is wrapped with context by its caller.
var (
	ErrInvalidEngagement = errors.New("safety: invalid engagement")
	ErrNotAuthorized     = errors.New("safety: not authorised")
	ErrOutsideWindow     = errors.New("safety: outside the engagement window")
	ErrOriginRefused     = errors.New("safety: origin refused")
	ErrClassRefused      = errors.New("safety: operation class refused")
	ErrBudgetExhausted   = errors.New("safety: request budget exhausted")
	ErrHalted            = errors.New("safety: circuit breaker tripped")
	ErrStopped           = errors.New("safety: stopped by kill switch")
	ErrRedirect          = errors.New("safety: redirects are never followed")
)

// FromOpClass converts a model class. Anything unrecognised is ClassUnknown.
func FromOpClass(c model.OpClass) Class {
	switch c {
	case model.ClassRead:
		return ClassRead
	case model.ClassSetupSafe:
		return ClassSetupSafe
	case model.ClassReversible:
		return ClassReversible
	case model.ClassMoney:
		return ClassMoney
	case model.ClassNotifying:
		return ClassNotifying
	}
	return ClassUnknown
}

// rank orders classes by restrictiveness; a higher rank is more restrictive.
// Unrecognised values rank above everything.
func rank(c Class) int {
	switch c {
	case ClassRead:
		return 1
	case ClassSetupSafe:
		return 2
	case ClassReversible:
		return 3
	case ClassNotifying:
		return 4
	case ClassMoney:
		return 5
	}
	return 6
}

// AtLeastAsRestrictive reports whether requested is the same as or more restrictive than ceiling.
// The order, least to most restrictive, is read, setup_safe, reversible, notifying, money, and
// unknown (and anything unrecognised) above all. A run request may only move an operation's class
// up this order from the administrator's classification, never down.
func AtLeastAsRestrictive(requested, ceiling Class) bool {
	return rank(requested) >= rank(ceiling)
}

func isSafeMethod(m string) bool {
	switch strings.ToUpper(m) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

func listed(list []string, id string) bool {
	for _, s := range list {
		if s == id {
			return true
		}
	}
	return false
}

// Allow decides whether an operation of class c may run under e.
//
//   - read, setup_safe, reversible: allowed; when e.Operations is non-empty the
//     operation id must be listed.
//   - money: only when the engagement declares the rail simulated, lists the
//     operation id and names at least one simulator beneficiary. Milestone 1
//     does not enforce the beneficiary VALUE in a request (that needs
//     per-operation body knowledge); it requires that a simulator list exists
//     and that the operator listed the operation explicitly.
//   - notifying: only when test recipients are declared and the operation id is
//     listed. Recipient values in requests are likewise not inspected in M1.
//   - unknown (or any unrecognised class): never.
func Allow(c Class, op model.Operation, e Engagement) error {
	switch c {
	case ClassRead, ClassSetupSafe, ClassReversible:
		// Backstop independent of how the class was chosen: a state-changing method is never "read".
		if c == ClassRead && !isSafeMethod(op.Method) {
			return refuse("operation %q uses %s and cannot be classed read", op.ID, op.Method)
		}
		if len(e.Operations) > 0 && !listed(e.Operations, op.ID) {
			return refuse("operation %q is not in the engagement allowlist", op.ID)
		}
		return nil
	case ClassMoney:
		if !e.SimulatedRail {
			return refuse("operation %q moves money and the engagement does not declare a simulated rail", op.ID)
		}
		if len(e.SimulatorBeneficiaries) == 0 {
			return refuse("operation %q moves money and no simulator beneficiaries are declared", op.ID)
		}
		if !listed(e.Operations, op.ID) {
			return refuse("money operation %q is not explicitly listed in the engagement", op.ID)
		}
		return nil
	case ClassNotifying:
		if len(e.TestRecipients) == 0 {
			return refuse("operation %q notifies and no test recipients are declared", op.ID)
		}
		if !listed(e.Operations, op.ID) {
			return refuse("notifying operation %q is not explicitly listed in the engagement", op.ID)
		}
		return nil
	}
	return refuse("operation %q has an unknown class and never runs", op.ID)
}
