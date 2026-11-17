// Package carbanakledger is a lab-only simulated banking ledger. It enforces
// banking control rules on its own API so that fraud-control results come
// from the ledger, never from the scenario that calls it.
package carbanakledger

import (
	"fmt"
	"slices"
	"time"
	_ "time/tzdata" // fixed zone data so IST results do not depend on the host
)

type Decision string

const (
	Approved Decision = "approved"
	Rejected Decision = "rejected"
	Flagged  Decision = "flagged"
)

// Action is one request evaluated against the rules. Kind is one of
// "transfer", "approve", "beneficiary", "limit", or "session".
type Action struct {
	Kind                  string
	Actor                 string
	Approver              string
	Amount                int64
	Limit                 int64
	At                    time.Time
	ApproverRole          bool
	PrivilegedRole        bool
	SecondApproverPresent bool
	SameHostAsSession     bool
	SessionExpired        bool
}

// Window is the normal operating window. Hours are [StartHour, EndHour) on the
// listed weekdays, interpreted in Location.
type Window struct {
	Location  *time.Location
	StartHour int
	EndHour   int
	Weekdays  []time.Weekday
}

// DefaultWindow is the lab default from the approved design: Asia/Kolkata,
// Monday-Friday, 09:00-18:00. It is not a universal banking policy.
func DefaultWindow() (Window, error) {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		return Window{}, fmt.Errorf("load Asia/Kolkata: %w", err)
	}
	return Window{
		Location:  loc,
		StartHour: 9,
		EndHour:   18,
		Weekdays:  []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday},
	}, nil
}

func (w Window) Inside(t time.Time) bool {
	local := t.In(w.Location)
	if !slices.Contains(w.Weekdays, local.Weekday()) {
		return false
	}
	return local.Hour() >= w.StartHour && local.Hour() < w.EndHour
}

// Evaluate returns the decision and the first rule that fired. Rejections are
// checked before flags. An approved action returns an empty rule.
func Evaluate(a Action, w Window) (Decision, string) {
	switch a.Kind {
	case "approve":
		if a.Approver == a.Actor {
			return Rejected, "maker_checker_self_approval"
		}
		if !a.ApproverRole {
			return Rejected, "approver_role_missing"
		}
	case "beneficiary":
		if !a.SecondApproverPresent {
			return Rejected, "beneficiary_second_approver_missing"
		}
	case "limit":
		if !a.PrivilegedRole {
			return Rejected, "limit_change_unprivileged"
		}
	}

	if a.Kind == "transfer" && a.Limit > 0 && a.Amount > a.Limit {
		return Flagged, "amount_over_limit"
	}
	if !w.Inside(a.At) {
		return Flagged, "outside_operating_window"
	}
	if !a.SameHostAsSession || a.SessionExpired {
		return Flagged, "session_anomaly"
	}
	return Approved, ""
}
