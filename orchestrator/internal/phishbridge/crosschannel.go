package phishbridge

import (
	"strconv"
	"time"

	"github.com/audspect/bas/internal/phishval"
)

// FromChannelInjectorResult translates exercise's own SMS/Slack/Teams
// injector result (SMSInjector.Send / SlackInjector.Send /
// TeamsInjector.Send -- already real, httptest-proven in
// exercise/injectors_test.go) into phishval's Delivery dimension for
// Phase 7's PH-CHN-* cross-channel scenarios.
//
// This is deliberately Delivery-only, never Enforcement or Detection:
// the injectors prove the simulated phishing message reached the
// channel's send API (a real precondition every PH-CHN scenario needs),
// but nothing in exercise reads back whether the destination
// organization's own controls (Teams DLP, carrier SMS filtering, a
// mobile EMM policy) then caught or blocked it -- that evidence source
// genuinely does not exist yet. Grading Enforcement/Detection from this
// map would be exactly the kind of artificial completeness the
// standing conditions forbid.
//
// dispatchErr non-nil (SlackInjector/TeamsInjector return (nil, err) on
// any failure, never a failed-count map) grades DeliveryRejected
// outright. Otherwise result is read as SMSInjector.Send actually
// shapes it: {"channel","sent","failed","errors"} -- an absent or
// non-numeric "sent"/"failed" reads as zero, never an error.
func FromChannelInjectorResult(channel string, result map[string]any, dispatchErr error, observedAt time.Time) phishval.Observation {
	if dispatchErr != nil {
		return phishval.Observation{Delivery: &phishval.DeliveryObservation{
			Outcome: phishval.DeliveryRejected, Timestamp: observedAt,
			Source: "exercise-" + channel + "-injector", Evidence: phishval.EvidenceControlReceipt,
			Confidence: phishval.ConfidenceHigh, Detail: channel + " dispatch rejected: " + dispatchErr.Error(),
		}}
	}

	sent, _ := result["sent"].(int)
	failed, _ := result["failed"].(int)

	outcome := phishval.DeliveryRejected
	detail := "no message sent via " + channel + " (failed=" + strconv.Itoa(failed) + ")"
	if sent > 0 {
		outcome = phishval.DeliveryDelivered
		detail = channel + " dispatch accepted " + strconv.Itoa(sent) + " message(s)"
	}
	return phishval.Observation{
		Delivery: &phishval.DeliveryObservation{
			Outcome: outcome, Timestamp: observedAt,
			Source: "exercise-" + channel + "-injector", Evidence: phishval.EvidenceControlReceipt,
			Confidence: phishval.ConfidenceHigh, Detail: detail,
		},
	}
}
