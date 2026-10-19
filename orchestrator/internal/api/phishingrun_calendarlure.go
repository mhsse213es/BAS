package api

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// CalendarEventLureClient is the Graph calendar access PH-CHN-004 needs. It is
// the only side-effecting dependency in the phishing registry: it creates a
// real event, reads it back, and deletes it. *phishidentity.Client satisfies it.
type CalendarEventLureClient interface {
	CreateCalendarEventLure(ctx context.Context, userID, subject, body string, attendeeEmails []string) (phishidentity.CalendarEventLure, error)
	VerifyCalendarEventExists(ctx context.Context, userID, eventID string) phishidentity.CreatedState
	DeleteCalendarEvent(ctx context.Context, userID, eventID string) error
}

// CalendarEventAllowlist is the operator-configured set of mailboxes a
// calendar-lure run may use. Both lists must match exactly (case-insensitive),
// so no run can reach a real employee or an arbitrary mailbox.
type CalendarEventAllowlist struct {
	Organizers []string
	Attendees  []string
}

func (a CalendarEventAllowlist) configured() bool {
	return len(a.Organizers) > 0 && len(a.Attendees) > 0
}

func allowlistContains(list []string, value string) bool {
	for _, v := range list {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

// executePHCHN004 runs PH-CHN-004, a side-effecting calendar-lure scenario. It
// is off by default: with no client or no allow-list it returns NotTested and
// makes no Graph call. When configured, it creates one event for one allow-listed
// attendee, confirms it with an independent read, then always attempts cleanup.
// A creation that fails or a read that is not confirmed is NotTested, never
// inferred as delivered. A cleanup failure is reported and does not change the verdict.
func executePHCHN004(ctx context.Context, env PhishingRunExecutorEnv, runID string, params map[string]any) (phishval.Outcome, error) {
	catalogExp, err := lookupPhishingCatalogExpectation("PH-CHN-004")
	if err != nil {
		return phishval.Outcome{}, err
	}
	if env.CalendarEventLure == nil || !env.CalendarEventAllow.configured() {
		return phishval.Evaluate(runID, "", catalogExp, phishval.Observation{}), nil
	}

	organizer, _ := params["organizerUserId"].(string)
	attendee, _ := params["attendeeEmail"].(string)
	if organizer == "" || attendee == "" {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-CHN-004 requires organizerUserId and attendeeEmail parameters")
	}
	if !allowlistContains(env.CalendarEventAllow.Organizers, organizer) {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-CHN-004 organizer %q is not on the calendar allow-list", organizer)
	}
	if !allowlistContains(env.CalendarEventAllow.Attendees, attendee) {
		return phishval.Outcome{}, fmt.Errorf("phishingrun: PH-CHN-004 attendee %q is not on the calendar allow-list", attendee)
	}

	subject := "Audspect BAS calendar lure " + runID
	body := "Synthetic validation event from an authorized Audspect BAS run. No action is required."
	lure, err := env.CalendarEventLure.CreateCalendarEventLure(ctx, organizer, subject, body, []string{attendee})
	if err != nil {
		outcome := phishval.Evaluate(runID, "", catalogExp, phishval.Observation{})
		outcome.Delivery.Reason = "calendar event creation failed: " + err.Error()
		return outcome, nil
	}

	state := env.CalendarEventLure.VerifyCalendarEventExists(ctx, organizer, lure.EventID)
	cleanupErr := env.CalendarEventLure.DeleteCalendarEvent(ctx, organizer, lure.EventID)

	var obs phishval.Observation
	if state == phishidentity.CreatedConfirmed {
		obs.Delivery = &phishval.DeliveryObservation{
			Outcome: phishval.DeliveryDelivered, Timestamp: time.Now(), Source: "graph-calendar-create",
			Evidence: phishval.EvidenceVerifiedTelemetry, Confidence: phishval.ConfidenceHigh,
		}
	}
	outcome := phishval.Evaluate(runID, "", catalogExp, obs)
	if state != phishidentity.CreatedConfirmed {
		outcome.Delivery.Reason = "calendar event read-back not confirmed (" + string(state) + "); delivery not inferred"
	}
	if cleanupErr != nil {
		note := fmt.Sprintf("cleanup failed: event %s may remain on %s: %v", lure.EventID, organizer, cleanupErr)
		if outcome.Delivery.Reason != "" {
			outcome.Delivery.Reason += "; "
		}
		outcome.Delivery.Reason += note
	}
	return outcome, nil
}
