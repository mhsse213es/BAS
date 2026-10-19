package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/phishidentity"
	"github.com/audspect/bas/internal/phishval"
)

// fakeCalendarLure records every Graph call the PH-CHN-004 executor makes, so
// tests can prove the guardrails refuse before any call, and the cleanup order.
type fakeCalendarLure struct {
	calls     []string
	subject   string
	createErr error
	verify    phishidentity.CreatedState
	deleteErr error
}

func (f *fakeCalendarLure) CreateCalendarEventLure(_ context.Context, userID, subject, _ string, attendees []string) (phishidentity.CalendarEventLure, error) {
	f.calls = append(f.calls, "create:"+userID+":"+strings.Join(attendees, ","))
	f.subject = subject
	if f.createErr != nil {
		return phishidentity.CalendarEventLure{}, f.createErr
	}
	return phishidentity.CalendarEventLure{EventID: "evt-1"}, nil
}

func (f *fakeCalendarLure) VerifyCalendarEventExists(_ context.Context, userID, eventID string) phishidentity.CreatedState {
	f.calls = append(f.calls, "verify:"+userID+":"+eventID)
	return f.verify
}

func (f *fakeCalendarLure) DeleteCalendarEvent(_ context.Context, userID, eventID string) error {
	f.calls = append(f.calls, "delete:"+userID+":"+eventID)
	return f.deleteErr
}

var testCalendarAllow = CalendarEventAllowlist{
	Organizers: []string{"lab-organizer@example-lab.test"},
	Attendees:  []string{"lab-attendee@example-lab.test"},
}

func runCalendarLure(t *testing.T, env PhishingRunExecutorEnv, params map[string]any) (phishval.Outcome, error) {
	t.Helper()
	exec, ok := LookupPhishingRunExecutor("PH-CHN-004")
	if !ok {
		t.Fatal("PH-CHN-004 must be registered as executable")
	}
	return exec(context.Background(), env, "run-cal-1", params)
}

func calendarParams() map[string]any {
	return map[string]any{"organizerUserId": "lab-organizer@example-lab.test", "attendeeEmail": "lab-attendee@example-lab.test"}
}

func TestExecutePHCHN004_NotConfigured_NoGraphCall(t *testing.T) {
	fake := &fakeCalendarLure{verify: phishidentity.CreatedConfirmed}
	// A client with no allow-list, and an allow-list with no client, both refuse.
	for name, env := range map[string]PhishingRunExecutorEnv{
		"no client":        {CalendarEventAllow: testCalendarAllow},
		"no allow-list":    {CalendarEventLure: fake},
		"empty allow-list": {CalendarEventLure: fake, CalendarEventAllow: CalendarEventAllowlist{}},
	} {
		outcome, err := runCalendarLure(t, env, calendarParams())
		if err != nil {
			t.Fatalf("%s: executor: %v", name, err)
		}
		if outcome.Delivery.Verdict != phishval.VerdictNotTested {
			t.Errorf("%s: Delivery.Verdict = %q, want NotTested", name, outcome.Delivery.Verdict)
		}
	}
	if len(fake.calls) != 0 {
		t.Errorf("unconfigured executor made Graph calls: %v", fake.calls)
	}
}

func TestExecutePHCHN004_OrganizerNotAllowlisted_RefusedBeforeCall(t *testing.T) {
	fake := &fakeCalendarLure{verify: phishidentity.CreatedConfirmed}
	env := PhishingRunExecutorEnv{CalendarEventLure: fake, CalendarEventAllow: testCalendarAllow}
	params := map[string]any{"organizerUserId": "someone-else@corp.test", "attendeeEmail": "lab-attendee@example-lab.test"}
	if _, err := runCalendarLure(t, env, params); err == nil {
		t.Fatal("an organizer outside the allow-list must be refused")
	}
	if len(fake.calls) != 0 {
		t.Errorf("refused organizer still reached Graph: %v", fake.calls)
	}
}

func TestExecutePHCHN004_AttendeeNotAllowlisted_RefusedBeforeCall(t *testing.T) {
	fake := &fakeCalendarLure{verify: phishidentity.CreatedConfirmed}
	env := PhishingRunExecutorEnv{CalendarEventLure: fake, CalendarEventAllow: testCalendarAllow}
	params := map[string]any{"organizerUserId": "lab-organizer@example-lab.test", "attendeeEmail": "real-employee@corp.test"}
	if _, err := runCalendarLure(t, env, params); err == nil {
		t.Fatal("an attendee outside the allow-list must be refused")
	}
	if len(fake.calls) != 0 {
		t.Errorf("refused attendee still reached Graph: %v", fake.calls)
	}
}

func TestExecutePHCHN004_MissingParams_Error(t *testing.T) {
	fake := &fakeCalendarLure{verify: phishidentity.CreatedConfirmed}
	env := PhishingRunExecutorEnv{CalendarEventLure: fake, CalendarEventAllow: testCalendarAllow}
	if _, err := runCalendarLure(t, env, map[string]any{"organizerUserId": "lab-organizer@example-lab.test"}); err == nil {
		t.Fatal("a missing attendeeEmail must be an error")
	}
	if len(fake.calls) != 0 {
		t.Errorf("incomplete parameters still reached Graph: %v", fake.calls)
	}
}

func TestExecutePHCHN004_ConfirmedDelivery_CreateVerifyDeleteInOrder(t *testing.T) {
	fake := &fakeCalendarLure{verify: phishidentity.CreatedConfirmed}
	env := PhishingRunExecutorEnv{CalendarEventLure: fake, CalendarEventAllow: testCalendarAllow}
	outcome, err := runCalendarLure(t, env, calendarParams())
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Delivery.Verdict != phishval.VerdictPass {
		t.Errorf("Delivery.Verdict = %q, want Pass for a confirmed event", outcome.Delivery.Verdict)
	}
	want := []string{
		"create:lab-organizer@example-lab.test:lab-attendee@example-lab.test",
		"verify:lab-organizer@example-lab.test:evt-1",
		"delete:lab-organizer@example-lab.test:evt-1",
	}
	if strings.Join(fake.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %v, want %v", fake.calls, want)
	}
	if !strings.Contains(fake.subject, "run-cal-1") {
		t.Errorf("subject %q must carry the run ID so the event is attributable", fake.subject)
	}
}

func TestExecutePHCHN004_UnconfirmedRead_NotTestedNotInferred(t *testing.T) {
	fake := &fakeCalendarLure{verify: phishidentity.CreatedUnknown}
	env := PhishingRunExecutorEnv{CalendarEventLure: fake, CalendarEventAllow: testCalendarAllow}
	outcome, err := runCalendarLure(t, env, calendarParams())
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Delivery.Verdict == phishval.VerdictPass {
		t.Error("an unconfirmed read-back must never be graded as delivered")
	}
	if !strings.Contains(strings.Join(fake.calls, "|"), "delete:") {
		t.Error("the event must still be cleaned up after an unconfirmed read-back")
	}
}

func TestExecutePHCHN004_CreateFails_NoVerifyOrDelete(t *testing.T) {
	fake := &fakeCalendarLure{createErr: errors.New("graph 503")}
	env := PhishingRunExecutorEnv{CalendarEventLure: fake, CalendarEventAllow: testCalendarAllow}
	outcome, err := runCalendarLure(t, env, calendarParams())
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Delivery.Verdict != phishval.VerdictNotTested {
		t.Errorf("Delivery.Verdict = %q, want NotTested when creation failed", outcome.Delivery.Verdict)
	}
	if len(fake.calls) != 1 {
		t.Errorf("a failed creation must make no verify or delete call, got %v", fake.calls)
	}
}

func TestExecutePHCHN004_CleanupFails_VerdictUnchangedAndReported(t *testing.T) {
	fake := &fakeCalendarLure{verify: phishidentity.CreatedConfirmed, deleteErr: errors.New("graph 500")}
	env := PhishingRunExecutorEnv{CalendarEventLure: fake, CalendarEventAllow: testCalendarAllow}
	outcome, err := runCalendarLure(t, env, calendarParams())
	if err != nil {
		t.Fatalf("executor: %v", err)
	}
	if outcome.Delivery.Verdict != phishval.VerdictPass {
		t.Errorf("Delivery.Verdict = %q, want Pass: a cleanup failure must not change the verdict", outcome.Delivery.Verdict)
	}
	if !strings.Contains(outcome.Delivery.Reason, "cleanup failed") {
		t.Errorf("Reason = %q, want the leftover event reported", outcome.Delivery.Reason)
	}
}
