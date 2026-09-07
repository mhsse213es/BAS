package jobs

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIsTerminalJobState(t *testing.T) {
	cases := map[string]bool{
		JobStateRequested: false,
		JobStateRunning:   false,
		JobStateCompleted: true,
		JobStatePartial:   true,
		JobStateFailed:    true,
		JobStateCancelled: true,
	}
	for state, want := range cases {
		if got := IsTerminalJobState(state); got != want {
			t.Errorf("IsTerminalJobState(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestNextOccurrenceSince_FirstOccurrenceEverChecked(t *testing.T) {
	// A Friday 23:00 UTC schedule, never checked before (LastOccurrenceAt
	// nil), evaluated on the following Monday -- should find last Friday's
	// occurrence.
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC"} // 5 = Friday
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)              // a Monday
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true (first-ever check should find last Friday)")
	}
	want := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC).Add(jitterOffset(sch.ID, scheduleJitterWindow)) // the preceding Friday, jittered
	if !occurrence.Equal(want) {
		t.Errorf("occurrence = %v, want %v", occurrence, want)
	}
}

func TestNextOccurrenceSince_AlreadyHandled_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC"}
	already := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC).Add(jitterOffset(sch.ID, scheduleJitterWindow))
	sch.LastOccurrenceAt = &already
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC) // still the same week, no new Friday yet
	_, ok := nextOccurrenceSince(sch, now)
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- this occurrence was already handled")
	}
}

func TestNextOccurrenceSince_TimeOfDayNotYetReachedToday(t *testing.T) {
	sch := Schedule{DayOfWeek: 1, TimeOfDay: "23:00", Timezone: "UTC"} // 1 = Monday
	now := time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)              // Monday, 10:00 -- before 23:00
	_, ok := nextOccurrenceSince(sch, now)
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- today's occurrence time hasn't arrived yet")
	}
}

func TestNextOccurrenceSince_TimezoneConversion(t *testing.T) {
	// Friday 23:00 IST (Asia/Kolkata, UTC+5:30) is Friday 17:30 UTC.
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Asia/Kolkata"}
	now := time.Date(2026, 8, 7, 18, 0, 0, 0, time.UTC) // just after 17:30 UTC on that Friday
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true")
	}
	want := time.Date(2026, 8, 7, 17, 30, 0, 0, time.UTC).Add(jitterOffset(sch.ID, scheduleJitterWindow))
	if !occurrence.Equal(want) {
		t.Errorf("occurrence = %v, want %v (UTC equivalent of Friday 23:00 IST)", occurrence, want)
	}
}

func TestNextOccurrenceSince_InvalidTimezone_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Not/A_Real_Zone"}
	_, ok := nextOccurrenceSince(sch, time.Now().UTC())
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false for an invalid timezone")
	}
}

func TestNextOccurrenceSince_InvalidTimeOfDay_ReturnsNotOK(t *testing.T) {
	sch := Schedule{DayOfWeek: 5, TimeOfDay: "not-a-time", Timezone: "UTC"}
	_, ok := nextOccurrenceSince(sch, time.Now().UTC())
	if ok {
		t.Error("nextOccurrenceSince() ok = true, want false for an invalid time-of-day")
	}
}

func TestCreateSchedule_PersistsAndRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "weekly hardening"})

		created, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1", "a2"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "Asia/Kolkata", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		if created.ID == "" || !created.Enabled || created.LastSpawnedJobID != "" {
			t.Fatalf("created = %+v, want non-empty ID, Enabled=true, LastSpawnedJobID=''", created)
		}

		got, err := store.GetSchedule(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if len(got.AgentIDs) != 2 || got.AgentIDs[0] != "a1" || got.DayOfWeek != 5 || got.TimeOfDay != "23:00" || got.Timezone != "Asia/Kolkata" {
			t.Errorf("got = %+v, want AgentIDs=[a1 a2] DayOfWeek=5 TimeOfDay=23:00 Timezone=Asia/Kolkata", got)
		}
	})
}

func TestUpdateSchedule_PersistsEditableFieldsAndPreservesIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall"})
		created, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 1, TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}

		// Deliberately leave Type/CreatedBy unset on the update struct to prove
		// UpdateSchedule's SQL never references those columns at all -- not just
		// that this test happened to pass matching values.
		newPayload, _ := json.Marshal(map[string]string{"remediationId": "disable_smbv1"})
		updated, err := store.UpdateSchedule(ctx, created.ID, Schedule{
			Payload: newPayload, AgentIDs: []string{"a2", "a3"}, DayOfWeek: 5, TimeOfDay: "23:00",
			Timezone: "Asia/Kolkata", Enabled: true, RecurrenceType: "weekly", ConcurrencyLimit: 3,
		})
		if err != nil {
			t.Fatalf("UpdateSchedule: %v", err)
		}
		if updated.ID != created.ID || updated.Type != "batch_remediation" || updated.CreatedBy != "user-1" || !updated.CreatedAt.Equal(created.CreatedAt) {
			t.Errorf("identity fields changed: got %+v, want ID/Type/CreatedBy/CreatedAt unchanged from %+v", updated, created)
		}
		if len(updated.AgentIDs) != 2 || updated.AgentIDs[0] != "a2" || updated.DayOfWeek != 5 || updated.TimeOfDay != "23:00" || updated.Timezone != "Asia/Kolkata" || updated.ConcurrencyLimit != 3 {
			t.Errorf("got = %+v, want AgentIDs=[a2 a3] DayOfWeek=5 TimeOfDay=23:00 Timezone=Asia/Kolkata ConcurrencyLimit=3", updated)
		}
	})
}

func TestListEnabledSchedules_ExcludesDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})

		enabled, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule (enabled): %v", err)
		}
		disabled, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a2"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule (to-be-disabled): %v", err)
		}
		if err := store.DisableSchedule(ctx, disabled.ID); err != nil {
			t.Fatalf("DisableSchedule: %v", err)
		}

		got, err := store.ListEnabledSchedules(ctx)
		if err != nil {
			t.Fatalf("ListEnabledSchedules: %v", err)
		}
		var sawEnabled, sawDisabled bool
		for _, sch := range got {
			if sch.ID == enabled.ID {
				sawEnabled = true
			}
			if sch.ID == disabled.ID {
				sawDisabled = true
			}
		}
		if !sawEnabled || sawDisabled {
			t.Errorf("ListEnabledSchedules() sawEnabled=%v sawDisabled=%v, want true/false", sawEnabled, sawDisabled)
		}
	})
}

func TestMarkScheduleOccurrenceHandled_UpdatesBothFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		payload, _ := json.Marshal(map[string]string{"remediationId": "enable_windows_firewall", "reason": "test"})
		sch, err := store.CreateSchedule(ctx, Schedule{
			Type: "batch_remediation", Payload: payload, AgentIDs: []string{"a1"},
			DayOfWeek: 5, TimeOfDay: "23:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		occurrence := time.Date(2026, 8, 7, 23, 0, 0, 0, time.UTC)

		if err := store.MarkScheduleOccurrenceHandled(ctx, sch.ID, occurrence, "spawned-job-1"); err != nil {
			t.Fatalf("MarkScheduleOccurrenceHandled: %v", err)
		}
		got, err := store.GetSchedule(ctx, sch.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.LastOccurrenceAt == nil || !got.LastOccurrenceAt.Equal(occurrence) || got.LastSpawnedJobID != "spawned-job-1" {
			t.Fatalf("got = %+v, want LastOccurrenceAt=%v LastSpawnedJobID=spawned-job-1", got, occurrence)
		}
	})
}

func TestCreateSchedule_RoundTripsScheduledAssessmentFields(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := NewStore(pool)
		runAt := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Microsecond)
		created, err := store.CreateSchedule(context.Background(), Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-1"},
			GroupIDs: []int64{7, 8}, RecurrenceType: "once", RunAt: &runAt, Enabled: true,
			ConcurrencyLimit: 5, Mode: "telemetry", ApprovedBy: "admin-1", ApprovalVersion: 1, Reason: "test",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		got, err := store.GetSchedule(context.Background(), created.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.RecurrenceType != "once" || got.RunAt == nil || !got.RunAt.Equal(runAt) {
			t.Errorf("recurrence fields: got RecurrenceType=%q RunAt=%v, want once/%v", got.RecurrenceType, got.RunAt, runAt)
		}
		if len(got.GroupIDs) != 2 || got.GroupIDs[0] != 7 || got.GroupIDs[1] != 8 {
			t.Errorf("GroupIDs = %v, want [7 8]", got.GroupIDs)
		}
		if got.ConcurrencyLimit != 5 || got.Mode != "telemetry" || got.ApprovedBy != "admin-1" || got.ApprovalVersion != 1 || got.Reason != "test" {
			t.Errorf("got = %+v, want ConcurrencyLimit=5 Mode=telemetry ApprovedBy=admin-1 ApprovalVersion=1 Reason=test", got)
		}
	})
}

func TestCreateSchedule_RoundTripsInitiativeID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		store := NewStore(pool)
		created, err := store.CreateSchedule(ctx, Schedule{
			Type: "scheduled_assessment", Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-1"},
			DayOfWeek: 1, TimeOfDay: "02:00", Timezone: "UTC", Enabled: true, CreatedBy: "user-1",
			InitiativeID: "init-123",
		})
		if err != nil {
			t.Fatalf("CreateSchedule: %v", err)
		}
		if created.InitiativeID != "init-123" {
			t.Errorf("created.InitiativeID = %q, want init-123", created.InitiativeID)
		}

		got, err := store.GetSchedule(ctx, created.ID)
		if err != nil {
			t.Fatalf("GetSchedule: %v", err)
		}
		if got.InitiativeID != "init-123" {
			t.Errorf("got.InitiativeID = %q, want init-123", got.InitiativeID)
		}

		updated, err := store.UpdateSchedule(ctx, created.ID, Schedule{
			Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-1"}, DayOfWeek: 1, TimeOfDay: "02:00",
			Timezone: "UTC", Enabled: true, InitiativeID: "init-456",
		})
		if err != nil {
			t.Fatalf("UpdateSchedule: %v", err)
		}
		if updated.InitiativeID != "init-456" {
			t.Errorf("updated.InitiativeID = %q, want init-456", updated.InitiativeID)
		}

		// Updating with InitiativeID left as "" clears it -- same "whole
		// struct replaces editable fields" convention UpdateSchedule already
		// uses for every other editable field (see
		// TestUpdateSchedule_PersistsEditableFieldsAndPreservesIdentity).
		cleared, err := store.UpdateSchedule(ctx, created.ID, Schedule{
			Payload: json.RawMessage(`{}`), AgentIDs: []string{"sa-1"}, DayOfWeek: 1, TimeOfDay: "02:00",
			Timezone: "UTC", Enabled: true,
		})
		if err != nil {
			t.Fatalf("UpdateSchedule (clear): %v", err)
		}
		if cleared.InitiativeID != "" {
			t.Errorf("cleared.InitiativeID = %q, want empty", cleared.InitiativeID)
		}
	})
}

func TestNextOccurrenceSince_Once(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	runAt := time.Date(2026, 8, 10, 2, 0, 0, 0, loc)
	sch := Schedule{RecurrenceType: "once", RunAt: &runAt, Timezone: "UTC", TimeOfDay: "00:00"}

	before := time.Date(2026, 8, 9, 0, 0, 0, 0, loc)
	if _, ok := nextOccurrenceSince(sch, before); ok {
		t.Error("before RunAt: got ok=true, want false")
	}

	after := time.Date(2026, 8, 11, 0, 0, 0, 0, loc)
	occ, ok := nextOccurrenceSince(sch, after)
	if !ok || !occ.Equal(runAt) {
		t.Errorf("first check after RunAt: got occ=%v ok=%v, want %v/true", occ, ok, runAt)
	}

	spawned := runAt
	sch.LastOccurrenceAt = &spawned
	if _, ok := nextOccurrenceSince(sch, after.Add(24*time.Hour)); ok {
		t.Error("after already spawned: got ok=true, want false (once-only)")
	}
}

func TestNextOccurrenceSince_Daily(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}
	offset := jitterOffset(sch.ID, scheduleJitterWindow)

	now := time.Date(2026, 8, 10, 14, 5, 0, 0, loc)
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 14, 0, 0, 0, loc).Add(offset)
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}

	sch.LastOccurrenceAt = &occ
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("same-day recheck after spawn: got ok=true, want false")
	}
	tomorrow := now.Add(24 * time.Hour)
	occ2, ok := nextOccurrenceSince(sch, tomorrow)
	wantTomorrow := time.Date(2026, 8, 11, 14, 0, 0, 0, loc).Add(offset)
	if !ok || !occ2.Equal(wantTomorrow) {
		t.Errorf("next day: got occ=%v ok=%v, want %v/true", occ2, ok, wantTomorrow)
	}
}

func TestNextOccurrenceSince_Weekly_EmptyRecurrenceTypeAliasesToWeekly(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{RecurrenceType: "", DayOfWeek: 1, TimeOfDay: "09:00", Timezone: "UTC"} // Monday
	now := time.Date(2026, 8, 11, 9, 30, 0, 0, loc)                                        // a Tuesday, 9:30
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 9, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow)) // the Monday before, jittered
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}

func TestNextOccurrenceSince_Monthly(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{RecurrenceType: "monthly", DayOfMonth: 1, TimeOfDay: "03:00", Timezone: "UTC"}
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, loc) // Aug 5, after Aug 1's slot
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 1, 3, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow))
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}

func TestNextOccurrenceSince_EndDate_StopsSpawning(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	ended := time.Date(2026, 8, 1, 0, 0, 0, 0, loc)
	sch := Schedule{RecurrenceType: "daily", TimeOfDay: "09:00", Timezone: "UTC", EndDate: &ended}
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, loc) // well after EndDate
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("after EndDate: got ok=true, want false")
	}
}

func TestNextOccurrenceDaily_JitterShiftsOccurrence(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	now := time.Date(2026, 8, 10, 14, 5, 0, 0, loc)

	// "test-schedule-1" has a positive jitterOffset (~+34.5s).
	positive := Schedule{ID: "test-schedule-1", RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}
	if off := jitterOffset(positive.ID, scheduleJitterWindow); off <= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want > 0 -- pick a different ID", positive.ID, off)
	}
	occ, ok := nextOccurrenceSince(positive, now)
	want := time.Date(2026, 8, 10, 14, 0, 0, 0, loc).Add(jitterOffset(positive.ID, scheduleJitterWindow))
	if !ok || !occ.Equal(want) {
		t.Errorf("positive-offset ID: got occ=%v ok=%v, want %v/true", occ, ok, want)
	}

	// "test-schedule-2" has a negative jitterOffset (~-66s).
	negative := Schedule{ID: "test-schedule-2", RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}
	if off := jitterOffset(negative.ID, scheduleJitterWindow); off >= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want < 0 -- pick a different ID", negative.ID, off)
	}
	occ2, ok := nextOccurrenceSince(negative, now)
	want2 := time.Date(2026, 8, 10, 14, 0, 0, 0, loc).Add(jitterOffset(negative.ID, scheduleJitterWindow))
	if !ok || !occ2.Equal(want2) {
		t.Errorf("negative-offset ID: got occ=%v ok=%v, want %v/true", occ2, ok, want2)
	}
}

func TestNextOccurrenceDaily_JitterCrossesDayBoundary(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "sched-g", RecurrenceType: "daily", TimeOfDay: "00:01", Timezone: "UTC"}
	offset := jitterOffset(sch.ID, scheduleJitterWindow)
	if offset >= -60*time.Second {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want <= -60s to cross the day boundary from 00:01 -- pick a different ID", sch.ID, offset)
	}

	now := time.Date(2026, 8, 10, 1, 0, 0, 0, loc) // well after midnight
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 0, 1, 0, 0, loc).Add(offset)
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
	if occ.UTC().Day() != 9 {
		t.Errorf("occurrence lands on day %d, want day 9 (the prior calendar day) -- jitter should have pushed a 00:01 nominal time backward across midnight", occ.UTC().Day())
	}
}

func TestNextOccurrenceOnce_JitterDoesNotApply(t *testing.T) {
	runAt := time.Date(2026, 8, 10, 9, 0, 0, 0, time.UTC)
	sch := Schedule{ID: "sched-d", RecurrenceType: "once", RunAt: &runAt, Timezone: "UTC", TimeOfDay: "00:00"}
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off == 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = 0, want nonzero -- pick a different ID", sch.ID)
	}
	now := runAt.Add(time.Hour)
	occurrence, ok := nextOccurrenceSince(sch, now)
	if !ok {
		t.Fatal("nextOccurrenceSince() ok = false, want true")
	}
	if !occurrence.Equal(runAt) {
		t.Errorf("occurrence = %v, want %v (exact RunAt, unaffected by jitter)", occurrence, runAt)
	}
}

func TestNextOccurrenceWeekly_JitterShiftsOccurrence(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "sched-b", RecurrenceType: "weekly", DayOfWeek: 1, TimeOfDay: "09:00", Timezone: "UTC"} // Monday
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off <= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want > 0 -- pick a different ID", sch.ID, off)
	}
	now := time.Date(2026, 8, 11, 9, 30, 0, 0, loc) // a Tuesday, 9:30
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 10, 9, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow)) // the Monday before, jittered
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}

func TestNextOccurrenceMonthly_JitterShiftsOccurrence(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "sched-e", RecurrenceType: "monthly", DayOfMonth: 1, TimeOfDay: "03:00", Timezone: "UTC"}
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off >= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want < 0 -- pick a different ID", sch.ID, off)
	}
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, loc) // Aug 5, after Aug 1's slot
	occ, ok := nextOccurrenceSince(sch, now)
	want := time.Date(2026, 8, 1, 3, 0, 0, 0, loc).Add(jitterOffset(sch.ID, scheduleJitterWindow))
	if !ok || !occ.Equal(want) {
		t.Errorf("got occ=%v ok=%v, want %v/true", occ, ok, want)
	}
}

// The following three tests guard against the deploy-boundary duplicate-spawn
// bug: every schedule row in production had LastOccurrenceAt written by the
// pre-jitter code, in the old nominal (unjittered) convention. If the dedup
// check compared the new jittered occurrence directly against that old
// nominal LastOccurrenceAt with no tolerance, any schedule ID with a positive
// jitterOffset would see jittered.After(LastOccurrenceAt) == true for the
// slot that was JUST spawned under the old code, and re-fire it.

func TestNextOccurrenceDaily_JitterDoesNotReFireAlreadyHandledSlot(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "test-schedule-1", RecurrenceType: "daily", TimeOfDay: "14:00", Timezone: "UTC"}
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off <= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want > 0 -- pick a different ID", sch.ID, off)
	}
	// Simulate a row written by the old pre-jitter code (or this same slot
	// already being handled): LastOccurrenceAt holds the nominal,
	// unjittered time of today's slot.
	nominal := time.Date(2026, 8, 10, 14, 0, 0, 0, loc)
	sch.LastOccurrenceAt = &nominal
	now := time.Date(2026, 8, 10, 14, 5, 0, 0, loc) // after the jittered instant
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- slot already handled under the old nominal convention must not re-fire")
	}
}

func TestNextOccurrenceWeekly_JitterDoesNotReFireAlreadyHandledSlot(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "sched-b", RecurrenceType: "weekly", DayOfWeek: 1, TimeOfDay: "09:00", Timezone: "UTC"} // Monday
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off <= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want > 0 -- pick a different ID", sch.ID, off)
	}
	nominal := time.Date(2026, 8, 10, 9, 0, 0, 0, loc) // the Monday, nominal (unjittered)
	sch.LastOccurrenceAt = &nominal
	now := time.Date(2026, 8, 11, 9, 30, 0, 0, loc) // a Tuesday, well after the jittered instant
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- slot already handled under the old nominal convention must not re-fire")
	}
}

func TestNextOccurrenceMonthly_JitterDoesNotReFireAlreadyHandledSlot(t *testing.T) {
	loc, _ := time.LoadLocation("UTC")
	sch := Schedule{ID: "test-schedule-1", RecurrenceType: "monthly", DayOfMonth: 1, TimeOfDay: "03:00", Timezone: "UTC"}
	if off := jitterOffset(sch.ID, scheduleJitterWindow); off <= 0 {
		t.Fatalf("test fixture assumption broken: jitterOffset(%q) = %v, want > 0 -- pick a different ID", sch.ID, off)
	}
	nominal := time.Date(2026, 8, 1, 3, 0, 0, 0, loc) // Aug 1's slot, nominal (unjittered)
	sch.LastOccurrenceAt = &nominal
	now := time.Date(2026, 8, 5, 0, 0, 0, 0, loc) // Aug 5, well after the jittered instant
	if _, ok := nextOccurrenceSince(sch, now); ok {
		t.Error("nextOccurrenceSince() ok = true, want false -- slot already handled under the old nominal convention must not re-fire")
	}
}
