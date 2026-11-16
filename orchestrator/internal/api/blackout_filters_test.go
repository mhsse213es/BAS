package api

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/jobs"
	"github.com/audspect/bas/internal/license"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
)

// The weekday and month-day filters are accepted through the API, returned by the list, and a bad one is a 400.
func TestScheduledBlackouts_DayFiltersThroughTheAPI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		store := jobs.NewStore(pool)
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), testJWTSecret).WithJobsDispatcher(store, jobs.NewDispatcher(store))
		prev := license.Current()
		license.SetInitial(license.Info{State: license.StateValid, Tier: license.TierEnterprise})
		t.Cleanup(func() { license.SetInitial(prev) })
		router := Mount(h, ws.NewHub(), testJWTSecret, "", http.NotFoundHandler(), 0, 0)

		tenant := "default"
		tok, err := auth.GenerateTenantToken("blk-analyst", auth.RoleAnalyst, &tenant, false, testJWTSecret, time.Hour)
		if err != nil {
			t.Fatal(err)
		}

		rec := ciDo(router, http.MethodPost, "/api/scheduled-blackouts", tok,
			`{"name":"Month end","kind":"daily","timeFrom":"00:00","timeTo":"24:00","timezone":"Asia/Kolkata","weekdays":"mon,tue,wed,thu,fri","monthDays":"-2,-1,1"}`)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create: status %d, body %s", rec.Code, rec.Body.String())
		}
		for _, body := range []string{
			`{"name":"x","kind":"daily","timeFrom":"00:00","timeTo":"24:00","timezone":"UTC","weekdays":"funday"}`,
			`{"name":"x","kind":"daily","timeFrom":"00:00","timeTo":"24:00","timezone":"UTC","monthDays":"0"}`,
			`{"name":"x","kind":"daily","timeFrom":"24:00","timeTo":"06:00","timezone":"UTC"}`,
		} {
			if c := ciDo(router, http.MethodPost, "/api/scheduled-blackouts", tok, body).Code; c != http.StatusBadRequest {
				t.Errorf("body %s: status %d, want 400", body, c)
			}
		}

		list := ciDo(router, http.MethodGet, "/api/scheduled-blackouts", tok, "")
		var out struct {
			Blackouts []struct {
				Name, Weekdays, MonthDays, TimeTo string
			} `json:"blackouts"`
		}
		if err := json.Unmarshal(list.Body.Bytes(), &out); err != nil || len(out.Blackouts) != 1 {
			t.Fatalf("list: %v, %s", err, list.Body.String())
		}
		if g := out.Blackouts[0]; g.Weekdays != "mon,tue,wed,thu,fri" || g.MonthDays != "-2,-1,1" || g.TimeTo != "24:00" {
			t.Fatalf("listed window lost its filters: %+v", g)
		}
	})
}
