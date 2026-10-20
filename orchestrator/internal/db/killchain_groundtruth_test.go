package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/killchain"
)

func TestGroundTruth_PutAndGetRoundTrip(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedProofRuns(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		rec := db.GroundTruthRecord{RunID: "pr-lab", Source: "sysmon-event-1", Executed: killchain.TriYes,
			Reference: "host-1:evt-123", RecordedBy: "user-1"}
		if err := s.PutGroundTruth(ctx, rec); err != nil {
			t.Fatal(err)
		}
		got, ok, err := s.GroundTruthForRun(ctx, "pr-lab")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if got.Source != "sysmon-event-1" || got.Executed != killchain.TriYes || got.Reference != "host-1:evt-123" {
			t.Fatalf("round trip lost fields: %+v", got)
		}
	})
}

func TestGroundTruth_RefusalsAreEnforcedByTheStore(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedProofRuns(t, pool)
		ctx := context.Background()
		s := db.KillChainStore{Pool: pool}
		base := db.GroundTruthRecord{RunID: "pr-lab", Source: "sysmon-event-1", Executed: killchain.TriYes, Reference: "ref"}
		cases := map[string]struct {
			mut  func(r *db.GroundTruthRecord)
			want string
		}{
			"run-record source is not independent": {func(r *db.GroundTruthRecord) { r.Source = db.RunRecordSource }, "not independent"},
			"empty source":                         {func(r *db.GroundTruthRecord) { r.Source = "" }, "source is required"},
			"no reference to the evidence":         {func(r *db.GroundTruthRecord) { r.Reference = "" }, "reference is required"},
			"executed must be yes or no":           {func(r *db.GroundTruthRecord) { r.Executed = killchain.TriUnknown }, "yes or no"},
			"unknown run":                          {func(r *db.GroundTruthRecord) { r.RunID = "nope" }, "does not exist"},
			"failed run cannot carry ground truth": {func(r *db.GroundTruthRecord) { r.RunID = "pr-fail" }, "only a completed run"},
		}
		for name, c := range cases {
			r := base
			c.mut(&r)
			err := s.PutGroundTruth(ctx, r)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%s: err = %v, want it to contain %q", name, err, c.want)
			}
		}
	})
}

func TestGroundTruth_MissingRunReturnsNotFound(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		s := db.KillChainStore{Pool: pool}
		_, ok, err := s.GroundTruthForRun(context.Background(), "never-recorded")
		if err != nil || ok {
			t.Fatalf("ok=%v err=%v; no record must be reported as not found", ok, err)
		}
	})
}
