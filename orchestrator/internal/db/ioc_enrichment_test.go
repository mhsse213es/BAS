package db_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/audspect/bas/internal/db"
	"github.com/audspect/bas/internal/ioc"
)

func TestUpsertIOCEnrichmentSuccess_RoundTrip(t *testing.T) {
	ctx := context.Background()
	const typ, val, provider = "ip", "45.33.32.156", "otx"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2 AND provider=$3`, typ, val, provider)
	})

	result := &ioc.Result{
		Indicator: val, Type: typ, Provider: provider,
		PulseCount: 3, PulseNames: []string{"Emotet Campaign"},
		MalwareFamilies: []string{"Emotet"}, AdversaryNames: []string{"TA542"},
		Industries: []string{"Financial Services"}, Tags: []string{"emotet"},
	}
	ttl := time.Now().Add(24 * time.Hour)
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, provider, result, 250, ttl); err != nil {
		t.Fatalf("UpsertIOCEnrichmentSuccess: %v", err)
	}

	got, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, provider)
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got == nil {
		t.Fatal("GetIOCEnrichment returned nil for a row that was just upserted")
	}
	if got.PulseCount != 3 || len(got.MalwareFamilies) != 1 || got.MalwareFamilies[0] != "Emotet" {
		t.Errorf("got %+v", got)
	}
	if got.LastSuccessAt == nil {
		t.Error("LastSuccessAt was not set")
	}
	if got.LastFailureAt != nil {
		t.Error("LastFailureAt should be nil -- this row has never failed")
	}
	if !got.TTLExpiresAt.After(time.Now()) {
		t.Error("TTLExpiresAt should be in the future")
	}
}

func TestGetIOCEnrichment_NoRow_ReturnsNilNoError(t *testing.T) {
	got, err := db.GetIOCEnrichment(context.Background(), sharedDB.Pool, "ip", "203.0.113.99", "otx")
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil for an indicator that was never looked up", got)
	}
}

func TestUpsertIOCEnrichmentFailure_PreservesPriorSuccessData(t *testing.T) {
	ctx := context.Background()
	const typ, val, provider = "domain", "evil.example.com", "otx"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2 AND provider=$3`, typ, val, provider)
	})

	result := &ioc.Result{Indicator: val, Type: typ, Provider: provider, PulseCount: 5, MalwareFamilies: []string{"TrickBot"}}
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, provider, result, 100, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed success: %v", err)
	}

	if err := db.UpsertIOCEnrichmentFailure(ctx, sharedDB.Pool, typ, val, provider, errors.New("rate limited"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("UpsertIOCEnrichmentFailure: %v", err)
	}

	got, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, provider)
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got.PulseCount != 5 || len(got.MalwareFamilies) != 1 || got.MalwareFamilies[0] != "TrickBot" {
		t.Errorf("prior success data was overwritten by a later failure: %+v", got)
	}
	if got.LastFailureAt == nil || got.LastError != "rate limited" {
		t.Errorf("failure was not recorded: %+v", got)
	}
	if got.LastSuccessAt == nil {
		t.Error("LastSuccessAt should still be set from the earlier success")
	}
}

func TestUpsertIOCEnrichmentFailure_FirstEverAttempt(t *testing.T) {
	ctx := context.Background()
	const typ, val, provider = "hash", "deadbeefdeadbeefdeadbeefdeadbeef", "otx"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2 AND provider=$3`, typ, val, provider)
	})

	if err := db.UpsertIOCEnrichmentFailure(ctx, sharedDB.Pool, typ, val, provider, errors.New("timeout"), time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("UpsertIOCEnrichmentFailure: %v", err)
	}

	got, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, provider)
	if err != nil {
		t.Fatalf("GetIOCEnrichment: %v", err)
	}
	if got == nil {
		t.Fatal("a failed lookup must still create a cache row (so retries respect the TTL)")
	}
	if got.PulseCount != 0 || got.LastSuccessAt != nil {
		t.Errorf("got %+v, want zero-value success fields on a never-successful row", got)
	}
	if got.LastError != "timeout" {
		t.Errorf("LastError = %q, want timeout", got.LastError)
	}
}

func TestIOCEnrichment_ProviderAwareKeying(t *testing.T) {
	ctx := context.Background()
	const typ, val = "ip", "198.51.100.42"
	t.Cleanup(func() {
		_, _ = sharedDB.Pool.Exec(ctx, `DELETE FROM ioc_enrichment WHERE indicator_type=$1 AND indicator_value=$2`, typ, val)
	})

	otxResult := &ioc.Result{Indicator: val, Type: typ, Provider: "otx", PulseCount: 3}
	otherResult := &ioc.Result{Indicator: val, Type: typ, Provider: "other-provider", PulseCount: 0}
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, "otx", otxResult, 10, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed otx: %v", err)
	}
	if err := db.UpsertIOCEnrichmentSuccess(ctx, sharedDB.Pool, typ, val, "other-provider", otherResult, 10, time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed other-provider: %v", err)
	}

	otx, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, "otx")
	if err != nil || otx == nil || otx.PulseCount != 3 {
		t.Fatalf("otx row wrong: %+v, err=%v", otx, err)
	}
	other, err := db.GetIOCEnrichment(ctx, sharedDB.Pool, typ, val, "other-provider")
	if err != nil || other == nil || other.PulseCount != 0 {
		t.Fatalf("other-provider row wrong: %+v, err=%v", other, err)
	}
}
