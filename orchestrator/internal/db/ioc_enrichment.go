package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/audspect/bas/internal/db/legacy"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/ioc"
)

// EnsureIOCEnrichmentSchema creates the ioc_enrichment cache table. Idempotent
// -- safe to call on every startup.
func EnsureIOCEnrichmentSchema(ctx context.Context, pool *pgxpool.Pool) error {
	return legacy.EnsureIOCEnrichmentSchema(ctx, pool)
}

// Enrichment is one cached provider lookup result for one indicator.
type Enrichment struct {
	IndicatorType    string
	IndicatorValue   string
	Provider         string
	ProviderVersion  string
	SchemaVersion    int
	PulseCount       int
	PulseNames       []string
	MalwareFamilies  []string
	AdversaryNames   []string
	Industries       []string
	Tags             []string
	LookupDurationMs int
	LastSuccessAt    *time.Time
	LastFailureAt    *time.Time
	LastError        string
	TTLExpiresAt     time.Time
}

const currentEnrichmentSchemaVersion = 1

// GetIOCEnrichment returns the cached row for (indicatorType, indicatorValue,
// provider), or nil if none exists yet. Callers compare TTLExpiresAt against
// time.Now() themselves to decide whether it's still fresh enough to skip a
// re-lookup.
func GetIOCEnrichment(ctx context.Context, pool *pgxpool.Pool, indicatorType, indicatorValue, provider string) (*Enrichment, error) {
	var e Enrichment
	var pulseNamesJSON, malwareJSON, adversaryJSON, industriesJSON, tagsJSON []byte
	var lastError *string
	var lookupDurationMs *int
	err := pool.QueryRow(ctx,
		`SELECT indicator_type, indicator_value, provider, provider_version, schema_version,
		        pulse_count, pulse_names, malware_families, adversary_names, industries, tags,
		        lookup_duration_ms, last_success_at, last_failure_at, last_error, ttl_expires_at
		 FROM ioc_enrichment WHERE indicator_type = $1 AND indicator_value = $2 AND provider = $3`,
		indicatorType, indicatorValue, provider,
	).Scan(&e.IndicatorType, &e.IndicatorValue, &e.Provider, &e.ProviderVersion, &e.SchemaVersion,
		&e.PulseCount, &pulseNamesJSON, &malwareJSON, &adversaryJSON, &industriesJSON, &tagsJSON,
		&lookupDurationMs, &e.LastSuccessAt, &e.LastFailureAt, &lastError, &e.TTLExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("ioc enrichment get: %w", err)
	}
	_ = json.Unmarshal(pulseNamesJSON, &e.PulseNames)
	_ = json.Unmarshal(malwareJSON, &e.MalwareFamilies)
	_ = json.Unmarshal(adversaryJSON, &e.AdversaryNames)
	_ = json.Unmarshal(industriesJSON, &e.Industries)
	_ = json.Unmarshal(tagsJSON, &e.Tags)
	if lookupDurationMs != nil {
		e.LookupDurationMs = *lookupDurationMs
	}
	if lastError != nil {
		e.LastError = *lastError
	}
	return &e, nil
}

// UpsertIOCEnrichmentSuccess caches a successful lookup, starting a fresh TTL.
// Only success-related columns are written -- a prior failure's
// last_failure_at/last_error stay as historical record.
func UpsertIOCEnrichmentSuccess(ctx context.Context, pool *pgxpool.Pool, indicatorType, indicatorValue, provider string, result *ioc.Result, lookupDurationMs int, ttlExpiresAt time.Time) error {
	pulseNamesJSON, _ := json.Marshal(result.PulseNames)
	malwareJSON, _ := json.Marshal(result.MalwareFamilies)
	adversaryJSON, _ := json.Marshal(result.AdversaryNames)
	industriesJSON, _ := json.Marshal(result.Industries)
	tagsJSON, _ := json.Marshal(result.Tags)

	_, err := pool.Exec(ctx,
		`INSERT INTO ioc_enrichment
		 (indicator_type, indicator_value, provider, provider_version, schema_version,
		  pulse_count, pulse_names, malware_families, adversary_names, industries, tags,
		  raw_response, lookup_duration_ms, last_success_at, ttl_expires_at)
		 VALUES ($1,$2,$3,'',$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11::jsonb,$12,NOW(),$13)
		 ON CONFLICT (indicator_type, indicator_value, provider) DO UPDATE SET
		   schema_version = EXCLUDED.schema_version,
		   pulse_count = EXCLUDED.pulse_count,
		   pulse_names = EXCLUDED.pulse_names,
		   malware_families = EXCLUDED.malware_families,
		   adversary_names = EXCLUDED.adversary_names,
		   industries = EXCLUDED.industries,
		   tags = EXCLUDED.tags,
		   raw_response = EXCLUDED.raw_response,
		   lookup_duration_ms = EXCLUDED.lookup_duration_ms,
		   last_success_at = NOW(),
		   ttl_expires_at = EXCLUDED.ttl_expires_at`,
		indicatorType, indicatorValue, provider, currentEnrichmentSchemaVersion,
		result.PulseCount, pulseNamesJSON, malwareJSON, adversaryJSON, industriesJSON, tagsJSON,
		[]byte(result.RawResponse), lookupDurationMs, ttlExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("ioc enrichment upsert success: %w", err)
	}
	return nil
}

// UpsertIOCEnrichmentFailure records a failed lookup attempt without clearing
// any previously-cached successful data, starting a fresh TTL so a struggling
// provider isn't retried on every single run's enrichment pass.
func UpsertIOCEnrichmentFailure(ctx context.Context, pool *pgxpool.Pool, indicatorType, indicatorValue, provider string, lookupErr error, ttlExpiresAt time.Time) error {
	_, err := pool.Exec(ctx,
		`INSERT INTO ioc_enrichment
		 (indicator_type, indicator_value, provider, schema_version, pulse_count,
		  last_failure_at, last_error, ttl_expires_at)
		 VALUES ($1,$2,$3,$4,0,NOW(),$5,$6)
		 ON CONFLICT (indicator_type, indicator_value, provider) DO UPDATE SET
		   last_failure_at = NOW(),
		   last_error = EXCLUDED.last_error,
		   ttl_expires_at = EXCLUDED.ttl_expires_at`,
		indicatorType, indicatorValue, provider, currentEnrichmentSchemaVersion,
		lookupErr.Error(), ttlExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("ioc enrichment upsert failure: %w", err)
	}
	return nil
}
