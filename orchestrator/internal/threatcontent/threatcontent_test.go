package threatcontent

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/threatidentity"
)

// seedThreatWithTechnique resolves a new canonical threat and attaches one
// active technique, returning the threat id. Mirrors the pattern already
// used by connector's generator_attempts_test.go (ResolveAndPersist +
// seedActiveTechnique), but this package has no sibling test file to import
// that helper from, so it's redefined here, scoped to this package.
func seedThreatWithTechnique(t *testing.T, pool *pgxpool.Pool, name, techniqueID string) string {
	t.Helper()
	idStore := threatidentity.NewStore(pool)
	resolved, err := idStore.ResolveAndPersist(context.Background(), threatidentity.Incoming{Name: name}, threatidentity.ProfileFields{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO threat_techniques
		(threat_id, technique_id, last_seen_at, status, status_reason)
		VALUES ($1, $2, NOW(), 'active', 'supported')`, resolved.ThreatID, techniqueID); err != nil {
		t.Fatal(err)
	}
	return resolved.ThreatID
}

// seedContentVersion inserts one PUBLISHED_LOCAL, executable content_versions
// row with the given technique_ids, and links it to threatID via
// content_version_threats. Returns the new content_version id.
func seedContentVersion(t *testing.T, pool *pgxpool.Pool, threatID string, techniqueIDs []string) string {
	t.Helper()
	ctx := context.Background()
	contentID := "intel-" + t.Name()
	if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ($1, 'LOCAL') ON CONFLICT DO NOTHING`, contentID); err != nil {
		t.Fatal(err)
	}
	var versionID string
	err := pool.QueryRow(ctx, `INSERT INTO content_versions
		(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
		 trust_level, lifecycle, intake_source, schema_version, technique_ids, created_by)
		VALUES ($1, 'LOCAL', 1, 'sha-'||gen_random_uuid()::text, 1, 'x',
		 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'intel', 1, $2, 'test')
		RETURNING id`, contentID, techniqueIDs).Scan(&versionID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
		(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
		VALUES ($1, $2, 'generated_for', 'generator', 'test')`, versionID, threatID); err != nil {
		t.Fatal(err)
	}
	return versionID
}

func newTestRegistry(pool *pgxpool.Pool) *contentregistry.Registry {
	return contentregistry.New(pool, testutil.DevVerifier())
}

func TestListActiveThreatExposure_ThreatWithNoContentReturnsEmptyContentSlice(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		seedThreatWithTechnique(t, pool, "APT-exposure-nocontent", "T1059")

		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ThreatExposure
		for i := range got {
			if got[i].Title == "APT-exposure-nocontent" {
				found = &got[i]
			}
		}
		if found == nil {
			t.Fatalf("expected the seeded threat in the result, got %+v", got)
		}
		if found.Content == nil || len(found.Content) != 0 {
			t.Fatalf("expected an empty (not nil, not omitted) content slice, got %+v", found.Content)
		}
	})
}

func TestListActiveThreatExposure_DraftContentAppearsAsNotExecutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-draft", "T1059")
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ('intel-draft-test', 'LOCAL') ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		var versionID string
		err := pool.QueryRow(ctx, `INSERT INTO content_versions
			(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			 trust_level, lifecycle, intake_source, schema_version, technique_ids, created_by)
			VALUES ('intel-draft-test', 'LOCAL', 1, 'sha-draft', 1, 'x',
			 'UNTRUSTED', 'DRAFT', 'intel', 1, '{T1059}', 'test')
			RETURNING id`).Scan(&versionID)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO content_version_threats
			(content_version_id, threat_id, relationship_kind, provenance_type, provenance_ref)
			VALUES ($1, $2, 'generated_for', 'generator', 'test')`, versionID, threatID); err != nil {
			t.Fatal(err)
		}

		got, err := ListActiveThreatExposure(ctx, pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ContentExposure
		for _, te := range got {
			for i := range te.Content {
				if te.Content[i].ContentVersionID == versionID {
					found = &te.Content[i]
				}
			}
		}
		if found == nil {
			t.Fatal("expected the DRAFT content version to appear in the response")
		}
		if found.IsExecutable {
			t.Fatalf("expected DRAFT content to be isExecutable=false, got true: %+v", found)
		}
		if found.Validation != "structural-only" {
			t.Fatalf("expected validation=structural-only, got %q", found.Validation)
		}
	})
}

func TestListActiveThreatExposure_TechniqueWithNoMatchingContentIsNotExecutable(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-notech", "T1059")
		// Content exists for this threat, but covers a different technique.
		seedContentVersion(t, pool, threatID, []string{"T1053"})

		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ThreatExposure
		for i := range got {
			if got[i].ThreatID == threatID {
				found = &got[i]
			}
		}
		if found == nil {
			t.Fatal("expected the seeded threat in the result")
		}
		var tech *TechniqueExposure
		for i := range found.Techniques {
			if found.Techniques[i].TechniqueID == "T1059" {
				tech = &found.Techniques[i]
			}
		}
		if tech == nil {
			t.Fatal("expected T1059 in the technique list")
		}
		if tech.HasExecutableContent {
			t.Fatalf("expected hasExecutableContent=false (content covers a different technique), got true: %+v", tech)
		}
	})
}

func TestListActiveThreatExposure_OnlyCountsRunsWithRealContentVersionID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-runs", "T1059")
		versionID := seedContentVersion(t, pool, threatID, []string{"T1059"})
		ctx := context.Background()

		agentID := "agent-" + t.Name()
		if _, err := pool.Exec(ctx, `INSERT INTO agents (agent_id, hostname, os_version, state) VALUES ($1,'h','Windows 10','active') ON CONFLICT DO NOTHING`, agentID); err != nil {
			t.Fatal(err)
		}

		// A real run against this version.
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, content_version_id)
			VALUES (gen_random_uuid()::text, 'intel-exposure-runs', $2, 'r', 'completed', NOW(), $1)`,
			versionID, agentID); err != nil {
			t.Fatal(err)
		}
		// An unrelated run with the same scenario_id string but no content_version_id --
		// must NOT be counted, per the spec's "no string-match fallback" rule.
		if _, err := pool.Exec(ctx, `INSERT INTO scenario_runs (id, scenario_id, agent_id, name, status, started_at, content_version_id)
			VALUES (gen_random_uuid()::text, 'intel-exposure-runs', $1, 'r2', 'completed', NOW(), NULL)`, agentID); err != nil {
			t.Fatal(err)
		}

		got, err := ListActiveThreatExposure(ctx, pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		var found *ContentExposure
		for _, te := range got {
			for i := range te.Content {
				if te.Content[i].ContentVersionID == versionID {
					found = &te.Content[i]
				}
			}
		}
		if found == nil {
			t.Fatal("expected the seeded content version in the response")
		}
		if found.RunCount != 1 {
			t.Fatalf("expected runCount=1 (only the row with a real content_version_id), got %d", found.RunCount)
		}
		if found.LastRunAt == nil {
			t.Fatal("expected lastRunAt to be set")
		}
	})
}

func TestListActiveThreatExposure_ExcludesInactiveThreats(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		threatID := seedThreatWithTechnique(t, pool, "APT-exposure-inactive", "T1059")
		if _, err := pool.Exec(context.Background(), `UPDATE threats SET status = 'inactive' WHERE id = $1`, threatID); err != nil {
			t.Fatal(err)
		}

		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 20, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		for _, te := range got {
			if te.ThreatID == threatID {
				t.Fatalf("expected the inactive threat to be excluded from the default (active) listing, got it in results: %+v", te)
			}
		}
	})
}

func TestListActiveThreatExposure_LimitAndOffsetBounded(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		for i := range 3 {
			seedThreatWithTechnique(t, pool, "APT-exposure-page-"+time.Now().Format("150405.000000")+"-"+string(rune('a'+i)), "T1059")
		}
		got, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), 2, 0)
		if err != nil {
			t.Fatalf("ListActiveThreatExposure: %v", err)
		}
		if len(got) > 2 {
			t.Fatalf("expected limit=2 to cap results, got %d", len(got))
		}
		// Garbage limit must not panic or run unbounded.
		if _, err := ListActiveThreatExposure(context.Background(), pool, newTestRegistry(pool), -5, -5); err != nil {
			t.Fatalf("expected negative limit/offset to be defaulted, not error: %v", err)
		}
	})
}
