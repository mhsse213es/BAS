package contentregistry

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/testutil"
)

const destructiveYAML = `id: recheck-destructive
name: Recheck Destructive
steps:
  - {name: a, technique_id: T9999, framework: custom, command: y}
`

const nonDestructiveYAML = `id: recheck-safe
name: Recheck Safe
steps:
  - {name: a, technique_id: T1082, framework: custom, command: x}
`

func TestDispatchSafetyRecheck_RefusesDestructiveVerdict(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())

		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "recheck-destructive", origin: OriginLocal, source: SourceCustom,
			artifact: []byte(destructiveYAML), trust: TrustUntrusted, lifecycle: LifecycleDraft,
			actor: ActorGenerator, analysis: mustAnalyze(t, destructiveYAML),
		})
		if err != nil {
			t.Fatalf("createVersion: %v", err)
		}
		v, err := reg.LoadVersion(ctx, vid)
		if err != nil {
			t.Fatalf("LoadVersion: %v", err)
		}

		if err := reg.DispatchSafetyRecheck(ctx, v); err == nil {
			t.Fatal("a destructive verdict must refuse the dispatch")
		}

		var count int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'dispatch-recheck'`,
			v.ID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("got %d dispatch-recheck rows, err=%v, want exactly 1", count, err)
		}

		var detail []byte
		if err := pool.QueryRow(ctx,
			`SELECT detail FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'dispatch-recheck'`,
			v.ID).Scan(&detail); err != nil {
			t.Fatalf("read detail: %v", err)
		}
		var parsed any
		if err := json.Unmarshal(detail, &parsed); err != nil || len(detail) <= len("[]") {
			t.Fatalf("detail must be real, non-empty JSON, got %q", detail)
		}
	})
}

func TestDispatchSafetyRecheck_PassesNonDestructive(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		reg := New(pool, testutil.DevVerifier())

		vid, _, err := reg.createVersion(ctx, newVersion{
			contentID: "recheck-safe", origin: OriginLocal, source: SourceCustom,
			artifact: []byte(nonDestructiveYAML), trust: TrustUntrusted, lifecycle: LifecycleDraft,
			actor: ActorGenerator, analysis: mustAnalyze(t, nonDestructiveYAML),
		})
		if err != nil {
			t.Fatalf("createVersion: %v", err)
		}
		v, err := reg.LoadVersion(ctx, vid)
		if err != nil {
			t.Fatalf("LoadVersion: %v", err)
		}

		if err := reg.DispatchSafetyRecheck(ctx, v); err != nil {
			t.Fatalf("a non-destructive verdict must not be refused: %v", err)
		}
		var count int
		pool.QueryRow(ctx,
			`SELECT count(*) FROM content_safety_verdicts WHERE content_version_id = $1 AND classifier = 'dispatch-recheck'`,
			v.ID).Scan(&count)
		if count != 0 {
			t.Fatalf("a passing re-check must not write a refusal row, got %d", count)
		}
	})
}
