package connector

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/testutil"
)

// Final-review M2 (spec 4.4): the stored generation JSON carries inputs,
// component_versions and attack_version; a missing version source is null
// with a reason, never an invented value.
func TestGenerator_GenerationMetadataStoredOnDraft(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO art_content_meta (id, source_version) VALUES (1, 'art-v9')
			ON CONFLICT (id) DO UPDATE SET source_version = EXCLUDED.source_version`); err != nil {
			t.Fatal(err)
		}
		reg := contentregistry.New(pool, testutil.DevVerifier())
		g := NewGenerator(t.TempDir(), nil, nil, nil).WithRegistrar(reg).WithComponentVersions(DBComponentVersions(pool))
		a := ThreatActor{Name: "Meta Bear", Source: "misp", SourceID: "evt-7", Confidence: "high",
			Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083"}}}
		if res, err := g.Write([]ThreatActor{a}); err != nil || res.Created != 1 {
			t.Fatalf("write: %+v %v", res, err)
		}
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT generation FROM content_versions WHERE content_id = $1`,
			intelContentID(a.Name)).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var gen map[string]any
		if err := json.Unmarshal(raw, &gen); err != nil {
			t.Fatal(err)
		}
		inputs, _ := gen["inputs"].([]any)
		if len(inputs) != 1 {
			t.Fatalf("inputs: %s", raw)
		}
		in0, _ := inputs[0].(map[string]any)
		if in0["entity_type"] != "actor" || in0["entity_id"] != "Meta Bear" || in0["provider"] != "misp" || in0["external_id"] != "evt-7" {
			t.Fatalf("inputs[0]: %s", raw)
		}
		cv, _ := gen["component_versions"].(map[string]any)
		if cv == nil || cv["art"] != "art-v9" {
			t.Fatalf("component_versions.art: %s", raw)
		}
		if v, ok := cv["caldera"]; !ok || v != nil || cv["caldera_reason"] == "" || cv["caldera_reason"] == nil {
			t.Fatalf("component_versions.caldera must be null with a reason: %s", raw)
		}
		if v, ok := gen["attack_version"]; !ok {
			t.Fatalf("attack_version missing: %s", raw)
		} else if v == nil && (gen["attack_version_reason"] == nil || gen["attack_version_reason"] == "") {
			t.Fatalf("null attack_version needs a reason: %s", raw)
		}
		if gen["generator_version"] != generatorVersion {
			t.Fatalf("generator_version: %s", raw)
		}
	})
}
