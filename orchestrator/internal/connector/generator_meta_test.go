package connector

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/audspect/bas/internal/contentregistry"
	"github.com/audspect/bas/internal/reporting/attackdata"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/testutil"
	"github.com/audspect/bas/internal/threatidentity"
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
		var actorID, threatID string
		if err := pool.QueryRow(ctx, `INSERT INTO threat_actor_profiles (name) VALUES ('Meta Bear') RETURNING id`).Scan(&actorID); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `INSERT INTO threats (id, subject_type, subject_id, actor_id, title)
			VALUES ('thr-' || gen_random_uuid()::text, 'actor', $1, $1, 'Meta Bear') RETURNING id`, actorID).Scan(&threatID); err != nil {
			t.Fatal(err)
		}
		a := ThreatActor{Name: "Meta Bear", ActorID: actorID, ThreatID: threatID, Source: "misp", SourceID: "evt-7", Confidence: "high",
			Techniques: []TechniqueRef{{ID: "T1082"}, {ID: "T1083"}}}
		if res, err := g.Write([]ThreatActor{a}); err != nil || res.Created != 1 {
			t.Fatalf("write: %+v %v", res, err)
		}
		var raw []byte
		if err := pool.QueryRow(ctx, `SELECT generation FROM content_versions WHERE content_id = $1`,
			threatidentity.ContentID(a.ThreatID)).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var gen map[string]any
		if err := json.Unmarshal(raw, &gen); err != nil {
			t.Fatal(err)
		}
		inputs, _ := gen["inputs"].([]any)
		if len(inputs) != 2 {
			t.Fatalf("inputs: %s", raw)
		}
		in0, _ := inputs[0].(map[string]any)
		in1, _ := inputs[1].(map[string]any)
		if in0["entity_type"] != "threat" || in0["entity_id"] != threatID {
			t.Fatalf("inputs[0]: %s", raw)
		}
		if in1["entity_type"] != "actor" || in1["entity_id"] != actorID || in1["provider"] != "misp" || in1["external_id"] != "evt-7" {
			t.Fatalf("inputs[1]: %s", raw)
		}
		cv, _ := gen["component_versions"].(map[string]any)
		if cv == nil || cv["art"] != "art-v9" {
			t.Fatalf("component_versions.art: %s", raw)
		}
		if v, ok := cv["caldera"]; !ok || v != nil || cv["caldera_reason"] == "" || cv["caldera_reason"] == nil {
			t.Fatalf("component_versions.caldera must be null with a reason: %s", raw)
		}
		if gen["attack_version"] != "16.1" ||
			gen["attack_dataset_sha256"] != "8423d8dac3fc2feb825bb07d26e5f5d905e08a88f6fe4652cc20834cbe982813" {
			t.Fatalf("attack dataset: %s", raw)
		}
		if _, ok := gen["attack_version_reason"]; ok {
			t.Fatalf("a known version carries no reason: %s", raw)
		}
		if gen["attack_dataset_use"] != "actor canonicalization (ATT&CK groups)" ||
			gen["tactic_mapping"] != "static prefix table (mapping_version)" {
			t.Fatalf("dataset influence not recorded: %s", raw)
		}
		if gen["generator_version"] != generatorVersion {
			t.Fatalf("generator_version: %s", raw)
		}
	})
}

func TestGenerationMeta_UnknownAttackDataset(t *testing.T) {
	g := NewGenerator(t.TempDir(), nil, nil, nil)
	g.attackMeta = func() attackdata.Meta { return attackdata.Meta{SourceBundleSHA256: "ab"} }
	gen := g.generationMeta(ThreatActor{Name: "X"}, scenario.ComponentVersions{}, nil)
	if v, ok := gen["attack_version"]; !ok || v != nil || gen["attack_version_reason"] != "dataset version unavailable" {
		t.Fatalf("unknown dataset: %v", gen)
	}
}
