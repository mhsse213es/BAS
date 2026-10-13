package evidence

import (
	"context"
	"testing"
)

func TestActiveTechniquesAndRecordGeneration(t *testing.T) {
	ctx := context.Background()
	store := NewStore(sharedDB.Pool)
	threatID := seedThreat(t, sharedDB.Pool, "APT-generation-test")

	for _, tc := range []struct{ id, status string }{
		{"T1059", "active"}, {"T1055", "active"}, {"T1021", "retracted"},
	} {
		if _, err := sharedDB.Pool.Exec(ctx, `INSERT INTO threat_techniques
			(threat_id, technique_id, last_seen_at, status, status_reason)
			VALUES ($1, $2, NOW(), $3, 'supported')`, threatID, tc.id, tc.status); err != nil {
			t.Fatal(err)
		}
	}

	active, err := store.ActiveTechniques(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 2 || active[0] != "T1055" || active[1] != "T1059" {
		t.Fatalf("ActiveTechniques = %v, want [T1055 T1059] (sorted, retracted excluded)", active)
	}

	genNum, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if genNum != 1 {
		t.Fatalf("NextGenerationNumber = %d, want 1 (first generation)", genNum)
	}

	if err := store.RecordGeneration(ctx, threatID, "intel-abc123", "cv-1", genNum, "tcf2b-generation-v1"); err != nil {
		t.Fatal(err)
	}

	var hash1 string
	if err := sharedDB.Pool.QueryRow(ctx, `SELECT technique_set_hash FROM content_generations WHERE threat_id = $1 AND generation_number = 1`,
		threatID).Scan(&hash1); err != nil {
		t.Fatal(err)
	}
	if hash1 == "" {
		t.Fatal("technique_set_hash must be set")
	}

	genNum2, err := store.NextGenerationNumber(ctx, threatID)
	if err != nil {
		t.Fatal(err)
	}
	if genNum2 != 2 {
		t.Fatalf("NextGenerationNumber after one generation = %d, want 2", genNum2)
	}
}
