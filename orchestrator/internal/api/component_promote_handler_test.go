package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPromoteComponent_Returns200AndComponentID(t *testing.T) {
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		ctx := context.Background()
		if _, err := pool.Exec(ctx, `INSERT INTO scenarios (scenario_id, origin) VALUES ('intel-handler-promote', 'LOCAL') ON CONFLICT DO NOTHING`); err != nil {
			t.Fatal(err)
		}
		artifact := []byte("id: intel-handler-promote\nname: T\nsupported_os: [windows]\nsteps:\n- name: s\n  technique_id: T1059\n  framework: art\n  test_index: 0\n")
		var versionID string
		if err := pool.QueryRow(ctx, `INSERT INTO content_versions
			(content_id, origin, version, artifact_sha256, artifact_size, artifact_bytes,
			 trust_level, lifecycle, intake_source, schema_version, technique_ids, supported_os, created_by)
			VALUES ('intel-handler-promote', 'LOCAL', 1, 'sha-h', $2, $1,
			 'LOCAL_TRUSTED', 'PUBLISHED_LOCAL', 'custom', 1, '{T1059}', '{windows}', 'test') RETURNING id`,
			artifact, len(artifact)).Scan(&versionID); err != nil {
			t.Fatal(err)
		}

		e, _, _ := registryEngine(t, pool)
		h := &Handler{db: pool, engine: e}
		body, _ := json.Marshal(map[string]any{"contentVersionId": versionID, "stepIndex": 0})
		req := httptest.NewRequest(http.MethodPost, "/api/content-registry/components/promote", bytes.NewReader(body))
		w := httptest.NewRecorder()
		h.PromoteComponent(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})
}
