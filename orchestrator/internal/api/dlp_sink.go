package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/audspect/bas/internal/dnssink"
	"github.com/audspect/bas/internal/scenario"
)

// sinkTokenTTL bounds how long an issued DLP sink token remains valid. A
// step's own dispatch-to-completion window is always well under this; the
// margin exists only so a token can't be replayed long after its run ended.
const sinkTokenTTL = 10 * time.Minute

// generateSinkToken returns an n-byte crypto/rand value, hex-encoded (2n hex
// characters). Callers choose n based on how the token will be used: 32
// bytes for the HTTP sink's {{SINK_TOKEN}} (no length constraint on an HTTP
// request body), 8 bytes for the DNS channel's {{SINK_DNS_CAMPAIGN_ID}}
// (must fit inside a single 63-character DNS label alongside a sequence
// number and other structure). Unlike newID() (handlers.go), which derives
// from time.Now().UnixNano() and is therefore guessable within a narrow
// window, this token is the actual anti-replay credential a step must
// present back to prove its payload reached the destination -- it must
// not be predictable regardless of length.
func generateSinkToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate sink token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// issueSinkTokensAndSubstitute scans each step's command text for the
// {{SINK_TOKEN}}/{{SINK_URL}} placeholders. For any step that references
// them, it generates a fresh token, persists it to dlp_sink_tokens keyed by
// run + technique, and substitutes both placeholders into the command text
// before the step is sent to the agent. Steps without the placeholder are
// returned unchanged. The agent never learns a substitution happened -- it
// runs the resulting command exactly like any other step (dumb executor).
func (h *Handler) issueSinkTokensAndSubstitute(ctx context.Context, runID, publicBaseURL string, steps []scenario.ScenarioStep) ([]scenario.ScenarioStep, error) {
	for i := range steps {
		if strings.Contains(steps[i].Command, "{{SINK_TOKEN}}") {
			token, err := generateSinkToken(32)
			if err != nil {
				return nil, err
			}
			expiresAt := time.Now().Add(sinkTokenTTL)
			if _, err := h.db.Exec(ctx,
				`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
				token, runID, steps[i].TechniqueID, expiresAt,
			); err != nil {
				return nil, fmt.Errorf("persist sink token: %w", err)
			}
			sinkURL := strings.TrimRight(publicBaseURL, "/") + "/api/dlp/sink"
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_TOKEN}}", token)
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_URL}}", sinkURL)
		}
		if strings.Contains(steps[i].Command, "{{SINK_DNS_CAMPAIGN_ID}}") {
			campaignID, err := generateSinkToken(8)
			if err != nil {
				return nil, err
			}
			expiresAt := time.Now().Add(sinkTokenTTL)
			if _, err := h.db.Exec(ctx,
				`INSERT INTO dlp_sink_tokens (token, run_id, technique_id, expires_at) VALUES ($1, $2, $3, $4)`,
				campaignID, runID, steps[i].TechniqueID, expiresAt,
			); err != nil {
				return nil, fmt.Errorf("persist dns sink token: %w", err)
			}
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_DNS_CAMPAIGN_ID}}", campaignID)
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_DNS_SERVER}}", dnsServerHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_DNS_DOMAIN}}", dnssink.DomainSuffix)
		}
		if strings.Contains(steps[i].Command, "{{SINK_SFTP_HOST}}") || strings.Contains(steps[i].Command, "{{SINK_SFTP_PORT}}") {
			// Unlike the DNS block above, this does NOT issue its own
			// token: SFTP reuses the existing 32-byte {{SINK_TOKEN}}
			// placeholder directly (no DNS-style label-length constraint),
			// and every real SFTP-wired step's command contains
			// {{SINK_TOKEN}} too (e.g. "{{SINK_TOKEN}}.dat" as the upload
			// filename) -- the unconditional block above already issues
			// and substitutes it whenever present. Re-issuing a second
			// token here would insert an orphaned, never-referenced
			// dlp_sink_tokens row on every SFTP step (the first token is
			// the one that actually ends up in the command the agent
			// runs; ReplaceAll on an already-substituted {{SINK_TOKEN}}
			// is a silent no-op) -- this block only ever substitutes the
			// two placeholders it's uniquely responsible for.
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SFTP_HOST}}", sftpSinkHost(publicBaseURL))
			steps[i].Command = strings.ReplaceAll(steps[i].Command, "{{SINK_SFTP_PORT}}", sftpSinkPort())
		}
	}
	return steps, nil
}

// dnsServerHost extracts just the hostname/IP from publicBaseURL (dropping
// scheme and port) for use as nslookup's explicit server argument -- DNS
// queries target the orchestrator's own address directly, the same
// "explicit target, not customer DNS routing" principle {{SINK_URL}}
// already uses for the HTTP channel.
func dnsServerHost(publicBaseURL string) string {
	u, err := url.Parse(publicBaseURL)
	if err != nil || u.Hostname() == "" {
		return publicBaseURL
	}
	return u.Hostname()
}

// sftpSinkHost resolves the {{SINK_SFTP_HOST}} placeholder: an explicit
// SINK_SFTP_HOST environment override if set (for deployments where the
// externally reachable SFTP address differs from publicBaseURL's host,
// e.g. behind NAT), otherwise the same derivation dnsServerHost already
// uses -- no new derivation logic.
func sftpSinkHost(publicBaseURL string) string {
	if v := os.Getenv("SINK_SFTP_HOST"); v != "" {
		return v
	}
	return dnsServerHost(publicBaseURL)
}

// sftpSinkPort resolves the {{SINK_SFTP_PORT}} placeholder: the
// configured SINK_SFTP_PORT (the host-published port an external client
// actually connects to, NOT the container-internal :22 the listener
// itself binds), defaulting to 2222 if unset.
func sftpSinkPort() string {
	if v := os.Getenv("SINK_SFTP_PORT"); v != "" {
		return v
	}
	return "2222"
}

type dlpSinkRequest struct {
	Token   string `json:"token"`
	Payload string `json:"payload"`
	Channel string `json:"channel"`
}

// DLPSink is POST /api/dlp/sink -- deliberately unauthenticated (see
// routes.go's publicRoutes and the design spec's rationale: the point is
// testing whether *content* gets intercepted in flight, not testing access
// control). Logs whatever it receives; never errors on an unrecognized
// token -- that distinction is exactly what an inspecting proxy/DLP
// shouldn't be able to learn from the response. The raw payload is never
// stored, only its hash and length.
func (h *Handler) DLPSink(w http.ResponseWriter, r *http.Request) {
	var req dlpSinkRequest
	_ = json.NewDecoder(r.Body).Decode(&req)

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	sum := sha256.Sum256([]byte(req.Payload))

	_, _ = h.db.Exec(r.Context(),
		`INSERT INTO dlp_sink_receipts (token, source_ip, payload_hash, payload_size, channel)
		 VALUES ($1, $2, $3, $4, $5)`,
		req.Token, host, hex.EncodeToString(sum[:]), len(req.Payload), req.Channel,
	)
	w.WriteHeader(http.StatusOK)
}
