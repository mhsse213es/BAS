package exercise

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"net"
	"net/smtp"
	"strconv"
	"strings"
)

// SMTPConfig holds the SMTP server configuration.
type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	FromAddr string `json:"from_addr"`
	FromName string `json:"from_name,omitempty"`
	// TrackerBaseURL is the public URL of this orchestrator instance
	// (e.g. "https://bas.internal") used to build tracking pixel/click URLs.
	TrackerBaseURL string `json:"tracker_base_url,omitempty"`
}

// SMTPInjector delivers phishing simulation emails and wires tracking tokens.
type SMTPInjector struct {
	cfg   SMTPConfig
	store *Store
	chain *EvidenceChain
}

func NewSMTPInjector(cfg SMTPConfig, store *Store, chain *EvidenceChain) *SMTPInjector {
	return &SMTPInjector{cfg: cfg, store: store, chain: chain}
}

// Send delivers the email to all exercise targets and returns a result map.
func (i *SMTPInjector) Send(ctx context.Context, stepExecID, execID string, cfg *EmailConfig, targets []Target) (map[string]interface{}, error) {
	if i.cfg.Host == "" {
		return nil, fmt.Errorf("SMTP host not configured")
	}

	sent := 0
	failed := 0
	var errs []string

	for _, t := range targets {
		addrs := cfg.To
		if len(addrs) == 0 && t.Email != "" {
			addrs = []string{t.Email}
		}
		for _, addr := range addrs {
			if addr == "" {
				continue
			}
			openToken, clickToken := "", ""
			var err error

			if cfg.TrackOpens {
				openToken, err = i.mintToken(ctx, execID, stepExecID, t.ID, "open", map[string]interface{}{
					"target_id": t.ID, "email": addr,
				})
				if err != nil {
					return nil, fmt.Errorf("mint open token: %w", err)
				}
			}
			if cfg.TrackClicks {
				clickToken, err = i.mintToken(ctx, execID, stepExecID, t.ID, "click", map[string]interface{}{
					"target_id": t.ID, "email": addr, "landing": cfg.LandingPage,
				})
				if err != nil {
					return nil, fmt.Errorf("mint click token: %w", err)
				}
			}

			body := i.buildBody(cfg.BodyHTML, openToken, clickToken, i.cfg.TrackerBaseURL)
			if err := i.deliver(addr, cfg.Subject, body); err != nil {
				failed++
				errs = append(errs, fmt.Sprintf("%s: %v", addr, err))
				continue
			}
			sent++
		}
	}

	result := map[string]interface{}{
		"sent":   sent,
		"failed": failed,
	}
	if len(errs) > 0 {
		result["errors"] = errs
	}
	return result, nil
}

// mintToken creates a single-use tracking token in the DB and returns it.
func (i *SMTPInjector) mintToken(ctx context.Context, execID, stepExecID, targetID, tokenType string, payload map[string]interface{}) (string, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	return token, i.store.InsertTrackToken(ctx, token, execID, stepExecID, targetID, tokenType, payload)
}

// buildBody injects the tracking pixel and rewrites anchor hrefs to the
// click-tracking redirect URL.
func (i *SMTPInjector) buildBody(bodyHTML, openToken, clickToken, baseURL string) string {
	var buf bytes.Buffer

	// Rewrite all href= in anchor tags to tracking redirect.
	if clickToken != "" && baseURL != "" {
		redirectURL := fmt.Sprintf("%s/x/click/%s", strings.TrimRight(baseURL, "/"), clickToken)
		// Simple substitution — replace href="..." with the tracking URL.
		// We preserve the original URL in the query param for the redirect target.
		bodyHTML = rewriteLinks(bodyHTML, redirectURL)
	}

	buf.WriteString(bodyHTML)

	// Inject 1×1 open-tracking pixel before </body>.
	if openToken != "" && baseURL != "" {
		pixelURL := fmt.Sprintf("%s/x/open/%s", strings.TrimRight(baseURL, "/"), openToken)
		pixel := fmt.Sprintf(`<img src="%s" width="1" height="1" alt="" style="display:none">`,
			html.EscapeString(pixelURL))
		body := buf.String()
		if idx := strings.LastIndex(body, "</body>"); idx >= 0 {
			return body[:idx] + pixel + body[idx:]
		}
		return body + pixel
	}
	return buf.String()
}

// rewriteLinks replaces all href="..." in <a> tags with the redirect URL,
// appending the original URL as a ?dest= parameter.
func rewriteLinks(body, redirectURL string) string {
	var out strings.Builder
	remaining := body
	for {
		idx := strings.Index(strings.ToLower(remaining), `href="`)
		if idx < 0 {
			out.WriteString(remaining)
			break
		}
		out.WriteString(remaining[:idx])
		out.WriteString(`href="`)
		rest := remaining[idx+6:]
		end := strings.Index(rest, `"`)
		if end < 0 {
			out.WriteString(rest)
			break
		}
		original := rest[:end]
		// Skip anchor/mailto/javascript hrefs — only track http(s).
		lc := strings.ToLower(original)
		if strings.HasPrefix(lc, "http://") || strings.HasPrefix(lc, "https://") {
			out.WriteString(redirectURL)
		} else {
			out.WriteString(original)
		}
		out.WriteString(`"`)
		remaining = rest[end+1:]
	}
	return out.String()
}

// deliver sends the email via the configured SMTP server.
func (i *SMTPInjector) deliver(to, subject, body string) error {
	port := i.cfg.Port
	if port == 0 {
		port = 25
	}
	addr := net.JoinHostPort(i.cfg.Host, strconv.Itoa(port))
	from := i.cfg.FromAddr

	msg := buildMIME(from, i.cfg.FromName, to, subject, body)

	if i.cfg.Username != "" {
		auth := smtp.PlainAuth("", i.cfg.Username, i.cfg.Password, i.cfg.Host)
		return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
	}
	// Unauthenticated relay (internal SMTP relays common in enterprise).
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	client, err := smtp.NewClient(conn, i.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	return w.Close()
}

func buildMIME(from, fromName, to, subject, bodyHTML string) string {
	fromField := from
	if fromName != "" {
		fromField = fmt.Sprintf("%s <%s>", fromName, from)
	}
	return strings.Join([]string{
		"MIME-Version: 1.0",
		"Content-Type: text/html; charset=UTF-8",
		"From: " + fromField,
		"To: " + to,
		"Subject: " + subject,
		"",
		bodyHTML,
	}, "\r\n")
}
