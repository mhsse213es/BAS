package exercise

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strconv"
	"strings"

	"github.com/audspect/bas/internal/exercise/tracker"
)

// SMTPConfig holds the SMTP server configuration.
// Credentials come from environment variables — never stored in the DB.
type SMTPConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password,omitempty"`
	FromAddr       string `json:"from_addr"`
	FromName       string `json:"from_name,omitempty"`
	TrackerBaseURL string `json:"tracker_base_url,omitempty"`
}

// SMTPInjector delivers phishing simulation emails.
// It delegates all HTML tracking concerns (link rewriting, pixel injection,
// token minting) to tracker.GenerateLinks — smtp.go only handles mail delivery.
type SMTPInjector struct {
	cfg   SMTPConfig
	store tracker.TokenStore
}

func NewSMTPInjector(cfg SMTPConfig, store tracker.TokenStore) *SMTPInjector {
	return &SMTPInjector{cfg: cfg, store: store}
}

// Send delivers the email to exercise targets. Tracking links are generated
// by tracker.GenerateLinks before delivery.
func (i *SMTPInjector) Send(ctx context.Context, stepExecID, execID string, cfg *EmailConfig, targets []Target) (map[string]any, error) {
	if i.cfg.Host == "" {
		return nil, fmt.Errorf("SMTP host not configured")
	}
	sent, failed := 0, 0
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
			body, err := tracker.GenerateLinks(ctx, i.store, execID, stepExecID, cfg.BodyHTML, tracker.LinkConfig{
				TrackOpens:  cfg.TrackOpens,
				TrackClicks: cfg.TrackClicks,
				BaseURL:     i.cfg.TrackerBaseURL,
				LandingPage: cfg.LandingPage,
				TargetID:    t.ID,
			})
			if err != nil {
				return nil, fmt.Errorf("generate links for %s: %w", addr, err)
			}
			if err := i.deliver(addr, cfg.Subject, body); err != nil {
				failed++
				errs = append(errs, fmt.Sprintf("%s: %v", addr, err))
				continue
			}
			sent++
		}
	}

	result := map[string]any{"sent": sent, "failed": failed}
	if len(errs) > 0 {
		result["errors"] = errs
	}
	return result, nil
}

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
	// Unauthenticated relay — common for internal enterprise SMTP relays.
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
