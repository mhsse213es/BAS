package exercise

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// injectorHTTPClient is shared by the HTTP-based injectors (SMS/Slack/Teams).
var injectorHTTPClient = &http.Client{Timeout: 15 * time.Second}

// ── SMS ─────────────────────────────────────────────────────────────────────

// SMSGatewayConfig configures the generic (Twilio-compatible) HTTP SMS gateway.
// Named to avoid colliding with the step-level SMSConfig{To, Body}.
type SMSGatewayConfig struct {
	URL       string `json:"url"`
	AuthToken string `json:"auth_token,omitempty"`
	From      string `json:"from,omitempty"`
}

type SMSInjector struct{ cfg SMSGatewayConfig }

func NewSMSInjector(cfg SMSGatewayConfig) *SMSInjector { return &SMSInjector{cfg: cfg} }

// Send POSTs one JSON request per recipient: {"to","from","body"}.
func (i *SMSInjector) Send(ctx context.Context, to []string, body string) (map[string]any, error) {
	if i.cfg.URL == "" {
		return nil, fmt.Errorf("SMS gateway not configured")
	}
	sent, failed := 0, 0
	var errs []string
	for _, num := range to {
		payload, _ := json.Marshal(map[string]string{"to": num, "from": i.cfg.From, "body": body})
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, i.cfg.URL, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if i.cfg.AuthToken != "" {
			req.Header.Set("Authorization", "Bearer "+i.cfg.AuthToken)
		}
		resp, err := injectorHTTPClient.Do(req)
		if err != nil {
			failed++
			errs = append(errs, num+": "+err.Error())
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			failed++
			errs = append(errs, fmt.Sprintf("%s: HTTP %d", num, resp.StatusCode))
			continue
		}
		sent++
	}
	res := map[string]any{"channel": "sms", "sent": sent, "failed": failed}
	if len(errs) > 0 {
		res["errors"] = errs
	}
	return res, nil
}

// ── Slack / Teams (incoming webhook) ──────────────────────────────────────────

type SlackInjector struct{ webhookURL string }

func NewSlackInjector(webhookURL string) *SlackInjector {
	return &SlackInjector{webhookURL: webhookURL}
}

func (i *SlackInjector) Send(ctx context.Context, text string) (map[string]any, error) {
	return postWebhookJSON(ctx, "slack", i.webhookURL, map[string]any{"text": text})
}

type TeamsInjector struct{ webhookURL string }

func NewTeamsInjector(webhookURL string) *TeamsInjector {
	return &TeamsInjector{webhookURL: webhookURL}
}

func (i *TeamsInjector) Send(ctx context.Context, text string) (map[string]any, error) {
	// Teams incoming webhooks accept a simple {"text": ...} payload.
	return postWebhookJSON(ctx, "teams", i.webhookURL, map[string]any{"text": text})
}

func postWebhookJSON(ctx context.Context, channel, url string, payload map[string]any) (map[string]any, error) {
	if url == "" {
		return nil, fmt.Errorf("%s webhook not configured", channel)
	}
	raw, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := injectorHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s webhook returned HTTP %d", channel, resp.StatusCode)
	}
	return map[string]any{"channel": channel, "sent": 1}, nil
}
