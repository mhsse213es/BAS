package ticketing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// webhookConnector implements Connector by POSTing JSON to a configurable URL.
// Useful for any system that can receive HTTP webhooks (OpsGenie, custom SOAR,
// Teams/Slack alert channels, etc.).
//
// Settings:
//   url           — target endpoint (required)
//   secret        — HMAC-SHA256 key; if set, X-BAS-Signature header is added
//   header_*      — extra headers, e.g. header_Authorization = Bearer token
type webhookConnector struct {
	url        string
	secret     string
	headers    map[string]string
	httpClient *http.Client
}

func newWebhook(settings map[string]string) *webhookConnector {
	headers := map[string]string{}
	for k, v := range settings {
		if strings.HasPrefix(k, "header_") {
			headers[strings.TrimPrefix(k, "header_")] = v
		}
	}
	return &webhookConnector{
		url:        settings["url"],
		secret:     settings["secret"],
		headers:    headers,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

type webhookPayload struct {
	Action     string        `json:"action"`
	TicketID   string        `json:"ticketId,omitempty"`
	RecordType string        `json:"recordType,omitempty"`
	Comment    string        `json:"comment,omitempty"`
	Finding    *TicketFinding `json:"finding,omitempty"`
}

func (w *webhookConnector) CreateTicket(ctx context.Context, f TicketFinding, rt RecordType) (TicketRef, error) {
	resp, err := w.post(ctx, webhookPayload{Action: "create", RecordType: string(rt), Finding: &f})
	if err != nil {
		return TicketRef{}, err
	}
	// If the webhook returns {ticketId, ticketUrl} use them; otherwise synthesise an ID.
	var ref struct {
		TicketID  string `json:"ticketId"`
		TicketURL string `json:"ticketUrl"`
	}
	if json.Unmarshal(resp, &ref) == nil && ref.TicketID != "" {
		return TicketRef{TicketID: ref.TicketID, TicketURL: ref.TicketURL}, nil
	}
	return TicketRef{TicketID: "wh-" + f.FindingID[:8], TicketURL: ""}, nil
}

func (w *webhookConnector) AddComment(ctx context.Context, ticketID, body string) error {
	_, err := w.post(ctx, webhookPayload{Action: "comment", TicketID: ticketID, Comment: body})
	return err
}

func (w *webhookConnector) CloseTicket(ctx context.Context, ticketID string) error {
	_, err := w.post(ctx, webhookPayload{Action: "close", TicketID: ticketID})
	return err
}

func (w *webhookConnector) ReopenTicket(ctx context.Context, ticketID string) error {
	_, err := w.post(ctx, webhookPayload{Action: "reopen", TicketID: ticketID})
	return err
}

// GetStatus is not supported for generic webhooks — they are fire-and-forget.
func (w *webhookConnector) GetStatus(_ context.Context, _ string) (string, error) {
	return "unknown", nil
}

func (w *webhookConnector) TestConnection(ctx context.Context) error {
	_, err := w.post(ctx, webhookPayload{Action: "ping"})
	return err
}

func (w *webhookConnector) post(ctx context.Context, payload any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}
	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(data)
		req.Header.Set("X-BAS-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook POST: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("webhook: HTTP %d: %s", resp.StatusCode, body)
	}
	return body, nil
}
