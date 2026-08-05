package notifications

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

var webhookClient = &http.Client{Timeout: 10 * time.Second}

// fanOutWebhooks POSTs evt as JSON to every enabled webhook whose
// min_severity is at or below evt.Severity. Runs in its own goroutine
// (called via `go` from Emit) -- a slow or unreachable endpoint must never
// block job dispatch or the caller of Emit.
func (s *Service) fanOutWebhooks(ctx context.Context, evt Event) {
	hooks, err := s.store.ListEnabledWebhooks(ctx)
	if err != nil {
		log.Printf("[notifications] list webhooks failed: %v", err)
		return
	}
	body, err := json.Marshal(map[string]any{
		"type":     string(evt.Type),
		"jobId":    evt.JobID,
		"targetId": evt.TargetID,
		"agentId":  evt.AgentID,
		"severity": string(evt.Severity),
		"message":  evt.Message,
		"metadata": evt.Metadata,
	})
	if err != nil {
		log.Printf("[notifications] marshal event failed: %v", err)
		return
	}
	for _, hook := range hooks {
		if severityRank(evt.Severity) < severityRank(Severity(hook.MinSeverity)) {
			continue
		}
		if err := sendWebhook(hook, body); err != nil {
			log.Printf("[notifications] webhook %s delivery failed: %v", hook.Name, err)
		}
	}
}

func sendWebhook(hook Webhook, body []byte) error {
	req, err := http.NewRequest(http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if hook.Secret != "" {
		mac := hmac.New(sha256.New, []byte(hook.Secret))
		mac.Write(body)
		req.Header.Set("X-BAS-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := webhookClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
