package exercise

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

func fireWebhook(ctx context.Context, method, url string, headers map[string]string, body string) error {
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), url, strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook do: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}
