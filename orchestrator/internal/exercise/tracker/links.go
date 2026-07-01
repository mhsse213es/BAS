package tracker

import (
	"context"
	"fmt"
	"strings"
)

// GenerateLinks is the single entry point for all injectors that need
// click/open tracking. It mints tokens, rewrites hrefs, and injects the
// open pixel. The injector itself only handles delivery — no HTML parsing.
func GenerateLinks(ctx context.Context, store TokenStore, execID, stepExecID string, bodyHTML string, cfg LinkConfig) (string, error) {
	if cfg.BaseURL == "" {
		return bodyHTML, nil
	}
	base := strings.TrimRight(cfg.BaseURL, "/")

	if cfg.TrackClicks {
		clickToken, err := MintToken(ctx, store, execID, stepExecID, cfg.TargetID, "click", map[string]any{
			"target_id": cfg.TargetID,
			"landing":   cfg.LandingPage,
		})
		if err != nil {
			return "", fmt.Errorf("mint click token: %w", err)
		}
		redirectURL := fmt.Sprintf("%s/x/click/%s", base, clickToken)
		bodyHTML = rewriteLinks(bodyHTML, redirectURL)
	}

	if cfg.TrackOpens {
		openToken, err := MintToken(ctx, store, execID, stepExecID, cfg.TargetID, "open", map[string]any{
			"target_id": cfg.TargetID,
		})
		if err != nil {
			return "", fmt.Errorf("mint open token: %w", err)
		}
		pixelURL := fmt.Sprintf("%s/x/open/%s", base, openToken)
		bodyHTML = injectPixel(bodyHTML, pixelURL)
	}

	return bodyHTML, nil
}

// rewriteLinks replaces all http(s) hrefs in <a> tags with the redirect URL.
// The original destination URL is embedded in the redirect step — the redirect
// handler restores it from the token payload.
func rewriteLinks(body, redirectURL string) string {
	var out strings.Builder
	remaining := body
	for {
		lower := strings.ToLower(remaining)
		idx := strings.Index(lower, `href="`)
		if idx < 0 {
			out.WriteString(remaining)
			break
		}
		out.WriteString(remaining[:idx+6]) // write up to and including href="
		rest := remaining[idx+6:]
		end := strings.Index(rest, `"`)
		if end < 0 {
			out.WriteString(rest)
			break
		}
		original := rest[:end]
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

// injectPixel inserts a 1×1 transparent tracking pixel before </body>.
func injectPixel(body, pixelURL string) string {
	pixel := fmt.Sprintf(`<img src="%s" width="1" height="1" alt="" style="display:none">`, pixelURL)
	if idx := strings.LastIndex(strings.ToLower(body), "</body>"); idx >= 0 {
		return body[:idx] + pixel + body[idx:]
	}
	return body + pixel
}
