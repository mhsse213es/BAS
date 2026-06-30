package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/audspect/bas/internal/models"
)

// PDFFromReport renders a report to PDF. It prefers HTML→PDF via the headless
// Chromium sidecar (so the PDF is pixel-identical to the styled HTML report);
// if the sidecar is unconfigured or unreachable it falls back to the built-in
// fpdf renderer, so the endpoint always returns a PDF.
func (e *Engine) PDFFromReport(ctx context.Context, w io.Writer, rep *FullReport, compliance []ComplianceSummaryRow, results []models.SimulationResult) error {
	var html bytes.Buffer
	if err := GenerateHTML(&html, rep, compliance); err == nil {
		if pdf, perr := htmlToPDF(ctx, html.Bytes()); perr == nil && len(pdf) > 0 {
			_, werr := w.Write(pdf)
			return werr
		} else if perr != nil {
			log.Printf("[reporting] HTML→PDF via chrome unavailable, using fpdf fallback: %v", perr)
		}
	}
	return RenderReportPDF(w, rep, results)
}

// chromeWSURL resolves the sidecar's browser CDP websocket URL from CHROME_WS_URL.
// Accepts a ws:// URL directly, or an http://host:port base whose /json/version
// is queried for the browser webSocketDebuggerUrl. Returns "" when unconfigured.
func chromeWSURL(ctx context.Context, base string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		return ""
	}
	if strings.HasPrefix(base, "ws://") || strings.HasPrefix(base, "wss://") {
		return base
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/json/version", nil)
	if err != nil {
		return ""
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var v struct {
		WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
	}
	if json.NewDecoder(resp.Body).Decode(&v) != nil {
		return ""
	}
	wsURL := v.WebSocketDebuggerURL
	// Chrome's /json/version always returns 127.0.0.1 in the WebSocket URL, even
	// when launched with --remote-debugging-address=0.0.0.0. From inside the
	// orchestrator container 127.0.0.1 resolves to the orchestrator's own loopback,
	// not the chrome sidecar — so chromedp can't connect and the call fails.
	// Replace the host portion with the one from base (e.g. "chrome:9222").
	if baseU, err := url.Parse(base); err == nil {
		if wsU, err2 := url.Parse(wsURL); err2 == nil {
			wsU.Host = baseU.Host
			wsURL = wsU.String()
		}
	}
	return wsURL
}

// htmlToPDF prints the given HTML to an A4 PDF using the remote headless-shell
// sidecar. Returns an error (so the caller can fall back) when the sidecar is
// unconfigured or the render fails.
func htmlToPDF(ctx context.Context, html []byte) ([]byte, error) {
	ws := chromeWSURL(ctx, os.Getenv("CHROME_WS_URL"))
	if ws == "" {
		return nil, fmt.Errorf("chrome sidecar not configured (CHROME_WS_URL)")
	}

	allocCtx, cancelAlloc := chromedp.NewRemoteAllocator(ctx, ws)
	defer cancelAlloc()
	taskCtx, cancelTask := chromedp.NewContext(allocCtx)
	defer cancelTask()
	taskCtx, cancelTimeout := context.WithTimeout(taskCtx, 45*time.Second)
	defer cancelTimeout()

	var pdf []byte
	err := chromedp.Run(taskCtx,
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			ft, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return err
			}
			return page.SetDocumentContent(ft.Frame.ID, string(html)).Do(ctx)
		}),
		chromedp.Sleep(350*time.Millisecond), // let layout + web fonts settle
		chromedp.ActionFunc(func(ctx context.Context) error {
			// A4 portrait, zero device margins — the report's own CSS owns the
			// page padding and the cover's full-bleed band.
			buf, _, err := page.PrintToPDF().
				WithPrintBackground(true).
				WithPaperWidth(8.27).WithPaperHeight(11.69).
				WithMarginTop(0).WithMarginBottom(0).WithMarginLeft(0).WithMarginRight(0).
				Do(ctx)
			if err != nil {
				return err
			}
			pdf = buf
			return nil
		}),
	)
	if err != nil {
		return nil, err
	}
	return pdf, nil
}
