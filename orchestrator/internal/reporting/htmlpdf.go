package reporting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/emulation"
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
	if err := GenerateHTML(&html, rep, compliance); err != nil {
		log.Printf("[reporting] GenerateHTML failed, using fpdf fallback: %v", err)
	} else if pdf, perr := htmlToPDF(ctx, html.Bytes()); perr == nil && len(pdf) > 0 {
		_, werr := w.Write(pdf)
		return werr
	} else {
		log.Printf("[reporting] HTML→PDF via chrome unavailable, using fpdf fallback: %v", perr)
	}
	return RenderReportPDF(w, rep, results)
}

// resolveBaseToIP rewrites base's host to a literal IP address, preferring
// an IPv4 result. Chrome's own DevTools HTTP handler rejects any request
// whose Host header isn't "localhost" or an IP literal -- an anti-DNS-
// rebinding check with no command-line override -- so a Docker Compose
// service-name host like "chrome" is refused outright even though the TCP
// connection itself works fine. Resolving to the container's actual IP on
// every call (rather than baking one into a static env var) keeps this
// correct across container recreates, when the IP can change. Falls back to
// the original base unchanged if the host is already an IP/localhost or
// resolution fails, so the existing reachability retry/fpdf-fallback path
// still applies to genuine outages.
func resolveBaseToIP(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		return base
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return base
	}
	ip := addrs[0]
	for _, a := range addrs {
		if parsed := net.ParseIP(a); parsed != nil && parsed.To4() != nil {
			ip = a
			break
		}
	}
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(ip, port)
	} else {
		u.Host = ip
	}
	return u.String()
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
	base = resolveBaseToIP(base)
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
// unconfigured or the render fails. Retries up to 3 times with 2 s backoff to
// handle the window between Chrome's container starting and its CDP port being
// ready (a race the healthcheck closes on fresh installs, but not mid-upgrade).
func htmlToPDF(ctx context.Context, html []byte) ([]byte, error) {
	base := os.Getenv("CHROME_WS_URL")
	if strings.TrimSpace(base) == "" {
		return nil, fmt.Errorf("chrome sidecar not configured (CHROME_WS_URL unset)")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(2 * time.Second):
			}
		}
		ws := chromeWSURL(ctx, base)
		if ws == "" {
			lastErr = fmt.Errorf("chrome sidecar not reachable at %s (attempt %d)", base, attempt+1)
			log.Printf("[reporting] %v", lastErr)
			continue
		}
		pdf, err := doRenderPDF(ctx, ws, html)
		if err == nil && len(pdf) > 0 {
			return pdf, nil
		}
		lastErr = err
		log.Printf("[reporting] chrome render attempt %d failed: %v", attempt+1, err)
	}
	return nil, fmt.Errorf("chrome render failed after 3 attempts: %w", lastErr)
}

// doRenderPDF performs a single Chrome CDP print-to-PDF pass.
func doRenderPDF(ctx context.Context, ws string, html []byte) ([]byte, error) {
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
		chromedp.ActionFunc(logPrintLayoutWidth),
		chromedp.ActionFunc(func(ctx context.Context) error {
			buf, _, err := printToPDFParams().Do(ctx)
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

// a4WidthCSSPx is the A4 portrait width in CSS pixels: 210mm at the CSS
// definition of 96px per inch. Chrome lays a print job out at the paper width,
// so the document should measure this and no more.
const a4WidthCSSPx = 793.7

// logPrintLayoutWidth measures the document under PRINT media emulation, just
// before the PDF is produced, and logs how wide Chrome actually laid it out.
//
// Why this exists: a real rendered report was measured (2026-09-03) at a
// uniform 0.708 scale — body type at 5.3pt where the CSS asks for ~7.6pt, and
// .inner padding at 25.5pt where the CSS asks for 36pt. Type and padding
// shrinking by the same factor rules out a font-size bug and points at a
// document-level scale. 1/0.708 = 1.414 = the A4 aspect ratio exactly, which
// suggests the layout is happening at 297mm and being scaled down to fit a
// 210mm page — but the cause was NOT established from the CSS, and nothing in
// the template sets zoom, transform:scale or @page.
//
// So this measures rather than assumes. scrollWidth greater than a4WidthCSSPx
// means some element is forcing the document wider than the paper, and the
// offending selector is named in the same log line. Emulating print media
// first matters: @media print changes .page from a fixed 210mm to width:100%
// and turns .page overflow from hidden to visible, so measuring under screen
// media would report a different (and irrelevant) width.
//
// Diagnostic only — it never fails a render. A report that prints slightly
// small is worth far more to a client than no report at all.
func logPrintLayoutWidth(ctx context.Context) error {
	if err := emulation.SetEmulatedMedia().WithMedia("print").Do(ctx); err != nil {
		log.Printf("[report/pdf] layout probe: could not emulate print media: %v", err)
		return nil
	}

	var probe struct {
		ScrollWidth float64 `json:"scrollWidth"`
		ClientWidth float64 `json:"clientWidth"`
		BodyScroll  float64 `json:"bodyScroll"`
		Widest      string  `json:"widest"`
		WidestPx    float64 `json:"widestPx"`
	}
	// Walks every element and reports the one whose right edge extends furthest,
	// so the log names the actual offender instead of just the symptom.
	const js = `(() => {
  const d = document.documentElement, b = document.body;
  let widest = '', widestPx = 0;
  for (const el of document.querySelectorAll('*')) {
    const r = el.getBoundingClientRect();
    const right = r.left + r.width + window.scrollX;
    if (right > widestPx) {
      widestPx = right;
      widest = el.tagName.toLowerCase() +
        (el.id ? '#' + el.id : '') +
        (el.className && typeof el.className === 'string' && el.className.trim()
          ? '.' + el.className.trim().split(/\s+/).join('.') : '');
    }
  }
  return {scrollWidth: d.scrollWidth, clientWidth: d.clientWidth,
          bodyScroll: b ? b.scrollWidth : 0, widest, widestPx};
})()`
	if err := chromedp.Evaluate(js, &probe).Do(ctx); err != nil {
		log.Printf("[report/pdf] layout probe: evaluate failed: %v", err)
		return nil
	}

	if probe.ScrollWidth > a4WidthCSSPx+1 {
		log.Printf("[report/pdf] LAYOUT OVERFLOW: document is %.1f CSS px wide under print media, paper is %.1f "+
			"(%.3fx) — Chrome shrinks to fit, so all type and spacing render %.1f%% smaller than the CSS specifies. "+
			"Widest element: %s at right edge %.1f px (html.scrollWidth=%.1f body.scrollWidth=%.1f clientWidth=%.1f)",
			probe.ScrollWidth, a4WidthCSSPx, probe.ScrollWidth/a4WidthCSSPx,
			100*(1-a4WidthCSSPx/probe.ScrollWidth),
			probe.Widest, probe.WidestPx, probe.ScrollWidth, probe.BodyScroll, probe.ClientWidth)
		return nil
	}
	log.Printf("[report/pdf] layout width OK: %.1f CSS px under print media (paper %.1f)", probe.ScrollWidth, a4WidthCSSPx)
	return nil
}

// printToPDFParams builds the CDP print-to-PDF request: A4 portrait, zero
// device margins (the report's own CSS owns the page padding and the
// cover's full-bleed band), and a native PDF outline/bookmark sidebar
// generated from the report's role="heading" section titles. Factored out
// of doRenderPDF as a plain function (no Chrome dependency) so the params
// themselves are unit-testable without a live sidecar.
func printToPDFParams() *page.PrintToPDFParams {
	return page.PrintToPDF().
		WithPrintBackground(true).
		WithPaperWidth(8.27).WithPaperHeight(11.69).
		WithMarginTop(0).WithMarginBottom(0).WithMarginLeft(0).WithMarginRight(0).
		WithGenerateDocumentOutline(true)
}
