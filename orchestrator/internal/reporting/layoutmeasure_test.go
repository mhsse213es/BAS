package reporting

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// TestRenderLocalPDF prints the dumped report through the SAME print parameters
// the sidecar uses, so a PDF built from the working tree can be measured
// without a deploy. Writes to AUDSPECT_LAYOUT_PDF.
func TestRenderLocalPDF(t *testing.T) {
	path := os.Getenv("AUDSPECT_LAYOUT_HTML")
	out := os.Getenv("AUDSPECT_LAYOUT_PDF")
	if path == "" || out == "" {
		t.Skip("set AUDSPECT_LAYOUT_HTML and AUDSPECT_LAYOUT_PDF")
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", "new"))...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, 120*time.Second)
	defer cancelT()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate("file:///"+path),
		chromedp.Sleep(1500*time.Millisecond),
		chromedp.ActionFunc(func(c context.Context) error {
			var err error
			buf, _, err = printToPDFParams().Do(c)
			return err
		}),
	)
	if err != nil {
		t.Fatalf("print: %v", err)
	}
	if err := os.WriteFile(out, buf, 0o644); err != nil {
		t.Fatalf("write pdf: %v", err)
	}
	t.Logf("wrote %s (%d bytes)", out, len(buf))
}

// TestMeasurePrintLayout loads the HTML dumped by TestDumpReportHTML in a real
// browser, emulates print media, and names the element whose right edge extends
// furthest. That element is what makes Chrome shrink the whole PDF to fit.
//
// Same probe as logPrintLayoutWidth in htmlpdf.go, run locally so a fix can be
// verified without a deploy. Skipped unless AUDSPECT_LAYOUT_HTML is set.
func TestMeasurePrintLayout(t *testing.T) {
	path := os.Getenv("AUDSPECT_LAYOUT_HTML")
	if path == "" {
		t.Skip("set AUDSPECT_LAYOUT_HTML to the dumped report HTML")
	}
	abs, err := os.Stat(path)
	if err != nil || abs.Size() == 0 {
		t.Fatalf("no HTML at %s (run TestDumpReportHTML first): %v", path, err)
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:], chromedp.Flag("headless", "new"))...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()
	ctx, cancelT := context.WithTimeout(ctx, 90*time.Second)
	defer cancelT()

	const probe = `(() => {
  const d = document.documentElement;
  const rows = [];
  for (const el of document.querySelectorAll('*')) {
    const r = el.getBoundingClientRect();
    const right = r.left + r.width + window.scrollX;
    rows.push({right: right, sel: el.tagName.toLowerCase() +
      (el.id ? '#' + el.id : '') +
      (el.className && typeof el.className === 'string' && el.className.trim()
        ? '.' + el.className.trim().split(/\s+/).join('.') : ''),
      w: r.width, left: r.left + window.scrollX});
  }
  rows.sort((a,b) => b.right - a.right);
  const seen = new Set(); const top = [];
  for (const r of rows) { if (seen.has(r.sel)) continue; seen.add(r.sel); top.push(r); if (top.length >= 12) break; }
  return JSON.stringify({scrollWidth: d.scrollWidth, clientWidth: d.clientWidth, top: top});
})()`

	var out string
	err = chromedp.Run(ctx,
		chromedp.EmulateViewport(794, 1123),
		chromedp.Navigate("file:///"+path),
		chromedp.ActionFunc(func(c context.Context) error {
			return emulation.SetEmulatedMedia().WithMedia("print").Do(c)
		}),
		chromedp.Sleep(1200*time.Millisecond),
		chromedp.Evaluate(probe, &out),
	)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}

	var res struct {
		ScrollWidth float64 `json:"scrollWidth"`
		ClientWidth float64 `json:"clientWidth"`
		Top         []struct {
			Right float64 `json:"right"`
			Sel   string  `json:"sel"`
			W     float64 `json:"w"`
			Left  float64 `json:"left"`
		} `json:"top"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("decode probe result: %v (raw %.200s)", err, out)
	}

	t.Logf("document scrollWidth=%.1fpx clientWidth=%.1fpx (A4 paper = 793.7px)",
		res.ScrollWidth, res.ClientWidth)
	if res.ScrollWidth > 794 {
		t.Logf("OVERFLOW by %.1fpx -> Chrome will shrink the PDF to %.3fx",
			res.ScrollWidth-793.7, 793.7/res.ScrollWidth)
	}
	for i, r := range res.Top {
		t.Logf("  %2d. right=%7.1f  width=%7.1f  left=%7.1f  %s", i+1, r.Right, r.W, r.Left, r.Sel)
	}
}
