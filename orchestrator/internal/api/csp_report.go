package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"unicode"

	"golang.org/x/time/rate"
)

// CSP violation reports (G1d spec 4.6). Browsers send them without the app's
// credentials, so this endpoint is public and trusts nothing: two content
// types, a 16 KB body cap, every logged value stripped of control characters
// and truncated, no database writes, and a global token bucket so a page
// stuck in a violation loop cannot flood the log (excess is counted).

const (
	cspReportMaxBytes = 16 << 10
	cspFieldMax       = 256
	cspMaxEntries     = 20
)

var (
	cspReportLimiter  = rate.NewLimiter(rate.Limit(1), 30)
	cspReportsDropped atomic.Int64
)

type cspViolation struct {
	DocumentURI, Directive, BlockedURI, SourceFile string
	Line                                           int
}

func (h *Handler) CSPReport(w http.ResponseWriter, r *http.Request) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/csp-report" && ct != "application/reports+json" {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cspReportMaxBytes))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "report too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "unreadable report", http.StatusBadRequest)
		return
	}
	vs, err := parseCSPReports(ct, body)
	if err != nil {
		http.Error(w, "malformed report", http.StatusBadRequest)
		return
	}
	for _, v := range vs {
		logCSPViolation(v)
	}
	w.WriteHeader(http.StatusNoContent)
}

func parseCSPReports(ct string, body []byte) ([]cspViolation, error) {
	if ct == "application/csp-report" {
		var doc struct {
			Report struct {
				DocumentURI        string `json:"document-uri"`
				ViolatedDirective  string `json:"violated-directive"`
				EffectiveDirective string `json:"effective-directive"`
				BlockedURI         string `json:"blocked-uri"`
				SourceFile         string `json:"source-file"`
				LineNumber         int    `json:"line-number"`
			} `json:"csp-report"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, err
		}
		d := doc.Report.EffectiveDirective
		if d == "" {
			d = doc.Report.ViolatedDirective
		}
		return []cspViolation{{doc.Report.DocumentURI, d, doc.Report.BlockedURI, doc.Report.SourceFile, doc.Report.LineNumber}}, nil
	}
	var list []struct {
		Type string `json:"type"`
		Body struct {
			DocumentURL        string `json:"documentURL"`
			EffectiveDirective string `json:"effectiveDirective"`
			BlockedURL         string `json:"blockedURL"`
			SourceFile         string `json:"sourceFile"`
			LineNumber         int    `json:"lineNumber"`
		} `json:"body"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, err
	}
	var out []cspViolation
	for _, e := range list {
		if e.Type != "csp-violation" || len(out) == cspMaxEntries {
			continue
		}
		out = append(out, cspViolation{e.Body.DocumentURL, e.Body.EffectiveDirective, e.Body.BlockedURL, e.Body.SourceFile, e.Body.LineNumber})
	}
	return out, nil
}

func logCSPViolation(v cspViolation) {
	if !cspReportLimiter.Allow() {
		cspReportsDropped.Add(1)
		return
	}
	log.Printf("[csp] violation directive=%q blocked=%q document=%q source=%q line=%d dropped_since_last=%d",
		cleanCSPField(v.Directive), cleanCSPField(v.BlockedURI), cleanCSPField(v.DocumentURI),
		cleanCSPField(v.SourceFile), v.Line, cspReportsDropped.Swap(0))
}

// cleanCSPField removes control characters and caps the length, so a report
// can neither forge log lines nor bloat the log.
func cleanCSPField(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > cspFieldMax {
		s = string(r[:cspFieldMax]) + "…"
	}
	return s
}
