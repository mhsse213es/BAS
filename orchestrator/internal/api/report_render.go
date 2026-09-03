package api

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strconv"
)

// writeBufferedReport renders a report into memory first and only writes to the
// client once it has succeeded.
//
// Every report handler used to pass the http.ResponseWriter straight to the
// renderer. Because html/template streams as it executes, a failure partway
// through had already written a valid-looking prefix AND committed a 200 — so
// the status could no longer be changed. The client received a truncated
// document, and depending on the handler either a JSON error blob appended to
// the broken page or, in most of them, nothing at all beyond a log line the
// operator never saw.
//
// That is not hypothetical. The exercise report aborted at .Execution.Status
// for its entire lifetime (a text/template argument-type mismatch, fixed
// alongside this) and every request still returned 200 with a partial page. A
// handler test asserting "status 200 and body contains <html>" passed happily
// throughout. Buffering makes a render failure look like a failure.
//
// The cost is holding one report in memory. These are per-request operator
// exports, not a hot path, and the PDF renderer already materialises the whole
// document as a []byte internally — so for that path buffering is free.
//
// Setting Content-Length is a side benefit: browsers get a real size and a
// determinate download instead of a chunked stream that simply stops early.
func writeBufferedReport(w http.ResponseWriter, contentType, disposition, logLabel string, render func(io.Writer) error) {
	var buf bytes.Buffer
	if err := render(&buf); err != nil {
		// Logged as well as returned: these renders fail for structural reasons
		// (a template change, a nil field) that an operator seeing only a 500 in
		// the browser cannot diagnose.
		log.Printf("[api] %s: %v", logLabel, err)
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", contentType)
	if disposition != "" {
		w.Header().Set("Content-Disposition", disposition)
	}
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	if _, err := buf.WriteTo(w); err != nil {
		// The document was built fine; the client went away mid-download. Worth
		// a log line, but the status is already sent and there is nothing to
		// report back to a connection that no longer exists.
		log.Printf("[api] %s: write to client failed after %d bytes: %v", logLabel, buf.Len(), err)
	}
}
