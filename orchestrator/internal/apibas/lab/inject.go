package lab

// Injection routes (API-BAS-INJ-001 to INJ-012, except 005 and 007, which are Phase 3).
//
// Each route exists in both builds. The vulnerable build interprets the caller's input:
// a predicate, a template, a filter, a path, a URL, a header value, a merge key or a
// form field. The fixed build refuses that input with 400 or 403 and does not interpret
// it. Evidence is deterministic: a protected value in a response, a changed owner or
// status, or a header carrying the injected value.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"
)

// registerInjection adds the injection routes to the mux. They are registered in both
// modes.
func (s *Server) registerInjection(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/search/orders", s.injSearchOrders)         // INJ-001
	mux.HandleFunc("POST /api/reports/filter", s.injReportFilter)       // INJ-002
	mux.HandleFunc("POST /api/notifications/preview", s.injPreview)     // INJ-003
	mux.HandleFunc("GET /api/directory/search", s.injDirectorySearch)   // INJ-004
	mux.HandleFunc("POST /api/orders/{id}/settings", s.injSettings)     // INJ-006
	mux.HandleFunc("GET /api/files/download", s.injDownload)            // INJ-008
	mux.HandleFunc("POST /api/orders/{id}/notes", s.injNotes)           // INJ-009
	mux.HandleFunc("POST /api/imports/fetch", s.injImport)              // INJ-010
	mux.HandleFunc("POST /api/orders/{id}/attributes", s.injAttributes) // INJ-011
	mux.HandleFunc("POST /api/orders/{id}/transition", s.injTransition) // INJ-012
}

func (s *Server) vulnerable() bool { return s.cfg.Mode == ModeVulnerable }

// requireCaller answers 401 and reports false when the request carries no valid credential.
func (s *Server) requireCaller(w http.ResponseWriter, r *http.Request) (string, bool) {
	caller, st := s.identify(r)
	if st != authOK {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return "", false
	}
	return caller, true
}

// validStatuses are the only order statuses the lab accepts through the validated paths.
var validStatuses = map[string]bool{"pending": true, "shipped": true, "cancelled": true}

// sortedOrders returns the orders in ID order, so responses are deterministic.
func sortedOrders(orders map[string]*Order) []*Order {
	ids := slices.Sorted(maps.Keys(orders))
	out := make([]*Order, 0, len(ids))
	for _, id := range ids {
		out = append(out, orders[id])
	}
	return out
}

// publicView is the order without its protected values.
func publicView(o *Order) map[string]any {
	body := map[string]any{"id": o.ID, "owner_id": o.OwnerID, "status": o.Status}
	for k, v := range o.Public {
		body[k] = v
	}
	return body
}

// --- INJ-001: SQL and NoSQL injection --------------------------------------------------

// tautology reports a quote followed by OR, the shape of a classic always-true predicate.
func tautology(q string) bool {
	return strings.Contains(q, "'") && strings.Contains(strings.ToUpper(q), " OR ")
}

// injSearchOrders matches an order ID exactly and only for its owner. The vulnerable build
// splices the parameter into the predicate, so an always-true clause returns every order.
func (s *Server) injSearchOrders(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	q := r.URL.Query().Get("q")
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []map[string]any{}
	for _, o := range sortedOrders(s.orders) {
		switch {
		case s.vulnerable() && tautology(q):
			out = append(out, orderBody(o))
		case o.OwnerID == caller && o.ID == q:
			out = append(out, publicView(o))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": out})
}

// --- INJ-002: expression injection ----------------------------------------------------

// injReportFilter accepts a status filter in both builds. The vulnerable build also
// evaluates an expression field, and a true disjunct matches every order.
func (s *Server) injReportFilter(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if expr, has := req["expression"]; has {
		if !s.vulnerable() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported field: expression"})
			return
		}
		text, _ := expr.(string)
		if !strings.Contains(text, "||") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported expression"})
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		out := []map[string]any{}
		for _, o := range sortedOrders(s.orders) {
			out = append(out, orderBody(o))
		}
		writeJSON(w, http.StatusOK, map[string]any{"orders": out})
		return
	}
	status, _ := req["status"].(string)
	if !validStatuses[status] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of pending, shipped, cancelled"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []map[string]any{}
	for _, o := range sortedOrders(s.orders) {
		if o.OwnerID == caller && o.Status == status {
			out = append(out, publicView(o))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": out})
}

// --- INJ-003: server-side template injection --------------------------------------------

// fillTokens replaces the two supported placeholders. The fixed build uses only this.
func fillTokens(message string, data map[string]any) string {
	return strings.NewReplacer("{id}", fmt.Sprint(data["id"]), "{status}", fmt.Sprint(data["status"])).Replace(message)
}

// injPreview renders a notification preview. The vulnerable build also parses a
// caller-supplied template against the full record, protected values included.
func (s *Server) injPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCaller(w, r); !ok {
		return
	}
	var req map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	id, _ := req["order_id"].(string)
	message, _ := req["message"].(string)
	s.mu.Lock()
	o, found := s.orders[id]
	var data map[string]any
	if found {
		data = orderBody(o)
	}
	s.mu.Unlock()
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if tpl, has := req["template"]; has {
		if !s.vulnerable() {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "templates are not supported"})
			return
		}
		text, _ := tpl.(string)
		parsed, err := template.New("preview").Parse(text)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "template does not parse"})
			return
		}
		var buf bytes.Buffer
		if err := parsed.Execute(&buf, data); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "template failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"preview": buf.String()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"preview": fillTokens(message, data)})
}

// --- INJ-004: LDAP filter injection ----------------------------------------------------

// injDirectorySearch looks up entries by owner ID. The vulnerable build builds an
// unescaped filter, so a wildcard matches every entry, protected values included.
func (s *Server) injDirectorySearch(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	uid := r.URL.Query().Get("uid")
	wildcard := strings.ContainsAny(uid, "*()\\")
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []map[string]any{}
	for _, o := range sortedOrders(s.orders) {
		if wildcard {
			if s.vulnerable() {
				out = append(out, orderBody(o))
			}
			continue
		}
		if o.OwnerID == uid && o.OwnerID == caller {
			out = append(out, publicView(o))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// --- INJ-006: JSON parser and duplicate keys -------------------------------------------

// keyValue is one top-level member of a JSON object, in document order.
type keyValue struct {
	key string
	raw json.RawMessage
}

// topLevelPairs reads the members of a JSON object in document order, keeping duplicates.
func topLevelPairs(body []byte) ([]keyValue, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("body must be a JSON object")
	}
	var out []keyValue
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("invalid key")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		out = append(out, keyValue{key, raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return out, nil
}

// injSettings updates an owner's order status. The fixed build rejects a duplicate key.
// The vulnerable build validates the first occurrence and applies the last, so a second
// status overrides a validated one.
func (s *Server) injSettings(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	pairs, err := topLevelPairs(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var statuses []string
	for _, p := range pairs {
		if p.key != "status" {
			continue
		}
		var v string
		if json.Unmarshal(p.raw, &v) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be a string"})
			return
		}
		statuses = append(statuses, v)
	}
	if len(statuses) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status is required"})
		return
	}
	if !s.vulnerable() && len(statuses) > 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "duplicate key: status"})
		return
	}
	if !validStatuses[statuses[0]] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of pending, shipped, cancelled"})
		return
	}
	apply := statuses[len(statuses)-1]
	if !s.vulnerable() && !validStatuses[apply] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of pending, shipped, cancelled"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	o.Status = apply
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// --- INJ-008: path traversal -----------------------------------------------------------

var csvName = regexp.MustCompile(`^[A-Za-z0-9-]+\.csv$`)

// publicCSV is the owner-visible export of an order.
func publicCSV(o *Order) string {
	return fmt.Sprintf("id,owner_id,status\n%s,%s,%s\n", o.ID, o.OwnerID, o.Status)
}

// recordText is the internal record of an order, protected values included.
func recordText(o *Order) string {
	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(o.Protected)) {
		fmt.Fprintf(&b, "%s=%s\n", k, o.Protected[k])
	}
	return b.String()
}

func writeText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, text)
}

// injDownload returns an export file. The fixed build accepts only a plain CSV name and
// the owner's own export. The vulnerable build joins the name onto the exports directory
// without checking it, so a traversal reaches the internal records.
func (s *Server) injDownload(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	name := r.URL.Query().Get("name")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.vulnerable() {
		if !csvName.MatchString(name) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid export name"})
			return
		}
		o, found := s.orders[strings.TrimSuffix(name, ".csv")]
		if !found || o.OwnerID != caller {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "export not found"})
			return
		}
		writeText(w, publicCSV(o))
		return
	}
	p := path.Join("exports", name)
	if rest, found := strings.CutPrefix(p, "internal/records/"); found {
		o, ok := s.orders[strings.TrimSuffix(rest, ".txt")]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "export not found"})
			return
		}
		writeText(w, recordText(o))
		return
	}
	o, found := s.orders[strings.TrimSuffix(strings.TrimPrefix(p, "exports/"), ".csv")]
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "export not found"})
		return
	}
	writeText(w, publicCSV(o))
}

// --- INJ-009: header injection ---------------------------------------------------------

var safeNote = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)

// injNotes stores a note on the owner's order and echoes it in a Set-Cookie header. The
// fixed build allows only plain characters. The vulnerable build writes the value raw, so
// a semicolon adds cookie attributes.
func (s *Server) injNotes(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	s.mu.Lock()
	o, found := s.orders[r.PathValue("id")]
	owned := found && o.OwnerID == caller
	s.mu.Unlock()
	if !owned {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if !s.vulnerable() && !safeNote.MatchString(req.Note) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "note contains characters that are not allowed"})
		return
	}
	w.Header().Set("Set-Cookie", "note="+req.Note)
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

// --- INJ-010: server-side request forgery -----------------------------------------------

// injImport imports an order by ID, or fetches a URL. The vulnerable build fetches any
// URL and resolves a relative one against its own host. The fixed build accepts only IDs.
func (s *Server) injImport(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if strings.HasPrefix(req.Source, "/") || strings.HasPrefix(req.Source, "http") {
		if !s.vulnerable() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "URL sources are not allowed"})
			return
		}
		target := req.Source
		if strings.HasPrefix(target, "/") {
			target = "http://" + r.Host + target
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get(target)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "fetch failed"})
			return
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		writeJSON(w, http.StatusOK, map[string]any{"status": resp.StatusCode, "body": string(raw)})
		return
	}
	s.mu.Lock()
	o, found := s.orders[req.Source]
	var view map[string]any
	owned := found && o.OwnerID == caller
	if owned {
		view = publicView(o)
	}
	s.mu.Unlock()
	if !owned {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": view})
}

// --- INJ-011: prototype pollution and unsafe merge -------------------------------------

// reservedKeys are the names a safe merge refuses.
var reservedKeys = []string{"__proto__", "constructor", "prototype"}

// injAttributes merges caller-supplied attributes into the owner's order. The fixed build
// refuses reserved keys before it changes anything. The vulnerable build merges a
// "__proto__" object into the record itself, so a nested owner_id rewrites ownership.
func (s *Server) injAttributes(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var req map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	hasReserved := false
	for _, k := range reservedKeys {
		if _, has := req[k]; has {
			hasReserved = true
		}
	}
	if hasReserved && !s.vulnerable() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "reserved key"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	if o.Public == nil {
		o.Public = map[string]string{}
	}
	for k, v := range req {
		if slices.Contains(reservedKeys, k) {
			nested, _ := v.(map[string]any)
			for nk, nv := range nested {
				str, isString := nv.(string)
				if !isString {
					continue
				}
				if nk == "owner_id" {
					o.OwnerID = str
				} else {
					o.Public[nk] = str
				}
			}
			continue
		}
		if str, isString := v.(string); isString {
			o.Public[k] = str
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

// --- INJ-012: validation inconsistencies across formats --------------------------------

// injTransition changes an order's status. The JSON body is validated in both builds. The
// vulnerable build skips validation for the form-encoded body, which is the inconsistency.
func (s *Server) injTransition(w http.ResponseWriter, r *http.Request) {
	caller, ok := s.requireCaller(w, r)
	if !ok {
		return
	}
	var status string
	form := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	if form {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form"})
			return
		}
		status = r.PostForm.Get("status")
	} else {
		var req struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
			return
		}
		status = req.Status
	}
	if !(s.vulnerable() && form) && !validStatuses[status] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be one of pending, shipped, cancelled"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, found := s.orders[r.PathValue("id")]
	if !found || o.OwnerID != caller {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "order not found"})
		return
	}
	o.Status = status
	writeJSON(w, http.StatusOK, map[string]string{"status": o.Status})
}

// Flaws returns the planted flaw registry: the core flaws plus the injection flaws.
func Flaws() []Flaw {
	return slices.Concat(flawsCore(), injectionFlaws(), gatewayFlaws(), authzFlaws(), discFlaws(), remainingFlaws(), graphqlFlaws(), soapFlaws())
}

// injectionFlaws names the planted injection flaws. Each is present only in ModeVulnerable.
func injectionFlaws() []Flaw {
	return []Flaw{
		{ID: "LAB-INJ-SQLI-001", ScenarioID: "API-BAS-INJ-001", Description: "GET /api/search/orders splices q into an always-true predicate and returns every order.", Oracle: "protected values of another owner's order appear in the response"},
		{ID: "LAB-INJ-EXPR-001", ScenarioID: "API-BAS-INJ-002", Description: "POST /api/reports/filter evaluates an expression field and returns every order when a disjunct is true.", Oracle: "protected values of another owner's order appear in the response"},
		{ID: "LAB-INJ-SSTI-001", ScenarioID: "API-BAS-INJ-003", Description: "POST /api/notifications/preview parses a caller template against the full record.", Oracle: "protected values of the order appear in the rendered preview"},
		{ID: "LAB-INJ-LDAP-001", ScenarioID: "API-BAS-INJ-004", Description: "GET /api/directory/search builds an unescaped filter, so a wildcard matches every entry.", Oracle: "protected values of another owner's order appear in the response"},
		{ID: "LAB-INJ-JSON-001", ScenarioID: "API-BAS-INJ-006", Description: "POST /api/orders/{id}/settings validates the first duplicate status key and applies the last.", Oracle: "the order status changes to a value the validation refused"},
		{ID: "LAB-INJ-PATH-001", ScenarioID: "API-BAS-INJ-008", Description: "GET /api/files/download joins the name onto the exports directory without checking it.", Oracle: "protected values of an internal record appear in the response"},
		{ID: "LAB-INJ-HDR-001", ScenarioID: "API-BAS-INJ-009", Description: "POST /api/orders/{id}/notes writes the note into Set-Cookie unencoded.", Oracle: "the injected cookie attribute appears in the response headers"},
		{ID: "LAB-INJ-SSRF-001", ScenarioID: "API-BAS-INJ-010", Description: "POST /api/imports/fetch fetches any URL and resolves relative sources against its own host.", Oracle: "protected values of an internal record appear in the fetched body"},
		{ID: "LAB-INJ-PROTO-001", ScenarioID: "API-BAS-INJ-011", Description: "POST /api/orders/{id}/attributes merges a __proto__ object into the record, so a nested owner_id rewrites ownership.", Oracle: "the order owner changes"},
		{ID: "LAB-INJ-VALID-001", ScenarioID: "API-BAS-INJ-012", Description: "POST /api/orders/{id}/transition skips status validation for form-encoded bodies.", Oracle: "the order status changes to a value the JSON path refuses"},
	}
}
