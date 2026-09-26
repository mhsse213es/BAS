package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/audspect/bas/internal/auth"
	"github.com/audspect/bas/internal/reporting"
	"github.com/go-chi/chi/v5"
)

// ReportSchedule is a recurring, emailed report delivery.
type ReportSchedule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	ReportType  string     `json:"reportType"` // board | compliance | audit_pack
	ScopeKind   string     `json:"scopeKind"`  // agent | campaign
	ScopeID     string     `json:"scopeId"`
	Framework   string     `json:"framework"` // compliance only
	Format      string     `json:"format"`    // pdf | html (audit_pack is always zip)
	Recipients  string     `json:"recipients"`
	Frequency   string     `json:"frequency"` // daily | weekly | monthly
	HourUTC     int        `json:"hourUtc"`
	DayOfWeek   int        `json:"dayOfWeek"`  // 0=Sun..6=Sat (weekly)
	DayOfMonth  int        `json:"dayOfMonth"` // 1..28 (monthly)
	Enabled     bool       `json:"enabled"`
	LastRunAt   *time.Time `json:"lastRunAt,omitempty"`
	LastStatus  string     `json:"lastStatus"`
	LastError   string     `json:"lastError,omitempty"`
	CreatedBy   string     `json:"createdBy,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

// ListReportSchedules returns all schedules. GET /api/report/schedules
func (h *Handler) ListReportSchedules(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id,name,report_type,scope_kind,scope_id,framework,format,recipients,
		        frequency,hour_utc,day_of_week,day_of_month,enabled,last_run_at,last_status,last_error,created_by,created_at
		   FROM report_schedules ORDER BY created_at DESC`)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out := []ReportSchedule{}
	for rows.Next() {
		var s ReportSchedule
		if err := rows.Scan(&s.ID, &s.Name, &s.ReportType, &s.ScopeKind, &s.ScopeID, &s.Framework, &s.Format,
			&s.Recipients, &s.Frequency, &s.HourUTC, &s.DayOfWeek, &s.DayOfMonth, &s.Enabled,
			&s.LastRunAt, &s.LastStatus, &s.LastError, &s.CreatedBy, &s.CreatedAt); err != nil {
			continue
		}
		out = append(out, s)
	}
	respond(w, out)
}

// CreateReportSchedule creates a schedule. POST /api/report/schedules
func (h *Handler) CreateReportSchedule(w http.ResponseWriter, r *http.Request) {
	var s ReportSchedule
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if msg := validateSchedule(&s); msg != "" {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	createdBy := ""
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		createdBy = claims.UserID
	}
	var id string
	err := h.db.QueryRow(r.Context(),
		`INSERT INTO report_schedules
		   (name,report_type,scope_kind,scope_id,framework,format,recipients,frequency,hour_utc,day_of_week,day_of_month,enabled,created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
		s.Name, s.ReportType, s.ScopeKind, s.ScopeID, s.Framework, s.Format, s.Recipients,
		s.Frequency, s.HourUTC, s.DayOfWeek, s.DayOfMonth, s.Enabled, createdBy,
	).Scan(&id)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "report.schedule.create", id, map[string]any{"type": s.ReportType, "scope": s.ScopeID}, "ok")
	respond(w, map[string]string{"id": id})
}

// UpdateReportSchedule updates a schedule. PUT /api/report/schedules/{id}
func (h *Handler) UpdateReportSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var s ReportSchedule
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if msg := validateSchedule(&s); msg != "" {
		jsonError(w, msg, http.StatusBadRequest)
		return
	}
	ct, err := h.db.Exec(r.Context(),
		`UPDATE report_schedules SET name=$2,report_type=$3,scope_kind=$4,scope_id=$5,framework=$6,format=$7,
		        recipients=$8,frequency=$9,hour_utc=$10,day_of_week=$11,day_of_month=$12,enabled=$13
		  WHERE id=$1`,
		id, s.Name, s.ReportType, s.ScopeKind, s.ScopeID, s.Framework, s.Format, s.Recipients,
		s.Frequency, s.HourUTC, s.DayOfWeek, s.DayOfMonth, s.Enabled)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ct.RowsAffected() == 0 {
		jsonError(w, "schedule not found", http.StatusNotFound)
		return
	}
	h.auditLog(r, "report.schedule.update", id, nil, "ok")
	respond(w, map[string]bool{"updated": true})
}

// DeleteReportSchedule removes a schedule. DELETE /api/report/schedules/{id}
func (h *Handler) DeleteReportSchedule(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := h.db.Exec(r.Context(), `DELETE FROM report_schedules WHERE id=$1`, id); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.auditLog(r, "report.schedule.delete", id, nil, "ok")
	respond(w, map[string]bool{"deleted": true})
}

// RunReportScheduleNow generates + emails one schedule immediately (for testing
// a configuration). POST /api/report/schedules/{id}/run
func (h *Handler) RunReportScheduleNow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, err := h.loadSchedule(r.Context(), id)
	if err != nil {
		jsonError(w, "schedule not found", http.StatusNotFound)
		return
	}
	if err := h.runSchedule(r.Context(), s); err != nil {
		h.markScheduleRun(r.Context(), id, "error", err.Error())
		jsonError(w, err.Error(), http.StatusBadGateway)
		return
	}
	h.markScheduleRun(r.Context(), id, "ok", "")
	h.auditLog(r, "report.schedule.run", id, nil, "ok")
	respond(w, map[string]bool{"sent": true})
}

// ── Scheduler tick ───────────────────────────────────────────────────────────

// RunReportScheduleTick is invoked periodically by a PollScheduler. It finds
// due, enabled schedules and delivers them. Errors are recorded per-schedule
// and never abort the tick.
func (h *Handler) RunReportScheduleTick(ctx context.Context) {
	now := time.Now().UTC()
	rows, err := h.db.Query(ctx,
		`SELECT id,name,report_type,scope_kind,scope_id,framework,format,recipients,
		        frequency,hour_utc,day_of_week,day_of_month,enabled,last_run_at,last_status,last_error,created_by,created_at
		   FROM report_schedules WHERE enabled = true`)
	if err != nil {
		return
	}
	var due []ReportSchedule
	for rows.Next() {
		var s ReportSchedule
		if err := rows.Scan(&s.ID, &s.Name, &s.ReportType, &s.ScopeKind, &s.ScopeID, &s.Framework, &s.Format,
			&s.Recipients, &s.Frequency, &s.HourUTC, &s.DayOfWeek, &s.DayOfMonth, &s.Enabled,
			&s.LastRunAt, &s.LastStatus, &s.LastError, &s.CreatedBy, &s.CreatedAt); err == nil {
			if scheduleDue(s, now) {
				due = append(due, s)
			}
		}
	}
	rows.Close()

	for _, s := range due {
		if err := h.runSchedule(ctx, s); err != nil {
			h.markScheduleRun(ctx, s.ID, "error", err.Error())
		} else {
			h.markScheduleRun(ctx, s.ID, "ok", "")
		}
	}
}

// scheduleDue reports whether s should fire at now: the right day + on/after the
// scheduled hour, and not already run today.
func scheduleDue(s ReportSchedule, now time.Time) bool {
	if now.Hour() < s.HourUTC {
		return false
	}
	switch s.Frequency {
	case "weekly":
		if int(now.Weekday()) != s.DayOfWeek {
			return false
		}
	case "monthly":
		if now.Day() != s.DayOfMonth {
			return false
		}
	}
	if s.LastRunAt != nil {
		l := s.LastRunAt.UTC()
		if l.Year() == now.Year() && l.YearDay() == now.YearDay() {
			return false // already ran today
		}
	}
	return true
}

func (h *Handler) markScheduleRun(ctx context.Context, id, status, errMsg string) {
	h.db.Exec(ctx,
		`UPDATE report_schedules SET last_run_at=NOW(), last_status=$2, last_error=$3 WHERE id=$1`,
		id, status, errMsg)
}

func (h *Handler) loadSchedule(ctx context.Context, id string) (ReportSchedule, error) {
	var s ReportSchedule
	err := h.db.QueryRow(ctx,
		`SELECT id,name,report_type,scope_kind,scope_id,framework,format,recipients,
		        frequency,hour_utc,day_of_week,day_of_month,enabled,last_run_at,last_status,last_error,created_by,created_at
		   FROM report_schedules WHERE id=$1`, id,
	).Scan(&s.ID, &s.Name, &s.ReportType, &s.ScopeKind, &s.ScopeID, &s.Framework, &s.Format,
		&s.Recipients, &s.Frequency, &s.HourUTC, &s.DayOfWeek, &s.DayOfMonth, &s.Enabled,
		&s.LastRunAt, &s.LastStatus, &s.LastError, &s.CreatedBy, &s.CreatedAt)
	return s, err
}

// runSchedule generates the report and emails it to the recipients.
func (h *Handler) runSchedule(ctx context.Context, s ReportSchedule) error {
	if h.reportSMTP.Host == "" {
		return fmt.Errorf("SMTP not configured — cannot deliver scheduled reports")
	}
	recipients := splitRecipients(s.Recipients)
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients configured")
	}
	filename, contentType, data, err := h.generateScheduledReport(ctx, s)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}
	subject := s.Name
	if subject == "" {
		subject = fmt.Sprintf("Audspect %s report — %s", s.ReportType, s.ScopeID)
	}
	body := fmt.Sprintf("Attached is your scheduled Audspect %s report for %s, generated %s.\n\nThis is an automated message.",
		s.ReportType, s.ScopeID, time.Now().UTC().Format("02 Jan 2006 15:04 UTC"))
	return h.sendReportEmail(recipients, subject, body, filename, contentType, data)
}

// generateScheduledReport builds the report bytes + filename + content type for
// a schedule, reusing the same renderers the interactive endpoints use.
func (h *Handler) generateScheduledReport(ctx context.Context, s ReportSchedule) (filename, contentType string, data []byte, err error) {
	if h.reportingEngine == nil {
		return "", "", nil, fmt.Errorf("reporting engine not loaded")
	}
	genBy := "scheduled:" + s.ID
	scope := s.ScopeID

	switch s.ReportType {
	case "audit_pack":
		var buf bytes.Buffer
		if aerr := h.reportingEngine.WriteAuditPack(ctx, s.ScopeID, h.complianceMapper, genBy, &buf); aerr != nil {
			return "", "", nil, aerr
		}
		return buildReportFilename("Audit_Pack", scope, "zip"), "application/zip", buf.Bytes(), nil

	case "compliance":
		if h.complianceMapper == nil {
			return "", "", nil, fmt.Errorf("compliance mapper not loaded")
		}
		results := h.aggregateAgentResults(ctx, s.ScopeID)
		cr, gerr := h.complianceMapper.GenerateReport(results, s.Framework, s.ScopeID, "", "")
		if gerr != nil {
			return "", "", nil, gerr
		}
		return h.renderToBytes(ctx, "Compliance_Report", scope, s.Format,
			func(out *bytes.Buffer) error { return reporting.RenderComplianceHTML(out, cr, genBy) },
			func(out *bytes.Buffer) error { return reporting.RenderCompliancePDF(ctx, out, cr, genBy) })

	default: // board
		var rep *reporting.FullReport
		var compRows []reporting.ComplianceSummaryRow
		var berr error
		if s.ScopeKind == "campaign" {
			rep, berr = h.reportingEngine.BuildFromCampaign(ctx, s.ScopeID, "")
		} else {
			rep, berr = h.reportingEngine.Build(ctx, s.ScopeID, "")
			compRows = h.complianceRows(ctx, s.ScopeID, "")
		}
		if berr != nil {
			return "", "", nil, berr
		}
		return h.renderToBytes(ctx, "Board_Scorecard", scope, s.Format,
			func(out *bytes.Buffer) error { return reporting.RenderBoardOnePager(out, rep, compRows, genBy) },
			func(out *bytes.Buffer) error { return reporting.RenderBoardOnePagerPDF(ctx, out, rep, compRows, genBy) })
	}
}

// renderToBytes renders HTML or (PDF with HTML fallback) to a byte slice.
func (h *Handler) renderToBytes(ctx context.Context, kind, scope, format string,
	renderHTML func(*bytes.Buffer) error, renderPDF func(*bytes.Buffer) error) (string, string, []byte, error) {
	if format == "pdf" {
		var pbuf bytes.Buffer
		if err := renderPDF(&pbuf); err == nil && pbuf.Len() > 0 {
			return buildReportFilename(kind, scope, "pdf"), "application/pdf", pbuf.Bytes(), nil
		}
		// fall through to HTML when the Chrome sidecar is unavailable
	}
	var hbuf bytes.Buffer
	if err := renderHTML(&hbuf); err != nil {
		return "", "", nil, err
	}
	return buildReportFilename(kind, scope, "html"), "text/html; charset=utf-8", hbuf.Bytes(), nil
}

// ── Email delivery (multipart/mixed with attachment) ─────────────────────────

func (h *Handler) sendReportEmail(to []string, subject, body, attachName, attachType string, attach []byte) error {
	cfg := h.reportSMTP
	port := cfg.Port
	if port == 0 {
		port = 25
	}
	from := cfg.FromAddr
	msg := buildReportMIME(from, cfg.FromName, to, subject, body, attachName, attachType, attach)
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))

	if cfg.Username != "" {
		auth := smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
		return smtp.SendMail(addr, auth, from, to, []byte(msg))
	}
	return smtp.SendMail(addr, nil, from, to, []byte(msg))
}

// buildReportMIME assembles a multipart/mixed message: a plain-text body plus a
// base64-encoded attachment.
func buildReportMIME(from, fromName string, to []string, subject, body, attachName, attachType string, attach []byte) string {
	boundary := "bas_" + randToken()
	fromHdr := from
	if fromName != "" {
		fromHdr = fmt.Sprintf("%s <%s>", fromName, from)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", fromHdr)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=%s\r\n\r\n", boundary)

	// text part
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(body)
	b.WriteString("\r\n\r\n")

	// attachment part
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	fmt.Fprintf(&b, "Content-Type: %s; name=%q\r\n", attachType, attachName)
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=%q\r\n\r\n", attachName)
	enc := base64.StdEncoding.EncodeToString(attach)
	// wrap at 76 chars per RFC 2045
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteString("\r\n")
	}
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.String()
}

func randToken() string {
	var buf [8]byte
	rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// ── helpers ──────────────────────────────────────────────────────────────────

func validateSchedule(s *ReportSchedule) string {
	switch s.ReportType {
	case "board", "compliance", "audit_pack":
	default:
		return "reportType must be board, compliance or audit_pack"
	}
	if s.ReportType == "compliance" && s.Framework == "" {
		return "framework is required for a compliance report"
	}
	if strings.TrimSpace(s.ScopeID) == "" {
		return "scopeId (agentId or campaignId) is required"
	}
	if strings.TrimSpace(s.Recipients) == "" {
		return "at least one recipient is required"
	}
	switch s.Frequency {
	case "daily", "weekly", "monthly":
	default:
		return "frequency must be daily, weekly or monthly"
	}
	if s.HourUTC < 0 || s.HourUTC > 23 {
		return "hourUtc must be 0-23"
	}
	if s.Format == "" {
		s.Format = "pdf"
	}
	if s.ScopeKind == "" {
		s.ScopeKind = "agent"
	}
	return ""
}

func splitRecipients(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
		if p := strings.TrimSpace(part); p != "" && strings.Contains(p, "@") {
			out = append(out, p)
		}
	}
	return out
}
