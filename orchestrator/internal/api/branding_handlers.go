package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/audspect/bas/internal/reporting"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LoadReportBranding reads the singleton report_branding row (if any) and
// installs it as the active report branding. Called once at startup and after
// every update so reports immediately reflect the configured white-label
// identity. A missing row leaves the Audspect defaults in place.
func LoadReportBranding(ctx context.Context, pool *pgxpool.Pool) {
	var b reporting.Branding
	err := pool.QueryRow(ctx,
		`SELECT product_name, org_name, accent_color, logo_data_uri, footer_note
		   FROM report_branding WHERE id = 1`,
	).Scan(&b.ProductName, &b.OrgName, &b.AccentColor, &b.LogoDataURI, &b.FooterNote)
	if err != nil {
		return // no row / not configured — keep defaults
	}
	reporting.SetBranding(b)
}

// GetReportBranding returns the active report branding. Viewer+.
// GET /api/report/branding
func (h *Handler) GetReportBranding(w http.ResponseWriter, r *http.Request) {
	respond(w, reporting.GetBranding())
}

// UpdateReportBranding upserts the white-label branding and applies it live.
// Admin only. PUT /api/report/branding
func (h *Handler) UpdateReportBranding(w http.ResponseWriter, r *http.Request) {
	var b reporting.Branding
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// Bound the logo payload so a huge data URI can't bloat every report.
	if len(b.LogoDataURI) > 512*1024 {
		jsonError(w, "logoDataUri too large (max 512 KB)", http.StatusBadRequest)
		return
	}
	if _, err := h.db.Exec(r.Context(),
		`INSERT INTO report_branding (id, product_name, org_name, accent_color, logo_data_uri, footer_note, updated_at)
		 VALUES (1,$1,$2,$3,$4,$5,NOW())
		 ON CONFLICT (id) DO UPDATE SET
		   product_name=$1, org_name=$2, accent_color=$3, logo_data_uri=$4, footer_note=$5, updated_at=NOW()`,
		b.ProductName, b.OrgName, b.AccentColor, b.LogoDataURI, b.FooterNote,
	); err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	reporting.SetBranding(b) // apply immediately (SetBranding fills empty fields from defaults)
	h.auditLog(r, "report.branding.update", "", map[string]any{"productName": b.ProductName, "orgName": b.OrgName}, "ok")
	respond(w, reporting.GetBranding())
}
