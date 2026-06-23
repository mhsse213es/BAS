package reporting

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/audspect/bas/internal/compliance"
	"github.com/audspect/bas/internal/models"
)

// WriteAuditPack streams a complete audit-pack ZIP to w.
// The ZIP contains:
//
//	README.txt
//	summary.json
//	executive-report.html
//	runs/<runId>-<scenarioName>.json
//	compliance/NIST_CSF_2.csv  (and other frameworks)
//	agent-inventory.json
func (e *Engine) WriteAuditPack(ctx context.Context, agentID string, mapper *compliance.Mapper, w io.Writer) error {
	report, err := e.Build(ctx, agentID, "")
	if err != nil {
		return fmt.Errorf("build report: %w", err)
	}

	// Latest run results — used for the PDF detailed section and compliance.
	var latestResults []models.SimulationResult
	if len(report.Runs) > 0 {
		var resultsRaw []byte
		e.db.QueryRow(ctx,
			`SELECT results FROM scenario_runs
			  WHERE agent_id = $1 AND status IN ('completed','partial')
			  ORDER BY started_at DESC LIMIT 1`, agentID,
		).Scan(&resultsRaw)
		json.Unmarshal(resultsRaw, &latestResults)
	}

	// ── Build compliance summaries ────────────────────────────────────────
	var compSummaries []ComplianceSummaryRow
	if len(latestResults) > 0 && mapper != nil {
		for _, fw := range mapper.Frameworks() {
			cr, err := mapper.GenerateReport(latestResults, fw.ID, agentID, "", "")
			if err != nil {
				continue
			}
			compSummaries = append(compSummaries, ComplianceSummaryRow{
				Framework:     fw.Name + " " + fw.Version,
				TotalControls: cr.Summary.TotalControls,
				Manual:        cr.Summary.ManualControls,
				Tested:        cr.Summary.TestedControls,
				Passing:       cr.Summary.PassingControls,
				Failing:       cr.Summary.FailingControls,
				Untested:      cr.Summary.UntestedControls,
				CompliancePct: cr.Summary.CompliancePercent,
				CoveragePct:   cr.Summary.CoveragePercent,
			})
		}
	}

	// ── Write ZIP ─────────────────────────────────────────────────────────
	zw := zip.NewWriter(w)
	defer zw.Close()

	dirName := fmt.Sprintf("bas-audit-pack-%s-%s",
		report.Agent.Hostname, time.Now().UTC().Format("2006-01-02"))
	if report.Agent.Hostname == "" {
		dirName = fmt.Sprintf("bas-audit-pack-%s-%s", agentID, time.Now().UTC().Format("2006-01-02"))
	}
	prefix := dirName + "/"

	// README.txt
	if f, err := zw.Create(prefix + "README.txt"); err == nil {
		fmt.Fprintf(f, readmeTmpl,
			report.Agent.Hostname, report.Agent.IPAddress,
			report.Agent.OSVersion, report.Agent.EnvLabel,
			time.Now().UTC().Format("02 Jan 2006, 15:04 UTC"),
		)
	}

	// summary.json
	if f, err := zw.Create(prefix + "summary.json"); err == nil {
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	}

	// executive-report.html
	if f, err := zw.Create(prefix + "executive-report.html"); err == nil {
		GenerateHTML(f, report, compSummaries)
	}

	// executive-report.pdf — print-ready enterprise report
	if f, err := zw.Create(prefix + "executive-report.pdf"); err == nil {
		if err := RenderReportPDF(f, report, latestResults); err != nil {
			fmt.Fprintf(f, "PDF generation failed: %v", err)
		}
	}

	// agent-inventory.json
	if f, err := zw.Create(prefix + "agent-inventory.json"); err == nil {
		inv := map[string]interface{}{
			"agentId":             report.Agent.AgentID,
			"hostname":            report.Agent.Hostname,
			"ipAddress":           report.Agent.IPAddress,
			"osVersion":           report.Agent.OSVersion,
			"username":            report.Agent.Username,
			"envLabel":            report.Agent.EnvLabel,
			"binaryTrusted":       report.Agent.BinaryTrusted,
			"lastUpdate":          report.Agent.LastUpdate,
			"securityTools":       report.SecurityTools,
			"detectionCategories": report.DetectionCategories,
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(inv)
	}

	// runs/<runId>.json — last 10 runs with full results
	rows, err := e.db.Query(ctx,
		`SELECT id, name, status, results, score, started_at, completed_at
		 FROM scenario_runs
		 WHERE agent_id = $1 AND status IN ('completed','partial')
		 ORDER BY started_at DESC LIMIT 10`, agentID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var runID, runName, status string
			var resultsRaw, scoreRaw []byte
			var startedAt time.Time
			var completedAt *time.Time
			rows.Scan(&runID, &runName, &status, &resultsRaw, &scoreRaw, &startedAt, &completedAt)

			fname := prefix + "runs/" + sanitize(runName) + "-" + runID[:8] + ".json"
			if f, err := zw.Create(fname); err == nil {
				var results []models.SimulationResult
				var score models.Score
				json.Unmarshal(resultsRaw, &results)
				json.Unmarshal(scoreRaw, &score)
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				enc.Encode(map[string]interface{}{
					"id": runID, "scenarioName": runName, "status": status,
					"startedAt": startedAt, "completedAt": completedAt,
					"score": score, "results": results,
				})
			}
		}
	}

	// compliance/<framework>.csv
	if mapper != nil && len(latestResults) > 0 {
		for _, fw := range mapper.Frameworks() {
			cr, err := mapper.GenerateReport(latestResults, fw.ID, agentID, "", "")
			if err != nil {
				continue
			}
			fname := prefix + "compliance/" + fw.ID + ".csv"
			if f, err := zw.Create(fname); err == nil {
				compliance.WriteCSV(f, cr)
			}
		}
	} else if mapper != nil {
		// Write empty headers so the folder exists
		for _, fw := range mapper.Frameworks() {
			fname := prefix + "compliance/" + fw.ID + ".csv"
			if f, err := zw.Create(fname); err == nil {
				emptyReport := &compliance.ComplianceReport{
					Framework: fw,
					AgentID:   agentID,
				}
				compliance.WriteCSV(f, emptyReport)
			}
		}
	}

	// Pack manifest for integrity
	if f, err := zw.Create(prefix + "MANIFEST.txt"); err == nil {
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "Audspect BAS Audit Pack\n")
		fmt.Fprintf(&buf, "Agent:     %s (%s)\n", report.Agent.Hostname, agentID)
		fmt.Fprintf(&buf, "Generated: %s\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintf(&buf, "Runs:      %d\n", len(report.Runs))
		fmt.Fprintf(&buf, "Risk:      %s (%d/100)\n", report.Summary.Classification, report.Summary.RiskScore)
		f.Write(buf.Bytes())
	}

	return nil
}

func sanitize(s string) string {
	var b []byte
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) > 32 {
		b = b[:32]
	}
	return string(b)
}

const readmeTmpl = `Audspect BAS — Audit Pack
=========================

Agent:       %s (%s)
OS:          %s
Environment: %s
Generated:   %s

Contents
--------
  README.txt              This file
  MANIFEST.txt            Pack summary (agent, risk score, run count)
  executive-report.pdf    Print-ready enterprise assessment report (PDF)
  summary.json            Full machine-readable report (JSON)
  executive-report.html   Human-readable HTML report — open in a browser
  runs/                   Raw scenario run data (one JSON file per run)
  compliance/             Per-framework compliance reports (CSV, one file per framework)
  agent-inventory.json    Agent metadata, security tools, and detection categories

Usage
-----
1. Open executive-report.pdf — the audit-ready report to share or archive.
2. executive-report.html is the same report for on-screen viewing in a browser.
3. Import compliance/*.csv into Excel or your GRC platform.
4. Attach summary.json to your ticketing system for automated processing.

Frameworks in compliance/
  NIST_CSF_2.csv        NIST Cybersecurity Framework 2.0
  ISO_27001_2022.csv    ISO/IEC 27001:2022
  RBI_CSF.csv           RBI Cyber Security Framework
  SEBI_CSCRF.csv        SEBI CSCRF
  IRDAI_CSF.csv         IRDAI Cyber Security Guidelines
  CERT_IN.csv           CERT-In Directions 2022

Classification: CONFIDENTIAL — For authorized use only.
`
