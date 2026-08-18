//go:build windows

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// exportBundle creates a diagnostic ZIP at the user's Desktop containing:
// - All agent log files from %ProgramData%\BASAgent\logs
// - %ProgramData%\BASAgent\api.token (redacted)
// - A health summary text file
func exportBundle(data *AllData) (string, error) {
	desktop := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	_ = os.MkdirAll(desktop, 0755)
	stamp := time.Now().Format("20060102-150405")
	zipPath := filepath.Join(desktop, "BASAgent-diagnostic-"+stamp+".zip")

	zf, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("create zip: %w", err)
	}
	defer zf.Close()
	w := zip.NewWriter(zf)
	defer w.Close()

	// Add log files
	logDir := filepath.Join(os.Getenv("ProgramData"), "BASAgent", "logs")
	addDir(w, logDir, "logs")

	// Redacted token file
	tw, _ := w.Create("api.token.txt")
	fmt.Fprintln(tw, "[token redacted for security]")

	// Health summary
	sw, _ := w.Create("health-summary.txt")
	writeHealthSummary(sw, data)

	return zipPath, nil
}

func addDir(w *zip.Writer, dir, prefix string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		src := filepath.Join(dir, e.Name())
		dst := prefix + "/" + e.Name()
		fw, err := w.Create(dst)
		if err != nil {
			continue
		}
		f, err := os.Open(src)
		if err != nil {
			continue
		}
		io.Copy(fw, f)
		f.Close()
	}
}

func writeHealthSummary(w io.Writer, data *AllData) {
	fmt.Fprintf(w, "Audspect BAS Agent - Diagnostic Bundle\n")
	fmt.Fprintf(w, "Generated: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	if data == nil || data.Err != nil {
		fmt.Fprintln(w, "STATUS: Agent service not reachable")
		if data != nil {
			fmt.Fprintf(w, "Error: %v\n", data.Err)
		}
		return
	}

	if s := data.Status; s != nil {
		fmt.Fprintf(w, "AGENT\n")
		fmt.Fprintf(w, "  Version  : %s\n", s.AgentVersion)
		fmt.Fprintf(w, "  Agent ID : %s\n", s.AgentID)
		fmt.Fprintf(w, "  Hostname : %s\n", s.Hostname)
		fmt.Fprintf(w, "  State    : %s\n", s.State)
		fmt.Fprintf(w, "  Status   : %s\n", s.Status)
		fmt.Fprintf(w, "  Server   : %s\n", s.ServerURL)
		fmt.Fprintf(w, "  Connected: %v\n", s.ServerConnected)
		fmt.Fprintf(w, "  Uptime   : %s\n\n", fmtUptime(s.UptimeSec))
	}

	if c := data.Controls; c != nil {
		fmt.Fprintf(w, "SECURITY CONTROLS\n")
		fmt.Fprintf(w, "  Defender RTP    : %v\n", c.Defender.RTPEnabled)
		fmt.Fprintf(w, "  Defender Tamper : %v\n", c.Defender.TamperProtected)
		fmt.Fprintf(w, "  Sysmon          : %v (%s)\n", c.Sysmon.Present, c.Sysmon.ServiceName)
		fmt.Fprintf(w, "  Firewall        : %v\n", c.Firewall.Enabled)
		fmt.Fprintf(w, "  AppLocker       : %v\n", c.AppLocker.Enabled)
		fmt.Fprintf(w, "  WDAC            : %v\n", c.WDAC.Enabled)
		fmt.Fprintf(w, "  AMSI            : %v\n\n", c.AMSI.Enabled)
	}

	if e := data.Evidence; e != nil {
		fmt.Fprintf(w, "EVIDENCE (LAST RUN)\n")
		fmt.Fprintf(w, "  Events Collected  : %d\n", e.EventsCollected)
		fmt.Fprintf(w, "  Defender Alerts   : %d\n", e.DefenderAlerts)
		fmt.Fprintf(w, "  Sysmon Detections : %d\n", e.SysmonDetections)
		fmt.Fprintf(w, "  Upload Queue      : %d\n\n", e.QueueSize)
	}

	if a := data.Activity; a != nil && len(a.RecentActivity) > 0 {
		fmt.Fprintf(w, "RECENT ACTIVITY\n")
		for _, item := range a.RecentActivity {
			if strings.TrimSpace(item.Event) != "" {
				fmt.Fprintf(w, "  %s  %s\n", item.Time.Format("15:04:05"), item.Event)
			}
		}
	}
}
