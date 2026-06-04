//go:build windows

package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// exportDiagnosticBundle creates a support ZIP on the user's Desktop containing
// the agent log files plus a short health summary. Runs in the user-session
// (--status-window / --tray) process so it can write to the user's Desktop.
func exportDiagnosticBundle() (string, error) {
	desktop := filepath.Join(os.Getenv("USERPROFILE"), "Desktop")
	if _, err := os.Stat(desktop); err != nil {
		desktop = os.Getenv("USERPROFILE")
	}
	stamp := time.Now().Format("20060102-150405")
	zipPath := filepath.Join(desktop, "BASAgent-diagnostic-"+stamp+".zip")

	zf, err := os.Create(zipPath)
	if err != nil {
		return "", fmt.Errorf("create zip: %w", err)
	}
	defer zf.Close()
	zw := zip.NewWriter(zf)
	defer zw.Close()

	// Summary
	if sw, err := zw.Create("summary.txt"); err == nil {
		fmt.Fprintf(sw, "Audspect BAS Agent — Diagnostic Bundle\n")
		fmt.Fprintf(sw, "Generated : %s\n", time.Now().Format("2006-01-02 15:04:05"))
		host, _ := os.Hostname()
		fmt.Fprintf(sw, "Hostname  : %s\n", host)
		fmt.Fprintf(sw, "Agent ver : %s\n", version)
	}

	// All agent log files
	dir := logDir()
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			src := filepath.Join(dir, e.Name())
			fw, err := zw.Create("logs/" + e.Name())
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

	return zipPath, nil
}
