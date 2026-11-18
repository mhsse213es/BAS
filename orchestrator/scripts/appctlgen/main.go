// Command appctlgen expands an Application Control Mastery source directory
// (scenarios-src/appcontrol-<category>: header.yaml, stages.json, and one
// <id>.ps1 per stage) plus the shared oracle scenarios-src/appcontrol-common/lib.ps1
// into scenarios/appcontrol-<category>.yaml. Re-sign the output after every change.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Stage is one entry in stages.json.
type Stage struct {
	ID                string   `json:"id"`
	N                 int      `json:"n"`
	Name              string   `json:"name"`
	TechniqueID       string   `json:"technique_id"`
	TimeoutSec        int      `json:"timeout_sec"`
	RequiresPriv      string   `json:"requires_priv"`
	Fidelity          string   `json:"fidelity"`
	ProductionSafe    *bool    `json:"production_safe"`
	Risk              string   `json:"risk"`
	Blast             string   `json:"blast_radius"`
	Telemetry         []string `json:"telemetry"`
	Detection         []string `json:"detection"`
	Cleanup           string   `json:"cleanup"`
	CleanupExtra      string   `json:"cleanup_extra"`
	ActionKey         string   `json:"action_key"`
	DetectionProfiles []string `json:"detection_profiles"`
	Note              string   `json:"note"`
	// NoDefaultCleanup marks a step that performs and verifies its own undo in-script. The generic
	// Windows sweep (defaultCleanup) is then not attached, so the contract does not count it as an undo.
	NoDefaultCleanup bool `json:"no_default_cleanup"`
	// Reversible, when set false, is emitted as reversible: false; nil keeps the historical default (true).
	Reversible *bool `json:"reversible"`
	// Irreversible is the author's reason an effect cannot be undone; emitted when set.
	Irreversible string `json:"irreversible"`
}

func q(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	return strings.TrimSuffix(b.String(), "\n")
}

func list(items []string) string {
	if len(items) == 0 {
		return " []\n"
	}
	var sb strings.Builder
	sb.WriteString("\n")
	for _, it := range items {
		sb.WriteString("      - " + q(it) + "\n")
	}
	return sb.String()
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	lines := strings.Split(strings.TrimRight(s, "\r\n"), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "" {
			lines[i] = pad + strings.TrimRight(l, "\r")
		} else {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// minify drops comment-only lines, blank lines and indentation. The sources
// contain no here-strings, so indentation is not significant.
func minify(s string) string {
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, "\n")
}

// Generate returns the complete scenario YAML for the sources in srcDir.
func Generate(srcDir, commonDir string) ([]byte, error) {
	hdr, err := os.ReadFile(filepath.Join(srcDir, "header.yaml"))
	if err != nil {
		return nil, err
	}
	lib, err := os.ReadFile(filepath.Join(commonDir, "lib.ps1"))
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(srcDir, "stages.json"))
	if err != nil {
		return nil, err
	}
	var stages []Stage
	if err := json.Unmarshal(raw, &stages); err != nil {
		return nil, fmt.Errorf("stages.json: %w", err)
	}
	sort.SliceStable(stages, func(i, j int) bool { return stages[i].N < stages[j].N })
	libText := minify(string(lib))

	var out bytes.Buffer
	out.WriteString(strings.TrimRight(strings.ReplaceAll(string(hdr), "\r\n", "\n"), "\n") + "\n\n")
	for _, s := range stages {
		if s.ID == "" || s.Name == "" || s.TechniqueID == "" {
			return nil, fmt.Errorf("stage %d: id, name and technique_id are required", s.N)
		}
		call, err := os.ReadFile(filepath.Join(srcDir, s.ID+".ps1"))
		if err != nil {
			return nil, fmt.Errorf("stage %s: %w", s.ID, err)
		}
		// Check for an undo script. If present, it will be wired into cleanup instead of defaultCleanup.
		undo, undoErr := os.ReadFile(filepath.Join(srcDir, s.ID+".undo.ps1"))
		hasUndo := undoErr == nil
		to := s.TimeoutSec
		if to == 0 {
			to = 120
		}
		priv := s.RequiresPriv
		if priv == "" {
			priv = "user"
		}
		fid := s.Fidelity
		if fid == "" {
			fid = "telemetry-safe"
		}
		risk := s.Risk
		if risk == "" {
			risk = "medium"
		}
		safe := false
		if s.ProductionSafe != nil {
			safe = *s.ProductionSafe
		}
		fmt.Fprintf(&out, "  # %s\n", strings.Repeat("-", 73))
		fmt.Fprintf(&out, "  - id: %s\n", s.ID)
		fmt.Fprintf(&out, "    name: %s\n", q(s.Name))
		fmt.Fprintf(&out, "    technique_id: %s\n", s.TechniqueID)
		if len(s.DetectionProfiles) > 0 {
			out.WriteString("    detection_profiles:" + list(s.DetectionProfiles))
		}
		if s.ActionKey != "" {
			fmt.Fprintf(&out, "    action_key: %s\n", s.ActionKey)
		}
		out.WriteString("    framework: custom\n    executor: powershell\n")
		fmt.Fprintf(&out, "    requires_priv: %s\n    timeout_sec: %d\n    fidelity: %s\n    production_safe: %t\n    risk: %s\n    reversible: %s\n", priv, to, fid, safe, risk, reversibleText(s.Reversible))
		if s.Irreversible != "" {
			fmt.Fprintf(&out, "    irreversible: %s\n", q(s.Irreversible))
		}
		fmt.Fprintf(&out, "    blast_radius: %s\n", q(s.Blast))
		if s.Note != "" {
			fmt.Fprintf(&out, "    # %s\n", strings.ReplaceAll(s.Note, "\n", " "))
		}
		out.WriteString("    telemetry:" + list(s.Telemetry))
		out.WriteString("    detection:" + list(s.Detection))
		out.WriteString("    command: |\n")
		out.WriteString(indent(libText+"\n"+minify(string(call)), 6))
		if hasUndo {
			// If an undo script exists, emit it as the cleanup (with lib helpers prepended).
			// NoDefaultCleanup semantics: no defaultCleanup sweep is attached.
			out.WriteString("    cleanup: |\n")
			out.WriteString(indent(libText+"\n"+minify(string(undo)), 6))
		} else if s.Cleanup == "" && s.NoDefaultCleanup && s.CleanupExtra == "" {
			out.WriteString("    cleanup: \"\"\n")
		} else if s.Cleanup == "" {
			out.WriteString("    cleanup: |\n")
			if s.NoDefaultCleanup {
				out.WriteString(indent(s.CleanupExtra, 6))
			} else {
				out.WriteString(indent(defaultCleanup+s.CleanupExtra, 6))
			}
		} else {
			out.WriteString("    cleanup: |\n")
			out.WriteString(indent(s.Cleanup, 6))
		}
		out.WriteString("\n")
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

// reversibleText renders a stage's reversible flag; nil means the historical default of true.
func reversibleText(r *bool) string {
	if r != nil && !*r {
		return "false"
	}
	return "true"
}

// defaultCleanup is the sweep that runs even when a step is killed before its own cleanup. It covers
// every location the pack writes to and the temporary signing certificate, all by the BAS-only prefix.
const defaultCleanup = `foreach ($root in @($env:TEMP, $env:APPDATA, (Join-Path $env:USERPROFILE 'Downloads'))) {
  Get-ChildItem -Path $root -Filter 'bas-appctl-*' -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
}
Get-ChildItem -Path $env:TEMP -Filter 'bas_????????.exe*' -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem Cert:\CurrentUser\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like 'CN=BAS-SIM-UNTRUSTED-*' } | Remove-Item -Force -ErrorAction SilentlyContinue`

func main() {
	src := flag.String("src", "", "category source directory, e.g. scenarios-src/appcontrol-proxy-execution")
	common := flag.String("common", "scenarios-src/appcontrol-common", "shared oracle directory")
	dst := flag.String("out", "", "output YAML")
	check := flag.Bool("check", false, "fail if the output file differs from generated content")
	flag.Parse()
	if *src == "" || *dst == "" {
		fmt.Fprintln(os.Stderr, "usage: appctlgen -src DIR -out FILE [-common DIR] [-check]")
		os.Exit(2)
	}
	b, err := Generate(*src, *common)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	b = append(b, '\n')
	if *check {
		cur, _ := os.ReadFile(*dst)
		if !bytes.Equal(bytes.ReplaceAll(cur, []byte("\r\n"), []byte("\n")), b) {
			fmt.Fprintln(os.Stderr, "generated YAML differs from", *dst)
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*dst, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
