// Command aclgen expands scenarios-src/acl-privilege-exposure-audit (header.yaml,
// lib.ps1, stages.json) into scenarios/acl-privilege-exposure-audit.yaml.
// The output must be re-signed after every change (scripts/signer.go sign).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Stage is one entry in stages.json.
type Stage struct {
	ID          string   `json:"id"`
	N           int      `json:"n"`
	Name        string   `json:"name"`
	TechniqueID string   `json:"technique_id"`
	AttackNote  string   `json:"attack_note"`
	TimeoutSec  int      `json:"timeout_sec"`
	Blast       string   `json:"blast_radius"`
	Telemetry   []string `json:"telemetry"`
	Detection   []string `json:"detection"`
	Call        string   `json:"call"`
	NoLib       bool     `json:"no_lib"`
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

var fnStart = regexp.MustCompile(`^function\s+([A-Za-z][\w-]*)`)

type chunk struct {
	name string
	text string
}

// splitLib separates top-level function definitions from always-included
// statements. Function bodies end when brace depth returns to zero.
func splitLib(lib string) (prelude string, fns []chunk) {
	var pre strings.Builder
	lines := strings.Split(strings.ReplaceAll(lib, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		m := fnStart.FindStringSubmatch(lines[i])
		if m == nil {
			pre.WriteString(lines[i] + "\n")
			continue
		}
		var body strings.Builder
		depth, opened := 0, false
		for ; i < len(lines); i++ {
			body.WriteString(lines[i] + "\n")
			depth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
			if strings.Contains(lines[i], "{") {
				opened = true
			}
			if opened && depth == 0 {
				break
			}
		}
		fns = append(fns, chunk{m[1], body.String()})
	}
	return pre.String(), fns
}

// minify drops comment-only lines, blank lines and indentation. PowerShell
// indentation is not significant and the library has no here-strings.
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

// shake returns the prelude plus only the functions the call reaches.
func shake(lib, call string) string {
	pre, fns := splitLib(lib)
	need := map[string]bool{}
	var visit func(text string)
	visit = func(text string) {
		lt := strings.ToLower(text)
		for _, f := range fns {
			if need[f.name] {
				continue
			}
			ln := strings.ToLower(f.name)
			hit := false
			if strings.HasPrefix(ln, "scope-") {
				// scope functions are reached by name string, e.g. Scope='tier0-objects'
				hit = strings.Contains(lt, "'"+strings.TrimPrefix(ln, "scope-")+"'")
			} else {
				hit = strings.Contains(lt, ln)
			}
			if hit {
				need[f.name] = true
				visit(f.text)
			}
		}
	}
	visit(call)
	var b strings.Builder
	b.WriteString(pre)
	for _, f := range fns {
		if need[f.name] {
			b.WriteString(f.text)
		}
	}
	return minify(b.String())
}

// Generate returns the complete scenario YAML for the sources in srcDir.
func Generate(srcDir string) ([]byte, error) {
	hdr, err := os.ReadFile(filepath.Join(srcDir, "header.yaml"))
	if err != nil {
		return nil, err
	}
	lib, err := os.ReadFile(filepath.Join(srcDir, "lib.ps1"))
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

	var out bytes.Buffer
	out.WriteString(strings.TrimRight(strings.ReplaceAll(string(hdr), "\r\n", "\n"), "\n") + "\n\n")
	for _, s := range stages {
		if s.ID == "" || s.Name == "" || s.Call == "" {
			return nil, fmt.Errorf("stage %d: id, name and call are required", s.N)
		}
		to := s.TimeoutSec
		if to == 0 {
			to = 60
		}
		fmt.Fprintf(&out, "  # %s\n", strings.Repeat("-", 73))
		fmt.Fprintf(&out, "  - name: %s\n", q(s.Name))
		fmt.Fprintf(&out, "    technique_id: %s\n", s.TechniqueID)
		out.WriteString("    framework: custom\n    executor: powershell\n    requires_priv: user\n")
		fmt.Fprintf(&out, "    timeout_sec: %d\n", to)
		out.WriteString("    fidelity: telemetry-safe\n    production_safe: true\n    risk: low\n    reversible: true\n")
		fmt.Fprintf(&out, "    blast_radius: %s\n", q(s.Blast))
		if s.AttackNote != "" {
			fmt.Fprintf(&out, "    # ATT&CK note: %s\n", strings.ReplaceAll(s.AttackNote, "\n", " "))
		}
		out.WriteString("    telemetry:" + strings.ReplaceAll(list(s.Telemetry), "      - ", "      - "))
		out.WriteString("    detection:" + list(s.Detection))
		out.WriteString("    command: |\n")
		body := s.Call
		if !s.NoLib {
			body = shake(string(lib), s.Call) + "\n" + s.Call
		}
		out.WriteString(indent(body, 6))
		out.WriteString("    cleanup: \"\"\n\n")
	}
	return bytes.TrimRight(out.Bytes(), "\n"), nil
}

func main() {
	src := flag.String("src", "scenarios-src/acl-privilege-exposure-audit", "source directory")
	dst := flag.String("out", "scenarios/acl-privilege-exposure-audit.yaml", "output YAML")
	check := flag.Bool("check", false, "fail if the output file differs from generated content")
	flag.Parse()
	b, err := Generate(*src)
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
