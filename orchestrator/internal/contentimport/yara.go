package contentimport

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/audspect/bas/internal/scenario"
)

// YaraRule is one rule from a YARA source.
type YaraRule struct {
	Name       string
	Meta       map[string]string
	strs       []yaraString
	cond       string
	node       condNode
	header     []byte   // required leading bytes (an MZ or ELF magic test in the condition)
	condNotes  []string // parts of the condition that are not reproduced
	strNotes   []string
	techniques []string
}

type yaraString struct {
	id    string
	data  []byte
	why   string // set when the string cannot be reproduced
	fixed bool
}

var (
	yaraRuleStart = regexp.MustCompile(`(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::[^{]*)?\{`)
	yaraStrLine   = regexp.MustCompile(`^\s*(\$[A-Za-z0-9_]*)\s*=\s*(.+?)\s*$`)
	yaraMetaLine  = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$`)
	yaraHeaderMZ  = regexp.MustCompile(`(?i)uint16\s*\(\s*0\s*\)\s*==\s*0x5a4d`)
	yaraHeaderELF = regexp.MustCompile(`(?i)uint32\s*\(\s*0\s*\)\s*==\s*0x464c457f`)
	yaraFilesize  = regexp.MustCompile(`(?i)filesize\s*(<=|>=|<|>|==)\s*\d+\s*(?:KB|MB)?`)
	yaraCount     = regexp.MustCompile(`#[A-Za-z0-9_]+\s*(?:<=|>=|<|>|==)\s*\d+`)
)

// ParseYARA reads every rule in a YARA source.
func ParseYARA(src string) ([]*YaraRule, error) {
	src = stripYaraComments(src)
	locs := yaraRuleStart.FindAllStringSubmatchIndex(src, -1)
	if len(locs) == 0 {
		return nil, fmt.Errorf("no YARA rule found")
	}
	var out []*YaraRule
	for i, loc := range locs {
		end := len(src)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		body := src[loc[1]:end]
		if cut := strings.LastIndex(body, "}"); cut >= 0 {
			body = body[:cut]
		}
		r, err := parseYaraBody(src[loc[2]:loc[3]], body)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", src[loc[2]:loc[3]], err)
		}
		out = append(out, r)
	}
	return out, nil
}

func stripYaraComments(s string) string {
	s = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(s, " ")
	var lines []string
	for _, ln := range strings.Split(s, "\n") {
		if i := strings.Index(ln, "//"); i >= 0 && !strings.Contains(ln[:i], `"`) {
			ln = ln[:i]
		}
		lines = append(lines, ln)
	}
	return strings.Join(lines, "\n")
}

func parseYaraBody(name, body string) (*YaraRule, error) {
	r := &YaraRule{Name: name, Meta: map[string]string{}}
	body = normalizeYaraBody(body)
	section := ""
	var cond []string
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		switch t {
		case "meta:", "strings:", "condition:":
			section = strings.TrimSuffix(t, ":")
			continue
		}
		if t == "" {
			continue
		}
		switch section {
		case "meta":
			if m := yaraMetaLine.FindStringSubmatch(ln); m != nil {
				r.Meta[m[1]] = strings.Trim(m[2], `"`)
			}
		case "strings":
			if m := yaraStrLine.FindStringSubmatch(ln); m != nil {
				r.strs = append(r.strs, decodeYaraString(m[1], m[2]))
			}
		case "condition":
			cond = append(cond, t)
		}
	}
	r.cond = strings.Join(cond, " ")
	if r.cond == "" {
		return nil, fmt.Errorf("no condition")
	}
	for _, k := range []string{"mitre_attack", "attack", "technique", "mitre_att&ck"} {
		if v := r.Meta[k]; v != "" {
			for _, m := range regexp.MustCompile(`(?i)T\d{4}(?:\.\d{3})?`).FindAllString(v, -1) {
				r.techniques = append(r.techniques, strings.ToUpper(m))
			}
		}
	}
	return r, nil
}

var yaraMods = regexp.MustCompile(`\b(nocase|wide|ascii|fullword|xor|base64wide|base64|private)\b`)

func decodeYaraString(id, rhs string) yaraString {
	s := yaraString{id: id}
	switch {
	case strings.HasPrefix(rhs, `"`):
		end := strings.LastIndex(rhs, `"`)
		if end <= 0 {
			s.why = "unterminated text string"
			return s
		}
		raw := rhs[1:end]
		mods := yaraMods.FindAllString(rhs[end+1:], -1)
		b, err := unescapeYara(raw)
		if err != nil {
			s.why = err.Error()
			return s
		}
		wide, ascii := false, true
		for _, m := range mods {
			switch m {
			case "wide":
				wide = true
				ascii = false
			case "ascii":
				ascii = true
			case "xor", "base64", "base64wide":
				s.why = "the " + m + " modifier cannot be reproduced"
				return s
			}
		}
		if wide && ascii {
			wide = false // both forms listed: the ascii form is enough
		}
		if wide {
			u := utf16.Encode([]rune(string(b)))
			b = b[:0:0]
			for _, c := range u {
				b = append(b, byte(c), byte(c>>8))
			}
		}
		s.data = b
	case strings.HasPrefix(rhs, "{"):
		end := strings.LastIndex(rhs, "}")
		if end < 0 {
			s.why = "unterminated hex string"
			return s
		}
		b, why := decodeYaraHex(rhs[1:end])
		s.data, s.why = b, why
	case strings.HasPrefix(rhs, "/"):
		s.why = "regular-expression strings cannot be reproduced"
	default:
		s.why = "unrecognised string syntax"
	}
	if s.why == "" && len(s.data) == 0 {
		s.why = "empty string"
	}
	return s
}

func unescapeYara(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			return nil, fmt.Errorf("dangling escape")
		}
		switch s[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '\\', '"':
			out = append(out, s[i])
		case 'x':
			if i+2 >= len(s) {
				return nil, fmt.Errorf("bad \\x escape")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, fmt.Errorf("bad \\x escape")
			}
			out = append(out, byte(v))
			i += 2
		default:
			return nil, fmt.Errorf("unsupported escape \\%c", s[i])
		}
	}
	return out, nil
}

var hexTok = regexp.MustCompile(`^[0-9A-Fa-f]{2}$`)

func decodeYaraHex(s string) ([]byte, string) {
	if strings.ContainsAny(s, "|~") || strings.Contains(s, "(") {
		return nil, "hex alternatives and negation cannot be reproduced"
	}
	var out []byte
	for _, tok := range strings.Fields(strings.ReplaceAll(strings.ReplaceAll(s, "[", " [ "), "]", " ] ")) {
		switch {
		case hexTok.MatchString(tok):
			v, _ := strconv.ParseUint(tok, 16, 8)
			out = append(out, byte(v))
		case tok == "??" || strings.Contains(tok, "?"):
			out = append(out, 0)
		case tok == "[" || tok == "]":
		default:
			if n, err := strconv.Atoi(strings.Split(tok, "-")[0]); err == nil && n >= 0 && n <= 64 {
				out = append(out, make([]byte, n)...)
			} else {
				return nil, "hex jump " + tok + " cannot be reproduced"
			}
		}
	}
	return out, ""
}

// YaraResult is the outcome for one rule.
type YaraResult struct {
	Rule     *YaraRule
	Step     *scenario.Step
	OS       string
	Content  []byte // what the generated file holds
	Coverage Coverage
}

const maxYaraContent = 4096

// GenerateYARA builds a draft for the rule: a step that writes a small inert file holding what the rule matches, then
// checks whether the security software on the host removed it. os is "windows" or "linux"; techOverride supplies the
// ATT&CK id when the rule's meta has none.
func GenerateYARA(r *YaraRule, osName, techOverride string) (*YaraResult, error) {
	res := &YaraResult{Rule: r, OS: osName}
	if osName != "windows" && osName != "linux" {
		return nil, fmt.Errorf("os must be windows or linux")
	}
	tech := strings.ToUpper(strings.TrimSpace(techOverride))
	if tech == "" && len(r.techniques) > 0 {
		tech = r.techniques[0]
	}
	if tech == "" {
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, "the rule has no mitre_attack/attack meta entry; supply the ATT&CK technique id")
		return res, nil
	}

	cond := r.cond
	var header []byte
	if yaraHeaderMZ.MatchString(cond) {
		header = []byte("MZ")
		cond = yaraHeaderMZ.ReplaceAllString(cond, "true")
	}
	if yaraHeaderELF.MatchString(cond) {
		header = []byte{0x7f, 'E', 'L', 'F'}
		cond = yaraHeaderELF.ReplaceAllString(cond, "true")
	}
	if yaraFilesize.MatchString(cond) {
		for _, m := range yaraFilesize.FindAllString(cond, -1) {
			if strings.Contains(m, ">") || strings.Contains(m, "==") {
				res.Coverage.Notes = append(res.Coverage.Notes, "size test not reproduced: "+m+" (the file is a few hundred bytes)")
			}
		}
		cond = yaraFilesize.ReplaceAllString(cond, "true")
	}
	if yaraCount.MatchString(cond) {
		res.Coverage.Notes = append(res.Coverage.Notes, "occurrence-count tests are treated as satisfied by one occurrence")
		cond = yaraCount.ReplaceAllString(cond, "true")
	}

	usable := map[string]yaraString{}
	var names []string
	for _, s := range r.strs {
		if s.why != "" {
			res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, fmt.Sprintf("%s: %s", s.id, s.why))
			continue
		}
		usable[s.id] = s
		names = append(names, s.id)
	}
	if len(names) == 0 {
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, "the rule has no string that can be reproduced")
		return res, nil
	}

	chosen := chooseYaraStrings(cond, names, &res.Coverage)
	var content []byte
	content = append(content, header...)
	for _, id := range chosen {
		content = append(content, usable[id].data...)
		content = append(content, '\n')
	}
	if len(content) > maxYaraContent {
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, fmt.Sprintf("the strings need %d bytes; at most %d are written", len(content), maxYaraContent))
		return res, nil
	}
	res.Coverage.Emulable = true
	res.Coverage.Emulated = chosen
	res.Content = content

	marker := Marker("yara", r.Name, string(content))
	st := &scenario.Step{
		Name: truncate("YARA: "+r.Name, 120), TechniqueID: tech, Framework: "custom", TestIndex: 0, TimeoutSec: 60,
		Marker: marker, Risk: "low", Reversible: true, ProductionSafe: true,
		BlastRadius: "writes a small inert file under the temp folder that contains the rule's match strings; nothing is executed, and the file is deleted afterwards",
		Detection:   []string{"YARA rule: " + r.Name + " (file scan by the host's security software)"},
		Telemetry:   []string{"file-scan / quarantine event from the endpoint security product"},
	}
	b64 := base64.StdEncoding.EncodeToString(content)
	dir := "audspect-" + marker
	if osName == "windows" {
		st.Executor = "powershell"
		st.Command = "$ErrorActionPreference='Stop'; $d = Join-Path $env:TEMP '" + dir + "'; New-Item -ItemType Directory -Force $d | Out-Null; " +
			"$f = Join-Path $d '" + dir + ".bin'; [IO.File]::WriteAllBytes($f,[Convert]::FromBase64String('" + b64 + "')); " +
			"Start-Sleep -Seconds 5; if (-not (Test-Path $f)) { Write-Output 'AUDSPECT: the file was removed by a security control'; exit 1 }; Write-Output '" + marker + "'"
		st.Cleanup = "Remove-Item -Recurse -Force (Join-Path $env:TEMP '" + dir + "') -ErrorAction SilentlyContinue"
	} else {
		st.Executor = "bash"
		st.Command = "d=/tmp/" + dir + "; mkdir -p \"$d\" && printf %s '" + b64 + "' | base64 -d > \"$d/" + dir + ".bin\" && sleep 5 && " +
			"{ [ -f \"$d/" + dir + ".bin\" ] || { echo 'AUDSPECT: the file was removed by a security control'; exit 1; }; } && echo '" + marker + "'"
		st.Cleanup = "rm -rf /tmp/" + dir
	}
	res.Step = st
	return res, nil
}

// chooseYaraStrings picks the smallest set of strings that satisfies the condition, or all of them with a note when
// the condition cannot be solved.
func chooseYaraStrings(cond string, names []string, cov *Coverage) []string {
	node, err := parseCondition(cond)
	if err == nil && len(names) <= 14 {
		if sets, err := satisfyingSets(node, append([]string(nil), names...)); err == nil {
			for _, s := range sets {
				if len(s) > 0 {
					return s
				}
			}
			if len(sets) > 0 { // satisfied by no string at all (headers only): carry the first string anyway
				return names[:1]
			}
		}
	}
	// shortcuts that do not need enumeration
	switch strings.ToLower(strings.TrimSpace(cond)) {
	case "any of them":
		return names[:1]
	case "all of them":
		return names
	}
	if m := regexp.MustCompile(`^(\d+) of them$`).FindStringSubmatch(strings.TrimSpace(cond)); m != nil {
		n, _ := strconv.Atoi(m[1])
		if n > len(names) {
			n = len(names)
		}
		return names[:n]
	}
	cov.Notes = append(cov.Notes, "the condition could not be solved exactly, so every reproducible string is included")
	return names
}

// normalizeYaraBody puts every section keyword and every string definition on its own line, ignoring anything inside
// quotes, hex braces or regular expressions, so compact one-line rules parse like multi-line ones.
func normalizeYaraBody(body string) string {
	var out strings.Builder
	inQuote, inHex, inRegex := false, false, false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case inQuote:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(body) {
				i++
				out.WriteByte(body[i])
			} else if c == '"' {
				inQuote = false
			}
			continue
		case inHex:
			out.WriteByte(c)
			if c == '}' {
				inHex = false
			}
			continue
		case inRegex:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(body) {
				i++
				out.WriteByte(body[i])
			} else if c == '/' {
				inRegex = false
			}
			continue
		}
		switch c {
		case '"':
			inQuote = true
		case '{':
			inHex = true
		case '/':
			// a regex string starts right after "= " in the strings section
			if rest := strings.TrimRight(out.String(), " \t"); strings.HasSuffix(rest, "=") {
				inRegex = true
			}
		case '$':
			if m := yaraDefStart.FindString(body[i:]); m != "" {
				out.WriteByte('\n')
			}
		}
		if c == '\n' {
			out.WriteByte(c)
			continue
		}
		for _, kw := range []string{"meta:", "strings:", "condition:"} {
			if strings.HasPrefix(body[i:], kw) && (i == 0 || !isIdent(body[i-1])) {
				out.WriteString("\n" + kw + "\n")
				i += len(kw) - 1
				c = 0
				break
			}
		}
		if c != 0 {
			out.WriteByte(c)
		}
	}
	return out.String()
}

var yaraDefStart = regexp.MustCompile(`^\$[A-Za-z0-9_]*\s*=`)

func isIdent(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
