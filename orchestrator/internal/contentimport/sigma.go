package contentimport

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/audspect/bas/internal/scenario"
)

// SigmaRule is the part of a Sigma rule the importer uses.
type SigmaRule struct {
	ID, Title, Description, Level string
	Tags                          []string
	Product, Category, Service    string
	Techniques                    []string // ATT&CK ids from the attack.tNNNN tags
	selections                    map[string]sigmaSelection
	condition                     condNode
}

type sigmaSelection struct {
	keywords []string
	fields   []fieldMatch
}

type fieldMatch struct {
	field  string
	mods   []string
	values []string
	all    bool // contains|all: every value must match; otherwise any one
}

func (f fieldMatch) has(m string) bool {
	for _, x := range f.mods {
		if x == m {
			return true
		}
	}
	return false
}

var techTag = regexp.MustCompile(`(?i)^attack\.(t\d{4}(?:\.\d{3})?)$`)

// ParseSigma reads one Sigma rule.
func ParseSigma(src []byte) (*SigmaRule, error) {
	var raw struct {
		ID          string   `yaml:"id"`
		Title       string   `yaml:"title"`
		Description string   `yaml:"description"`
		Level       string   `yaml:"level"`
		Tags        []string `yaml:"tags"`
		Logsource   struct {
			Product  string `yaml:"product"`
			Category string `yaml:"category"`
			Service  string `yaml:"service"`
		} `yaml:"logsource"`
		Detection map[string]any `yaml:"detection"`
	}
	if err := yaml.Unmarshal(src, &raw); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if strings.TrimSpace(raw.Title) == "" {
		return nil, fmt.Errorf("the rule has no title")
	}
	if len(raw.Detection) == 0 {
		return nil, fmt.Errorf("the rule has no detection section")
	}
	r := &SigmaRule{ID: raw.ID, Title: strings.TrimSpace(raw.Title), Description: strings.TrimSpace(raw.Description),
		Level: raw.Level, Tags: raw.Tags, Product: strings.ToLower(raw.Logsource.Product),
		Category: strings.ToLower(raw.Logsource.Category), Service: strings.ToLower(raw.Logsource.Service),
		selections: map[string]sigmaSelection{}}
	for _, t := range raw.Tags {
		if m := techTag.FindStringSubmatch(t); m != nil {
			r.Techniques = append(r.Techniques, strings.ToUpper(m[1]))
		}
	}
	var condText []string
	for name, v := range raw.Detection {
		if name == "condition" {
			switch c := v.(type) {
			case string:
				condText = []string{c}
			case []any:
				for _, x := range c {
					condText = append(condText, fmt.Sprint(x))
				}
			}
			continue
		}
		if name == "timeframe" {
			continue
		}
		sel, err := parseSelection(v)
		if err != nil {
			return nil, fmt.Errorf("selection %q: %w", name, err)
		}
		r.selections[name] = sel
	}
	if len(condText) == 0 {
		return nil, fmt.Errorf("the rule has no condition")
	}
	var node condNode
	for _, ct := range condText { // several conditions are alternatives
		n, err := parseCondition(ct)
		if err != nil {
			return nil, fmt.Errorf("condition %q: %w", ct, err)
		}
		if node == nil {
			node = n
		} else {
			node = condBin{false, node, n}
		}
	}
	r.condition = node
	return r, nil
}

func scalarStrings(v any) ([]string, error) {
	switch x := v.(type) {
	case nil:
		return nil, fmt.Errorf("null values are not supported")
	case []any:
		var out []string
		for _, e := range x {
			if e == nil {
				return nil, fmt.Errorf("null values are not supported")
			}
			out = append(out, fmt.Sprint(e))
		}
		return out, nil
	default:
		return []string{fmt.Sprint(x)}, nil
	}
}

func parseSelection(v any) (sigmaSelection, error) {
	var s sigmaSelection
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			parts := strings.Split(k, "|")
			vals, err := scalarStrings(val)
			if err != nil {
				return s, fmt.Errorf("%s: %w", k, err)
			}
			fm := fieldMatch{field: parts[0], mods: parts[1:], values: vals}
			if fm.has("all") {
				fm.all = true
			}
			s.fields = append(s.fields, fm)
		}
		sortFields(s.fields)
	case []any:
		for _, e := range x {
			switch ev := e.(type) {
			case map[string]any: // a list of maps is alternatives; treat each as its own selection by flattening the first
				return s, fmt.Errorf("a list of field maps is not supported")
			default:
				s.keywords = append(s.keywords, fmt.Sprint(ev))
			}
		}
	default:
		return s, fmt.Errorf("unsupported selection shape")
	}
	return s, nil
}

func sortFields(f []fieldMatch) {
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && f[j].field < f[j-1].field; j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
}

// plan is what the step has to reproduce.
type plan struct {
	frags    []string // must appear in the command line / path
	endFrag  string   // the command line / path must end with this
	carrier  string   // file name the process must run as (Windows)
	reasons  []string // why a selection could not be emulated
	emulated []string
}

func (p *plan) addFrag(f string) {
	for _, e := range p.frags {
		if e == f {
			return
		}
	}
	p.frags = append(p.frags, f)
}

// pickSafe returns the values that can be carried: all of them when every one is needed, else the first that can.
func pickSafe(fm fieldMatch) ([]string, string) {
	if fm.all {
		for _, v := range fm.values {
			if !SafeFragment(v) {
				return nil, fmt.Sprintf("%s has a value that cannot be carried safely", fm.field)
			}
		}
		return fm.values, ""
	}
	for _, v := range fm.values {
		if SafeFragment(v) {
			return []string{v}, ""
		}
	}
	return nil, fmt.Sprintf("none of the %s values can be carried safely (they contain quoting, redirection or other shell characters)", fm.field)
}

func basenameIfExe(v string) string {
	v = strings.ReplaceAll(v, "\\", "/")
	b := path.Base(v)
	if regexp.MustCompile(`^[A-Za-z0-9_.-]{1,60}\.exe$`).MatchString(b) {
		return b
	}
	return ""
}

// planSelection works out whether one selection can be reproduced, and adds what it needs to p.
func planSelection(name string, s sigmaSelection, category, osName string, p *plan) bool {
	ok := true
	fail := func(why string) {
		ok = false
		p.reasons = append(p.reasons, fmt.Sprintf("selection %q: %s", name, why))
	}
	for _, kw := range s.keywords {
		if category != "process_creation" {
			fail("keyword matching is only supported for process_creation rules")
			return false
		}
		if !SafeFragment(kw) {
			fail("a keyword cannot be carried safely")
			continue
		}
		p.addFrag(kw)
	}
	for _, f := range s.fields {
		field := strings.ToLower(f.field)
		switch {
		case category == "process_creation" && field == "commandline":
			switch {
			case f.has("re") || f.has("startswith") || f.has("cidr") || f.has("base64") || f.has("base64offset"):
				fail("CommandLine|" + strings.Join(f.mods, "|") + " cannot be reproduced")
			case f.has("endswith"):
				v, why := pickSafe(f)
				if why != "" {
					fail(why)
				} else if p.endFrag != "" && p.endFrag != v[0] {
					fail("two different CommandLine endswith values are needed")
				} else {
					p.endFrag = v[0]
				}
			case f.has("contains"):
				vs, why := pickSafe(f)
				if why != "" {
					fail(why)
				}
				for _, v := range vs {
					if f.has("windash") {
						v = strings.ReplaceAll(v, "/", "-")
					}
					p.addFrag(v)
				}
			default:
				fail("an exact CommandLine match cannot be reproduced")
			}
		case category == "process_creation" && field == "image" && osName == "windows":
			if !(f.has("endswith") || f.has("contains")) {
				fail("Image can only be matched with endswith/contains")
				continue
			}
			carrier := ""
			for _, v := range f.values {
				if b := basenameIfExe(v); b != "" {
					carrier = b
					break
				}
			}
			switch {
			case carrier == "":
				fail("Image has no plain executable name to run a harmless copy of cmd.exe as")
			case p.carrier != "" && !strings.EqualFold(p.carrier, carrier):
				fail("two different Image names are needed")
			default:
				p.carrier = carrier
			}
		case category == "file_event" && field == "targetfilename":
			switch {
			case f.has("startswith") || f.has("re") || f.has("cidr") || f.has("base64") || f.has("base64offset"):
				fail("TargetFilename|" + strings.Join(f.mods, "|") + " cannot be reproduced")
			case f.has("endswith"):
				v, why := pickSafe(f)
				if why != "" {
					fail(why)
				} else if strings.ContainsAny(v[0], ":") {
					fail("a drive or stream in the file name cannot be reproduced")
				} else {
					p.endFrag = v[0]
				}
			case f.has("contains"):
				vs, why := pickSafe(f)
				if why != "" {
					fail(why)
				}
				for _, v := range vs {
					if strings.Contains(v, ":") {
						fail("a drive or stream in the file name cannot be reproduced")
						continue
					}
					p.addFrag(v)
				}
			default:
				fail("an exact TargetFilename match cannot be reproduced")
			}
		default:
			fail(fmt.Sprintf("field %s is not reproduced (it would need the real %s event)", f.field, category))
		}
	}
	if ok {
		p.emulated = append(p.emulated, name)
	}
	return ok
}

// SigmaResult is the outcome of generating a draft from one rule.
type SigmaResult struct {
	Rule     *SigmaRule
	Step     *scenario.Step // nil when Coverage.Emulable is false
	OS       string
	Coverage Coverage
}

// GenerateSigma builds a draft step for the rule, or says exactly why it cannot. techOverride supplies the ATT&CK id
// when the rule carries none.
func GenerateSigma(r *SigmaRule, techOverride string) (*SigmaResult, error) {
	res := &SigmaResult{Rule: r}
	switch r.Product {
	case "windows":
		res.OS = "windows"
	case "linux":
		res.OS = "linux"
	default:
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, fmt.Sprintf("logsource product %q is not supported (windows and linux only)", r.Product))
		return res, nil
	}
	if r.Category != "process_creation" && r.Category != "file_event" {
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, fmt.Sprintf("logsource category %q is not supported yet (process_creation and file_event only)", r.Category))
		return res, nil
	}
	tech := strings.ToUpper(strings.TrimSpace(techOverride))
	if tech == "" && len(r.Techniques) > 0 {
		tech = r.Techniques[0]
	}
	if tech == "" {
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, "the rule has no attack.tNNNN tag; supply the ATT&CK technique id")
		return res, nil
	}

	names := make([]string, 0, len(r.selections))
	for n := range r.selections {
		names = append(names, n)
	}
	sets, err := satisfyingSets(r.condition, names)
	if err != nil {
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, err.Error())
		return res, nil
	}

	var best *plan
	var firstReasons []string
	for _, set := range sets {
		if len(set) == 0 {
			continue
		}
		p := &plan{}
		all := true
		for _, nm := range set {
			if !planSelection(nm, r.selections[nm], r.Category, res.OS, p) {
				all = false
			}
		}
		if all {
			best = p
			// A selection the condition NEGATES must not be satisfied by the carrier; warn when it plausibly is.
			for _, nm := range names {
				in := false
				for _, s := range set {
					if s == nm {
						in = true
					}
				}
				if !in && negatedSelectionMayMatchCarrier(r.selections[nm], res.OS, p) {
					p.reasons = append(p.reasons, fmt.Sprintf("note: selection %q (excluded by the condition) may also match the carrier process, so the rule might not fire", nm))
				}
			}
			break
		}
		if firstReasons == nil {
			firstReasons = p.reasons
		}
	}
	if best == nil {
		res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, firstReasons...)
		if len(res.Coverage.NotEmulated) == 0 {
			res.Coverage.NotEmulated = append(res.Coverage.NotEmulated, "no combination of the rule's selections can be reproduced")
		}
		return res, nil
	}
	res.Coverage.Emulable = true
	res.Coverage.Emulated = best.emulated
	for _, why := range best.reasons {
		if strings.HasPrefix(why, "note: ") {
			res.Coverage.Notes = append(res.Coverage.Notes, strings.TrimPrefix(why, "note: "))
		}
	}
	marker := Marker("sigma", r.ID, r.Title)
	st := &scenario.Step{
		Name:        truncate("Sigma: "+r.Title, 120),
		TechniqueID: tech,
		Framework:   "custom",
		TestIndex:   0,
		TimeoutSec:  30,
		Marker:      marker,
		Risk:        "low", Reversible: true, ProductionSafe: true,
		BlastRadius: "runs a harmless echo (or creates an empty file) that carries the rule's strings; nothing the rule describes is executed",
		Detection:   []string{"Sigma rule: " + r.Title + idSuffix(r.ID)},
		Telemetry:   []string{telemetryFor(r.Category, res.OS)},
	}
	if r.Category == "process_creation" {
		buildProcessStep(st, res.OS, marker, best)
	} else {
		buildFileStep(st, res.OS, marker, best)
	}
	res.Step = st
	return res, nil
}

func idSuffix(id string) string {
	if id == "" {
		return ""
	}
	return " (" + id + ")"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func telemetryFor(category, os string) string {
	switch {
	case category == "process_creation" && os == "windows":
		return "Security EID 4688 / Sysmon EID 1"
	case category == "process_creation":
		return "auditd EXECVE / process events"
	case os == "windows":
		return "Sysmon EID 11 (file create)"
	default:
		return "auditd / file creation events"
	}
}

// negatedSelectionMayMatchCarrier is true when an excluded selection tests Image against the carrier we run.
func negatedSelectionMayMatchCarrier(s sigmaSelection, osName string, p *plan) bool {
	carrier := "cmd.exe"
	if p.carrier != "" {
		carrier = p.carrier
	}
	if osName != "windows" {
		carrier = "echo"
	}
	for _, f := range s.fields {
		if strings.EqualFold(f.field, "image") {
			for _, v := range f.values {
				if strings.HasSuffix(strings.ToLower(strings.ReplaceAll(v, "/", "\\")), "\\"+strings.ToLower(carrier)) {
					return true
				}
			}
		}
	}
	return false
}

func buildProcessStep(st *scenario.Step, osName, marker string, p *plan) {
	words := append([]string{marker}, p.frags...)
	if p.endFrag != "" {
		words = append(words, p.endFrag)
	}
	if osName == "windows" {
		st.Executor = "cmd"
		dir := "audspect-" + marker
		line := "cmd.exe /c echo " + strings.Join(words, " ")
		if p.carrier != "" {
			full := `%TEMP%\` + dir + `\` + p.carrier
			line = `mkdir "%TEMP%\` + dir + `" >nul 2>&1 & copy /y "%SystemRoot%\System32\cmd.exe" "` + full + `" >nul & "` + full + `" /c echo ` + strings.Join(words, " ")
		}
		st.Command = line
		st.Cleanup = `rmdir /s /q "%TEMP%\` + dir + `" 2>nul`
		return
	}
	st.Executor = "bash"
	quoted := make([]string, len(words))
	for i, w := range words {
		quoted[i] = "'" + w + "'"
	}
	st.Command = "/bin/echo " + strings.Join(quoted, " ")
	st.Cleanup = "true"
}

func buildFileStep(st *scenario.Step, osName, marker string, p *plan) {
	rel := strings.Join(p.frags, "")
	rel = strings.TrimLeft(strings.ReplaceAll(rel, "\\", "/"), "/")
	end := strings.ReplaceAll(p.endFrag, "\\", "/")
	if rel == "" {
		rel = marker
	}
	file := rel + end
	if strings.HasSuffix(file, "/") {
		file += marker
	}
	dir := "audspect-" + marker
	if osName == "windows" {
		st.Executor = "cmd"
		wfile := strings.ReplaceAll(file, "/", `\`)
		base := `%TEMP%\` + dir + `\` + wfile
		parent := base[:strings.LastIndex(base, `\`)]
		st.Command = `mkdir "` + parent + `" >nul 2>&1 & type nul > "` + base + `" & echo ` + marker
		st.Cleanup = `rmdir /s /q "%TEMP%\` + dir + `" 2>nul`
		return
	}
	st.Executor = "bash"
	base := "/tmp/" + dir + "/" + file
	parent := base[:strings.LastIndex(base, "/")]
	st.Command = "mkdir -p '" + parent + "' && : > '" + base + "' && echo '" + marker + "'"
	st.Cleanup = "rm -rf '/tmp/" + dir + "'"
}
