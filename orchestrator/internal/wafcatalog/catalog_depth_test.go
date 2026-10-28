package wafcatalog

import (
	"regexp"
	"strings"
	"testing"
)

// Payload depth: the catalog carries one entry per attack family before this file, which says a WAF "covers" SQL
// injection after one UNION string. These tests pin the extra variants a real WAF has to handle (other database
// engines, time-based and stacked queries, comment and case obfuscation, other locations, Windows and Unix paths,
// both shells' operators) and that every one stays a harmless probe.

func depthCatalog(t *testing.T) []AttackVector {
	t.Helper()
	v, err := AudspectWAFAttackCatalog()
	if err != nil {
		t.Fatalf("AudspectWAFAttackCatalog: %v", err)
	}
	return v
}

func inFamily(vs []AttackVector, f AttackFamily) []AttackVector {
	var out []AttackVector
	for _, v := range vs {
		if v.Family == f {
			out = append(out, v)
		}
	}
	return out
}

func joined(vs []AttackVector, pick func(AttackVector) string) string {
	var b strings.Builder
	for _, v := range vs {
		b.WriteString(pick(v))
		b.WriteString("\n")
	}
	return b.String()
}

func TestDepth_EveryFamilyHasMoreThanAHandfulOfVariants(t *testing.T) {
	vs := depthCatalog(t)
	for fam, min := range map[AttackFamily]int{FamilySQLInjection: 10, FamilyXSS: 12, FamilyPathTraversal: 8, FamilyCommandInjection: 7} {
		if got := len(inFamily(vs, fam)); got < min {
			t.Errorf("family %s has %d vectors, want at least %d", fam, got, min)
		}
	}
}

func TestDepth_SQLInjectionCoversTheTechniquesAWAFMustRecognise(t *testing.T) {
	names := strings.ToLower(joined(inFamily(depthCatalog(t), FamilySQLInjection), func(v AttackVector) string { return v.Name }))
	for _, want := range []string{"union", "boolean", "error-based", "time-based", "stacked", "oracle", "comment", "case", "json", "header"} {
		if !strings.Contains(names, want) {
			t.Errorf("no SQL injection vector is named for %q; names were:\n%s", want, names)
		}
	}
}

func TestDepth_XSSCoversContextsAndEncodings(t *testing.T) {
	names := strings.ToLower(joined(inFamily(depthCatalog(t), FamilyXSS), func(v AttackVector) string { return v.Name }))
	for _, want := range []string{"reflected", "stored", "dom", "attribute", "uri", "hex", "polyglot", "svg", "iframe", "json", "template", "double"} {
		if !strings.Contains(names, want) {
			t.Errorf("no XSS vector is named for %q; names were:\n%s", want, names)
		}
	}
}

func TestDepth_PathTraversalCoversUnixWindowsAndEncodings(t *testing.T) {
	vs := inFamily(depthCatalog(t), FamilyPathTraversal)
	payloads := joined(vs, func(v AttackVector) string { return v.Malicious.Path + " " + v.Malicious.Payload })
	for _, want := range []struct{ label, needle string }{
		{"Unix etc/passwd", "etc/passwd"},
		{"Windows backslash", `..\`},
		{"Windows win.ini", "win.ini"},
		{"single URL encoding", "%2e%2e%2f"},
		{"double URL encoding", "%252e"},
		{"overlong UTF-8", "%c0%af"},
		{"null byte", "%00"},
		{"absolute path", " /etc/"},
		{"nested dot sequence filter bypass", "....//"},
	} {
		if !strings.Contains(strings.ToLower(payloads), strings.ToLower(want.needle)) {
			t.Errorf("no path traversal vector covers %s (%q)", want.label, want.needle)
		}
	}
}

func TestDepth_CommandInjectionCoversUnixAndWindowsOperators(t *testing.T) {
	vs := inFamily(depthCatalog(t), FamilyCommandInjection)
	payloads := joined(vs, func(v AttackVector) string { return v.Malicious.Payload })
	for _, want := range []struct{ label, needle string }{
		{"semicolon", ";"},
		{"pipe", "|"},
		{"AND list", "&&"},
		{"OR list", "||"},
		{"command substitution", "$("},
		{"backtick", "`"},
		{"encoded newline", "%0a"},
		{"Windows single ampersand", " & "},
		{"Windows command", "whoami"},
		{"time-based probe", "sleep"},
	} {
		if !strings.Contains(strings.ToLower(payloads), want.needle) {
			t.Errorf("no command injection vector covers %s (%q)", want.label, want.needle)
		}
	}
}

// Every new vector must have a legitimate twin on the same endpoint, so a WAF that blocks the whole route (or
// everything) shows up as a false positive instead of a pass.
func TestDepth_EveryVectorInTheFourFamiliesHasABenignTwinOnTheSameEndpoint(t *testing.T) {
	for _, fam := range []AttackFamily{FamilySQLInjection, FamilyXSS, FamilyPathTraversal, FamilyCommandInjection} {
		for _, v := range inFamily(depthCatalog(t), fam) {
			if v.BenignCounterpart == nil {
				t.Errorf("%s has no benign counterpart", v.ID)
				continue
			}
			b := v.BenignCounterpart
			if b.Method != v.Malicious.Method || b.PayloadLocation != v.Malicious.PayloadLocation {
				t.Errorf("%s: benign twin uses %s %s, attack uses %s %s", v.ID, b.Method, b.PayloadLocation, v.Malicious.Method, v.Malicious.PayloadLocation)
			}
			if b.Payload == v.Malicious.Payload && b.Path == v.Malicious.Path {
				t.Errorf("%s: benign twin is identical to the attack", v.ID)
			}
		}
	}
}

func TestDepth_NoTwoVectorsSendTheSameRequest(t *testing.T) {
	seen := map[string]string{}
	for _, v := range depthCatalog(t) {
		m := v.Malicious
		k := m.Method + "|" + m.Path + "|" + m.PayloadLocation + "|" + m.Payload
		if other, dup := seen[k]; dup {
			t.Errorf("%s and %s send the identical request %q", v.ID, other, k)
		}
		seen[k] = v.ID
	}
}

func TestDepth_StandardsMappingMatchesTheFamily(t *testing.T) {
	want := map[AttackFamily]string{FamilySQLInjection: "CWE-89", FamilyXSS: "CWE-79", FamilyPathTraversal: "CWE-22", FamilyCommandInjection: "CWE-78"}
	for fam, cwe := range want {
		for _, v := range inFamily(depthCatalog(t), fam) {
			ok := false
			for _, c := range v.Standards.CWEIDs {
				if c == cwe {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s (%s) is not mapped to %s: %v", v.ID, fam, cwe, v.Standards.CWEIDs)
			}
		}
	}
}

// Safety: the catalog describes probes, never anything that changes or destroys data on a target that is actually
// vulnerable. Data-changing verbs, file deletion, shutdown and download-and-run payloads are refused here.
var destructive = regexp.MustCompile(`(?i)\b(drop\s+(table|database)|delete\s+from|truncate\s+table|update\s+\w+\s+set|insert\s+into|rm\s+-rf|mkfs|shutdown|reboot|format\s+c:|del\s+/[fsq]|wget\s|curl\s|powershell|certutil|nc\s+-e|/bin/(ba)?sh\s+-i|xp_cmdshell)`)

func TestDepth_NoPayloadCanDestroyOrChangeDataOrFetchCode(t *testing.T) {
	for _, v := range depthCatalog(t) {
		for label, r := range map[string]*RequestTemplate{"attack": &v.Malicious, "benign": v.BenignCounterpart} {
			if r == nil {
				continue
			}
			if loc := destructive.FindString(r.Payload + " " + r.Path); loc != "" {
				t.Errorf("%s %s request contains %q, which is not a harmless probe: %s %s %q", v.ID, label, loc, r.Method, r.Path, r.Payload)
			}
		}
	}
}

func TestDepth_IDsFollowTheFamilyPrefixAndAreSequential(t *testing.T) {
	for prefix, fam := range map[string]AttackFamily{"SQLI": FamilySQLInjection, "XSS": FamilyXSS, "PATHTRAV": FamilyPathTraversal, "CMDI": FamilyCommandInjection} {
		vs := inFamily(depthCatalog(t), fam)
		have := map[string]bool{}
		for _, v := range vs {
			if !strings.HasPrefix(v.ID, prefix+"-") {
				t.Errorf("%s has family %s but ID prefix is not %s-", v.ID, fam, prefix)
			}
			have[v.ID] = true
		}
		for i := 1; i <= len(vs); i++ {
			id := prefix + "-" + pad3(i)
			if !have[id] {
				t.Errorf("IDs for %s are not sequential: %s is missing", prefix, id)
			}
		}
	}
}

func pad3(n int) string {
	s := "00" + string(rune('0'+n/10%10)) + string(rune('0'+n%10))
	if n >= 100 {
		return string(rune('0'+n/100)) + string(rune('0'+n/10%10)) + string(rune('0'+n%10))
	}
	return s[len(s)-3:]
}
