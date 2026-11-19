package adcsaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const (
	enrollGUID = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	domUsers   = "S-1-5-21-1-2-3-513"
	domAdmins  = "S-1-5-21-1-2-3-512"
	helpdesk   = "S-1-5-21-1-2-3-1105"
)

type m = map[string]any

func ace(sid string, mask int64, objType, typ string) m {
	return m{"sid": sid, "mask": mask, "objectType": objType, "type": typ}
}
func enrollACE(sid string) m { return ace(sid, 0x100, enrollGUID, "Allow") }
func writeACE(sid string) m  { return ace(sid, 0x40000, "", "Allow") } // WriteDacl
func adminACE() m            { return ace(domAdmins, 0xF01FF, "", "Allow") }
func tmpl(name string, over m) m {
	t := m{"name": name, "schemaVersion": 2, "nameFlag": 0, "enrollFlag": 0, "raSignature": 0,
		"ekus": []string{"1.3.6.1.5.5.7.3.2"}, "appPolicies": []string{}, "issuancePolicies": []string{},
		"aclReadable": true, "aces": []m{adminACE(), enrollACE(domUsers)}, "publishedOn": []string{"CorpCA"}}
	for k, v := range over {
		t[k] = v
	}
	return t
}
func ca(over m) m {
	c := m{"name": "CorpCA", "host": "ca01.corp.test", "published": []string{"T"}, "editFlags": 0, "interfaceFlags": 0x200,
		"keyProvider": "SafeNet Key Storage Provider", "caAces": []m{ace(domAdmins, 0x3, "", "Allow")}, "web": nil, "build": nil}
	for k, v := range over {
		c[k] = v
	}
	return c
}

type tc struct {
	name   string
	esc    string // "1".."15", "PUB" not covered here, "CORR"
	want   string // PASS FAIL SKIP
	ctx    m
	expect string // substring that must appear in the output
}

func cases() []tc {
	T := func(ts ...m) m { return m{"Templates": ts, "CAs": []m{ca(nil)}} }
	cases := []tc{
		// ESC1
		{"esc1 vulnerable", "1", "FAIL", T(tmpl("Web", m{"nameFlag": 1})), "Domain Users"},
		{"esc1 enrollee supplies the SAN", "1", "FAIL", T(tmpl("SanOnly", m{"nameFlag": 0x10000})), "Domain Users"},
		{"esc1 manager approval", "1", "PASS", T(tmpl("Web", m{"nameFlag": 1, "enrollFlag": 2})), ""},
		{"esc1 RA signature", "1", "PASS", T(tmpl("Web", m{"nameFlag": 1, "raSignature": 1})), ""},
		{"esc1 only tier0 can enroll", "1", "PASS", T(tmpl("Web", m{"nameFlag": 1, "aces": []m{adminACE(), enrollACE(domAdmins)}})), ""},
		{"esc1 enroll denied", "1", "PASS", T(tmpl("Web", m{"nameFlag": 1, "aces": []m{enrollACE(domUsers), ace(domUsers, 0x100, enrollGUID, "Deny")}})), ""},
		{"esc1 no auth EKU", "1", "PASS", T(tmpl("Web", m{"nameFlag": 1, "ekus": []string{"1.3.6.1.5.5.7.3.4"}})), ""},
		{"esc1 acl unreadable is not clean", "1", "SKIP", T(tmpl("Web", m{"nameFlag": 1, "aclReadable": false, "aces": []m{}})), "could not be read"},
		{"esc1 clean template", "1", "PASS", T(tmpl("User", nil)), ""},
		{"esc1 templates not read", "1", "SKIP", m{"Errors": m{"templates": "no container"}, "CAs": []m{ca(nil)}}, ""},
		// ESC2
		{"esc2 any purpose", "2", "FAIL", T(tmpl("Any", m{"ekus": []string{"2.5.29.37.0"}})), "ESC2"},
		{"esc2 no EKU", "2", "FAIL", T(tmpl("Sub", m{"ekus": []string{}})), "ESC2"},
		{"esc2 specific EKU", "2", "PASS", T(tmpl("User", nil)), ""},
		// ESC3
		{"esc3 agent without consumer is potential", "3", "SKIP", T(tmpl("Agent", m{"ekus": []string{"1.3.6.1.4.1.311.20.2.1"}})), "potential"},
		{"esc3 agent with consumer", "3", "FAIL", T(tmpl("Agent", m{"ekus": []string{"1.3.6.1.4.1.311.20.2.1"}}),
			tmpl("OnBehalf", m{"raSignature": 1, "appPolicies": []string{"1.3.6.1.4.1.311.20.2.1"}, "enrollFlag": 0})), "ESC3"},
		{"esc3 no agent template", "3", "PASS", T(tmpl("User", nil)), ""},
		// ESC4
		{"esc4 helpdesk writes template", "4", "FAIL", T(tmpl("User", m{"aces": []m{adminACE(), writeACE(helpdesk)}})), helpdesk},
		{"esc4 tier0 only", "4", "PASS", T(tmpl("User", m{"aces": []m{adminACE()}})), ""},
		{"esc4 acl unreadable", "4", "SKIP", T(tmpl("User", m{"aclReadable": false, "aces": []m{}})), ""},
		// ESC5
		{"esc5 NTAuth writable", "5", "FAIL", m{"PkiObjects": []m{{"name": "NTAuthCertificates", "aclReadable": true, "aces": []m{adminACE(), writeACE(helpdesk)}}}}, "NTAuthCertificates"},
		{"esc5 clean", "5", "PASS", m{"PkiObjects": []m{{"name": "NTAuthCertificates", "aclReadable": true, "aces": []m{adminACE()}}}}, ""},
		{"esc5 unreadable", "5", "SKIP", m{"PkiObjects": []m{{"name": "AIA", "aclReadable": false, "aces": []m{}}}}, ""},
		{"esc5 not read", "5", "SKIP", m{"Errors": m{"pki": "denied"}}, ""},
		// ESC6
		{"esc6 flag set", "6", "FAIL", m{"CAs": []m{ca(m{"editFlags": 0x40000})}}, "ESC6"},
		{"esc6 flag clear", "6", "PASS", m{"CAs": []m{ca(nil)}}, ""},
		{"esc6 unreadable", "6", "SKIP", m{"CAs": []m{ca(m{"editFlags": nil})}}, ""},
		// ESC7
		{"esc7 manageca", "7", "FAIL", m{"CAs": []m{ca(m{"caAces": []m{ace(helpdesk, 0x1, "", "Allow")}})}}, "ManageCA"},
		{"esc7 managecertificates", "7", "FAIL", m{"CAs": []m{ca(m{"caAces": []m{ace(helpdesk, 0x2, "", "Allow")}})}}, "ManageCertificates"},
		{"esc7 tier0 only", "7", "PASS", m{"CAs": []m{ca(nil)}}, ""},
		{"esc7 sd unreadable", "7", "SKIP", m{"CAs": []m{ca(m{"caAces": nil})}}, ""},
		// ESC8
		{"esc8 not probed is potential", "8", "SKIP", m{"CAs": []m{ca(nil)}, "LiveProbe": false}, "BAS_ADCS_LIVE_PROBE"},
		{"esc8 live ntlm over http", "8", "FAIL", m{"CAs": []m{ca(m{"web": m{"answered": true, "httpNtlm": true}})}, "LiveProbe": true}, "ESC8"},
		{"esc8 live no web enrollment answer", "8", "SKIP", m{"CAs": []m{ca(m{"web": m{"answered": false, "httpNtlm": false}})}, "LiveProbe": true}, ""},
		{"esc8 live nothing listens on HTTP", "8", "PASS", m{"CAs": []m{ca(m{"web": m{"answered": false, "refused": true, "httpNtlm": false}})}, "LiveProbe": true}, ""},
		{"esc8 live answered without ntlm", "8", "PASS", m{"CAs": []m{ca(m{"web": m{"answered": true, "httpNtlm": false}})}, "LiveProbe": true}, ""},
		// ESC9
		{"esc9 no security extension", "9", "FAIL", T(tmpl("NoExt", m{"enrollFlag": 0x80000})), "ESC9"},
		{"esc9 with extension", "9", "PASS", T(tmpl("User", nil)), ""},
		// ESC10
		{"esc10 weak binding is potential", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 0, "certMappingMethods": nil}}}, "potential"},
		{"esc10 patched DC ignores a weak registry value", "10", "PASS", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 0, "certMappingMethods": nil, "build": m{"number": "17763", "ubr": 7800}}}}, ""},
		{"esc10 patched DC still counts the Schannel UPN bit", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 2, "certMappingMethods": 0x1f, "build": m{"number": "17763", "ubr": 7800}}}}, "UPN mapping"},
		{"esc10 unpatched DC with enforcement off", "10", "FAIL", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 0, "certMappingMethods": nil, "build": m{"number": "17763", "ubr": 7000}}}}, "below the September 9, 2025 update"},
		{"esc10 unpatched DC in compatibility mode is potential", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 1, "certMappingMethods": nil, "build": m{"number": "17763", "ubr": 7000}}}}, "below the September 9, 2025 update"},
		{"esc10 Server 2025 build is not matched", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 0, "certMappingMethods": nil, "build": m{"number": "26100", "ubr": 6584}}}}, "could not be matched"},
		{"esc10 enforced", "10", "PASS", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 2, "certMappingMethods": nil}}}, ""},
		{"esc10 unset is not clean", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": nil, "certMappingMethods": nil}}}, ""},
		{"esc10 Server 2022 below the May 2022 update has no strong mapping", "10", "FAIL", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": nil, "certMappingMethods": nil, "build": m{"number": "20348", "ubr": 587}}}}, "May 10, 2022"},
		{"esc10 Server 2022 below the May 2022 update ignores a set value", "10", "FAIL", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": 2, "certMappingMethods": nil, "build": m{"number": "20348", "ubr": 587}}}}, "May 10, 2022"},
		{"esc10 Server 2022 at the May 2022 update with the value unset is still unknown", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": nil, "certMappingMethods": nil, "build": m{"number": "20348", "ubr": 707}}}}, ""},
		{"esc10 Server 2019 below an unlisted threshold stays unknown", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": true, "strongBinding": nil, "certMappingMethods": nil, "build": m{"number": "17763", "ubr": 100}}}}, ""},
		{"esc10 unreadable dc", "10", "SKIP", m{"DCs": []m{{"name": "dc01", "readable": false, "strongBinding": nil, "certMappingMethods": nil}}}, ""},
		// ESC11
		{"esc11 encryption not enforced", "11", "FAIL", m{"CAs": []m{ca(m{"interfaceFlags": 0})}}, "ESC11"},
		{"esc11 enforced", "11", "PASS", m{"CAs": []m{ca(nil)}}, ""},
		{"esc11 unreadable", "11", "SKIP", m{"CAs": []m{ca(m{"interfaceFlags": nil})}}, ""},
		// ESC12
		{"esc12 software provider is posture, not a FAIL", "12", "SKIP", m{"CAs": []m{ca(m{"keyProvider": "Microsoft Software Key Storage Provider"})}}, "ESC12"},
		{"esc12 hsm provider", "12", "PASS", m{"CAs": []m{ca(nil)}}, ""},
		{"esc12 unreadable", "12", "SKIP", m{"CAs": []m{ca(m{"keyProvider": nil})}}, ""},
		// ESC13
		{"esc13 policy linked to privileged group", "13", "FAIL", m{"Templates": []m{tmpl("Pol", m{"issuancePolicies": []string{"1.2.3.4"}})},
			"Oids": []m{{"oid": "1.2.3.4", "name": "AdminPolicy", "linkedGroupSid": domAdmins, "linkResolved": true, "linkedGroupPrivileged": true}}}, "ESC13"},
		{"esc13 policy linked to ordinary group", "13", "PASS", m{"Templates": []m{tmpl("Pol", m{"issuancePolicies": []string{"1.2.3.4"}})},
			"Oids": []m{{"oid": "1.2.3.4", "name": "P", "linkedGroupSid": helpdesk, "linkResolved": true, "linkedGroupPrivileged": false}}}, ""},
		{"esc13 link unresolved", "13", "SKIP", m{"Templates": []m{tmpl("Pol", m{"issuancePolicies": []string{"1.2.3.4"}})},
			"Oids": []m{{"oid": "1.2.3.4", "name": "P", "linkedGroupSid": "CN=g", "linkResolved": false, "linkedGroupPrivileged": false}}}, ""},
		{"esc13 oids not read", "13", "SKIP", m{"Templates": []m{tmpl("Pol", m{"issuancePolicies": []string{"1.2.3.4"}})}, "Errors": m{"oids": "denied"}}, ""},
		// ESC14
		{"esc14 weak mapping", "14", "FAIL", m{"Accounts": []m{{"sam": "svc", "tier0": false, "mappings": []string{"X509:<RFC822>svc@corp.test"}}}}, "ESC14"},
		{"esc14 weak issuer subject on privileged account", "14", "FAIL", m{"Accounts": []m{{"sam": "admin", "tier0": true, "mappings": []string{"X509:<I>DC=test<S>CN=admin"}}}}, "privileged account"},
		{"esc14 strong mapping", "14", "PASS", m{"Accounts": []m{{"sam": "svc", "tier0": false, "mappings": []string{"X509:<I>DC=test<SR>0102"}}}}, ""},
		{"esc14 no mappings", "14", "PASS", m{"Accounts": []m{}}, ""},
		{"esc14 not read", "14", "SKIP", m{"Errors": m{"accounts": "denied"}}, ""},
		// ESC15
		{"esc15 v1 with enrollee subject is potential", "15", "SKIP", T(tmpl("WebV1", m{"schemaVersion": 1, "nameFlag": 1})), "potential"},
		{"esc15 CA below the fixed build", "15", "FAIL", m{"Templates": []m{tmpl("WebV1", m{"schemaVersion": 1, "nameFlag": 1})}, "CAs": []m{ca(m{"build": m{"number": "20348", "ubr": 2000}})}}, "below the fixed build"},
		{"esc15 CA at the fixed build", "15", "PASS", m{"Templates": []m{tmpl("WebV1", m{"schemaVersion": 1, "nameFlag": 1})}, "CAs": []m{ca(m{"build": m{"number": "20348", "ubr": 2849}})}}, ""},
		{"esc15 hotpatch zone is not called vulnerable", "15", "SKIP", m{"Templates": []m{tmpl("WebV1", m{"schemaVersion": 1, "nameFlag": 1})}, "CAs": []m{ca(m{"build": m{"number": "20348", "ubr": 2830}})}}, "could not be matched"},
		{"esc15 unrecognised build stays potential", "15", "SKIP", m{"Templates": []m{tmpl("WebV1", m{"schemaVersion": 1, "nameFlag": 1})}, "CAs": []m{ca(m{"build": m{"number": "9600", "ubr": 0}})}}, "could not be matched"},
		{"esc15 unpublished v1 template is latent", "15", "SKIP", m{"Templates": []m{tmpl("WebV1", m{"schemaVersion": 1, "nameFlag": 1, "publishedOn": []string{}})}, "CAs": []m{ca(m{"build": m{"number": "20348", "ubr": 2000}})}}, "latent"},
		{"esc15 v2", "15", "PASS", T(tmpl("WebV2", m{"schemaVersion": 2, "nameFlag": 1})), ""},
		// Correlation
		{"corr published esc1 is an exploitable path", "CORR", "FAIL", m{"Templates": []m{tmpl("Web", m{"nameFlag": 1})}, "CAs": []m{ca(nil)}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{}, "Accounts": []m{}}, "state=path"},
		{"corr unpublished esc1 is latent", "CORR", "SKIP", m{"Templates": []m{tmpl("Web", m{"nameFlag": 1, "publishedOn": []string{}})}, "CAs": []m{ca(nil)}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{}, "Accounts": []m{}}, "latent"},
		{"corr esc6 with a reachable template is a path", "CORR", "FAIL", m{"Templates": []m{tmpl("User", nil)}, "CAs": []m{ca(m{"editFlags": 0x40000})}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{}, "Accounts": []m{}}, "published template User"},
		{"corr esc6 on a CA that publishes nothing reachable is not a path", "CORR", "SKIP", m{"Templates": []m{tmpl("User", m{"publishedOn": []string{"OtherCA"}})}, "CAs": []m{ca(m{"editFlags": 0x40000}), ca(m{"name": "OtherCA"})}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{}, "Accounts": []m{}}, "no published template enrollable"},
		{"corr clean without the live probe", "CORR", "PASS", m{"Templates": []m{tmpl("User", m{"aces": []m{adminACE()}})}, "LiveProbe": false, "CAs": []m{ca(nil)}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{{"name": "dc", "readable": true, "strongBinding": 2}}, "Accounts": []m{}}, ""},
		{"corr clean", "CORR", "PASS", m{"Templates": []m{tmpl("User", m{"aces": []m{adminACE()}})}, "LiveProbe": true, "CAs": []m{ca(m{"web": m{"answered": true, "httpNtlm": false}})}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{{"name": "dc", "readable": true, "strongBinding": 2}}, "Accounts": []m{}}, ""},
		{"corr a confirmed DC misconfiguration alone is not called an issuance path", "CORR", "FAIL", m{"Templates": []m{tmpl("User", m{"aces": []m{adminACE()}})}, "LiveProbe": false, "CAs": []m{ca(nil)}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{{"name": "dc", "readable": true, "strongBinding": nil, "build": m{"number": "20348", "ubr": 587}}}, "Accounts": []m{}}, "no complete low-privilege issuance path"},
		{"corr a real path still says exploitable issuance path", "CORR", "FAIL", m{"Templates": []m{tmpl("Web", m{"nameFlag": 1})}, "CAs": []m{ca(nil)}, "PkiObjects": []m{}, "Oids": []m{}, "DCs": []m{}, "Accounts": []m{}}, "exploitable certificate-issuance path"},
		{"corr unread source is never clean", "CORR", "SKIP", m{"Templates": []m{tmpl("User", m{"aces": []m{adminACE()}})}, "CAs": []m{ca(nil)}, "Errors": m{"dcs": "denied"}}, ""},
	}
	return cases
}

func psPath(t *testing.T) string {
	t.Helper()
	for _, n := range []string{"powershell", "pwsh"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	t.Skip("no PowerShell available")
	return ""
}

func harness(t *testing.T, c tc) string {
	t.Helper()
	lib, err := FullLibrary()
	if err != nil {
		t.Fatal(err)
	}
	ctx, _ := json.Marshal(c.ctx)
	var call string
	if c.esc == "CORR" {
		call = "$f = @(); if ($null -ne $ctx.Templates -and $null -ne $ctx.CAs) { $f = Get-AdcsCorrelation $ctx }\n" +
			"$why=''; $complete=$true; foreach ($e in $ctx.Errors.Keys) { $complete=$false }\n" +
			"if ($null -eq $ctx.Templates -or $null -eq $ctx.CAs) { $complete=$false }\n" +
			"Write-AdcsVerdict 'correlation' 'BAS-SIM-ADCS-CORR' $f $complete $why 'clean.' $script:AdcsCorrFail $script:AdcsCorrFailNoPath"
	} else {
		info := escTable[c.esc]
		var needs []string
		for _, n := range info.Needs {
			needs = append(needs, psq(n))
		}
		call = fmt.Sprintf("$script:AdcsCtx = $ctx\nInvoke-AdcsStage %s @(%s) %s %s %s $false", psq(c.esc), strings.Join(needs, ","), psq(info.Label), psq(info.Pass), psq(info.Fail))
	}
	return lib + "\n$j = '" + strings.ReplaceAll(string(ctx), "'", "''") + "' | ConvertFrom-Json\n" +
		"$ctx = New-AdcsContext\n" +
		"foreach ($p in $j.PSObject.Properties) { if ($p.Name -eq 'Errors') { foreach ($e in $p.Value.PSObject.Properties) { $ctx.Errors[$e.Name] = $e.Value } } else { $ctx.($p.Name) = $p.Value } }\n" +
		"foreach ($n in @('Templates','CAs','PkiObjects','Oids','DCs','Accounts')) { if ($null -ne $ctx.$n) { $ctx.$n = @($ctx.$n) } }\n" +
		call + "\n"
}

func runPS(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "t.ps1")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := exec.Command(psPath(t), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", f)
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	return out.String()
}

func verdict(out string) string {
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		for _, v := range []string{"PASS:", "FAIL:", "SKIP:"} {
			if strings.HasPrefix(l, v) {
				return strings.TrimSuffix(v, ":")
			}
		}
	}
	return ""
}

// Every misconfiguration fixture gets the verdict the spec requires; unread or unconfirmed evidence is never a PASS.
func TestFixtures(t *testing.T) {
	psPath(t)
	for _, c := range cases() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			out := runPS(t, harness(t, c))
			if got := verdict(out); got != c.want {
				t.Fatalf("verdict = %q, want %q\n%s", got, c.want, out)
			}
			if c.expect != "" && !strings.Contains(out, c.expect) {
				t.Fatalf("output lacks %q\n%s", c.expect, out)
			}
		})
	}
}

// A path finding explains the chain principal -> right -> object -> conditions -> impact.
func TestFindingsExplainThePath(t *testing.T) {
	psPath(t)
	out := runPS(t, harness(t, cases()[0]))
	re := regexp.MustCompile(`ADCS-FINDING: state=confirmed esc=1 .* path=(.+)`)
	mm := re.FindStringSubmatch(out)
	if mm == nil {
		t.Fatalf("no ESC1 finding line\n%s", out)
	}
	if n := len(strings.Split(strings.TrimSpace(mm[1]), " -> ")); n != 5 {
		t.Fatalf("path has %d parts, want 5: %s", n, mm[1])
	}
}

// Off a domain the collectors cannot read anything: every stage must be SKIP, never PASS.
func TestNonDomainHostNeverPasses(t *testing.T) {
	if os.Getenv("USERDNSDOMAIN") != "" {
		t.Skip("host is domain joined")
	}
	psPath(t)
	lib, err := FullLibrary()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range Stages() {
		if s.Number == "0" {
			continue
		}
		s := s
		t.Run("stage "+s.Number, func(t *testing.T) {
			t.Parallel()
			body, err := Library(s.Regions...)
			if err != nil {
				t.Fatal(err)
			}
			_ = lib
			out := runPS(t, "$ErrorActionPreference = 'SilentlyContinue'\n"+body+"\n"+s.Call+"\n")
			if v := verdict(out); v != "SKIP" {
				t.Fatalf("verdict %q off-domain, want SKIP\n%s", v, out)
			}
		})
	}
}

func TestGenerationIsDeterministicAndMatchesCommitted(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Generate()
	if !bytes.Equal(a, b) {
		t.Fatal("Generate is not deterministic")
	}
	committed, err := os.ReadFile(filepath.Join("..", "..", "..", "scenarios", "adcs-esc-template-exposure-audit.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(committed, []byte("\r\n"), []byte("\n")), a) {
		t.Fatal("scenarios/adcs-esc-template-exposure-audit.yaml is stale: run go run ./cmd/gen-adcs-scenario and re-sign")
	}
}

func TestStageTableCoversEveryEsc(t *testing.T) {
	st := Stages()
	if len(st) != 18 {
		t.Fatalf("%d stages, want 18 (0..17)", len(st))
	}
	for i := 1; i <= 15; i++ {
		s := st[i]
		if s.Number != fmt.Sprint(i) || !strings.Contains(s.Title, fmt.Sprintf("ESC%d ", i)) {
			t.Fatalf("stage %d is %q", i, s.Title)
		}
	}
}

// Read-only: nothing in any step requests a certificate or writes to AD, the CA or the registry.
func TestScenarioIsReadOnly(t *testing.T) {
	y, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"certreq", "Get-Certificate", "Submit-", "Request-Certificate", "-setreg", "-SetCAtemplates", "Add-CATemplate", "Remove-CATemplate",
		"CommitChanges", "SetInfo", "Set-ADObject", "Set-ItemProperty", "Set-Acl", "New-ItemProperty", "Remove-Item", "SetValue(", "Invoke-WebRequest", "Invoke-RestMethod", "WebClient", "-Credential"} {
		if strings.Contains(string(y), bad) {
			t.Errorf("generated scenario contains %q", bad)
		}
	}
}

// A stage carries only the collectors it uses: the live web probe only where ESC8 needs it, certutil only for the CA
// registry values, and each stage requests exactly the CA fields its analyzer reads (an unrequested field stays null,
// which an analyzer reports as unreadable, never clean).
func TestStagesCarryOnlyTheCollectorsTheyUse(t *testing.T) {
	need := map[string]string{"6": "editFlags", "7": "caAces", "8": "web", "11": "interfaceFlags", "12": "keyProvider", "15": "build"}
	for _, s := range Stages() {
		body, err := Library(s.Regions...)
		if err != nil {
			t.Fatal(err)
		}
		full := s.Call + "\n" + body
		all := s.Number == "0" || s.Number == "17"
		if got, want := strings.Contains(full, "function Read-AdcsWebProbe"), all || s.Number == "8"; got != want {
			t.Errorf("stage %s: web probe present=%v want %v", s.Number, got, want)
		}
		usesCertutil := all || s.Number == "6" || s.Number == "11" || s.Number == "12"
		if got := strings.Contains(full, "& certutil"); got != usesCertutil {
			t.Errorf("stage %s: certutil present=%v want %v", s.Number, got, usesCertutil)
		}
		if f, ok := need[s.Number]; ok && !strings.Contains(s.Call, "'"+f+"'") {
			t.Errorf("stage %s does not request CA field %s", s.Number, f)
		}
		if !strings.Contains(s.Call, "$script:AdcsCaFields") {
			t.Errorf("stage %s does not set the CA field list", s.Number)
		}
	}
}

// ESC15 is only ever a potential finding: it must say the CA patch level decides it and that this step does not read it.
func TestEsc15WordingNamesThePatchDependency(t *testing.T) {
	info := escTable["15"]
	for _, w := range []string{"CA build", "CVE-2024-49019", "never as clean"} {
		if !strings.Contains(info.Label+" "+info.Pass, w) {
			t.Errorf("ESC15 stage text lacks %q", w)
		}
	}
	lib, _ := FullLibrary()
	if !strings.Contains(lib, "The CA build could not be matched to a fixed build") {
		t.Error("ESC15 finding text lacks the unmatched-build caveat")
	}
}

// The fixed builds are Microsoft's published numbers; a wrong digit would silently mislabel a patched or unpatched host.
func TestFixedBuildTable(t *testing.T) {
	lib, _ := FullLibrary()
	for _, w := range []string{
		"'14393' = @(7515, 0)", "'17763' = @(6532, 0)", "'20348' = @(2849, 2819)", "'25398' = @(1251, 0)", "'26100' = @(2314, 2240)",
		"'14393' = @(8422, 0)", "'17763' = @(7792, 0)", "'20348' = @(4171, 0)", "may2022 = @{ '20348' = @(707, 0) }"} {
		if !strings.Contains(lib, w) {
			t.Errorf("build table lacks %s", w)
		}
	}
}

// The collectors build the certutil config as host\CAName and read only the requested fields. This mocks certutil and the
// reachability check, so a lost separator (which made ESC6, ESC11 and ESC12 unreadable on every CA) is caught offline.
func TestCollectorUsesHostBackslashCaNameForCertutil(t *testing.T) {
	psPath(t)
	lib, err := FullLibrary()
	if err != nil {
		t.Fatal(err)
	}
	script := lib + `
function Read-AdcsEnrollmentServices($cfg) { return ,@([pscustomobject]@{ name = 'CorpCA'; host = 'ca01.corp.test'; dn = 'x'; published = @() }) }
function Test-AdcsPort { return $false }
$script:log = @()
function certutil { $script:log += ($args -join ' '); return '  EditFlags REG_DWORD = 40000 (262144)' }
$script:AdcsCaFields = @('editFlags')
$ctx = New-AdcsContext
Read-AdcsPart_cas $ctx 'CN=Configuration'
Write-Output ('LOG:' + ($script:log -join '|'))
Write-Output ('EDIT:' + $ctx.CAs[0].editFlags)
Write-Output ('IFACE:[' + $ctx.CAs[0].interfaceFlags + ']')
`
	out := runPS(t, script)
	if !strings.Contains(out, `LOG:-config ca01.corp.test\CorpCA -getreg policy\EditFlags`) {
		t.Fatalf("certutil not called with host-backslash-CA and the EditFlags value:\n%s", out)
	}
	if !strings.Contains(out, "EDIT:262144") {
		t.Fatalf("EditFlags was not parsed:\n%s", out)
	}
	if !strings.Contains(out, "IFACE:[]") {
		t.Fatalf("an unrequested CA field must stay null:\n%s", out)
	}
}

// A stage's Tag is what the output carries: a table edit that is never emitted would drift from the library.
func TestStageTagsAreEmitted(t *testing.T) {
	for _, s := range Stages() {
		body, err := Library(s.Regions...)
		if err != nil {
			t.Fatal(err)
		}
		full := s.Call + "\n" + body
		want := s.Tag
		if strings.HasPrefix(want, "BAS-SIM-ADCS-ESC") {
			want = "BAS-SIM-ADCS-ESC"
		}
		if !strings.Contains(full, want) {
			t.Errorf("stage %s: tag %s is not emitted by its code", s.Number, s.Tag)
		}
	}
}
