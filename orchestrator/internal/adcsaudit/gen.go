// Package adcsaudit builds the AD CS mastery scenario (scenarios/adcs-esc-template-exposure-audit.yaml) from one shared
// PowerShell analysis library (lib.ps1). The YAML is generated, deterministic and never edited by hand: change lib.ps1
// or the stage table here, run cmd/gen-adcs-scenario, then re-sign. A test fails if the committed file drifts.
package adcsaudit

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
)

//go:embed lib.ps1
var libSource string

// Region is one named block of the library with the regions it depends on.
type Region struct {
	Name  string
	Needs []string
	Body  string
}

// Regions parses lib.ps1 into its named regions, in file order.
func Regions() ([]Region, error) {
	var out []Region
	var cur *Region
	for _, line := range strings.Split(strings.ReplaceAll(libSource, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "#region "):
			f := strings.Fields(strings.TrimPrefix(line, "#region "))
			if len(f) == 0 {
				return nil, fmt.Errorf("region without a name")
			}
			r := Region{Name: f[0]}
			for _, p := range f[1:] {
				if strings.HasPrefix(p, "needs=") {
					for _, n := range strings.Split(strings.TrimPrefix(p, "needs="), ",") {
						if n != "" {
							r.Needs = append(r.Needs, n)
						}
					}
				}
			}
			cur = &r
		case strings.HasPrefix(line, "#endregion"):
			if cur == nil {
				return nil, fmt.Errorf("#endregion without #region")
			}
			cur.Body = strings.TrimRight(cur.Body, "\n")
			out = append(out, *cur)
			cur = nil
		default:
			if cur != nil {
				cur.Body += line + "\n"
			}
		}
	}
	if cur != nil {
		return nil, fmt.Errorf("region %q is not closed", cur.Name)
	}
	return out, nil
}

// Library returns the library text for the named regions and everything they need, in file order.
func Library(names ...string) (string, error) {
	regs, err := Regions()
	if err != nil {
		return "", err
	}
	byName := map[string]Region{}
	for _, r := range regs {
		byName[r.Name] = r
	}
	want := map[string]bool{}
	var visit func(n string) error
	visit = func(n string) error {
		r, ok := byName[n]
		if !ok {
			return fmt.Errorf("unknown region %q", n)
		}
		if want[n] {
			return nil
		}
		want[n] = true
		for _, d := range r.Needs {
			if err := visit(d); err != nil {
				return err
			}
		}
		return nil
	}
	for _, n := range names {
		if err := visit(n); err != nil {
			return "", err
		}
	}
	var b strings.Builder
	for _, r := range regs {
		if want[r.Name] {
			b.WriteString(r.Body)
			b.WriteString("\n")
		}
	}
	return strings.TrimRight(b.String(), "\n"), nil
}

// FullLibrary is every region, used by the fixture tests.
func FullLibrary() (string, error) {
	regs, err := Regions()
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(regs))
	for _, r := range regs {
		names = append(names, r.Name)
	}
	return Library(names...)
}

// Stage is one step of the scenario.
type Stage struct {
	Number    string // "0".."17"
	Title     string
	Technique string
	Tag       string   // BAS-SIM tag in the output
	Call      string   // the line that runs the stage after the library
	Regions   []string // library regions the stage needs
	Blast     string
	Telemetry []string
	Detection []string
	Timeout   int
}

const readOnly = " Read-only: never requests a certificate, modifies a template or CA object, or changes CA settings."

// escText: label, pass text, fail text and the parts each ESC stage reads.
type escInfo struct {
	Label, Pass, Fail string
	Needs             []string
	Fields            []string // CA fields the stage reads
}

var escTable = map[string]escInfo{
	"1":  {"ESC1 (enrollee-supplied subject with a client-auth EKU)", "no certificate template combines an enrollee-supplied subject, an authentication EKU, no approval and low-privilege enrollment. This step assesses ESC1 only.", "ESC1: a template lets a low-privileged enrollee name any identity in a certificate that authenticates.", []string{"templates", "cas"}, nil},
	"2":  {"ESC2 (Any Purpose or no EKU)", "no template with Any Purpose or no EKU, no approval and low-privilege enrollment. This step assesses ESC2 only.", "ESC2: a template with Any Purpose or no EKU is enrollable by a low-privileged principal.", []string{"templates", "cas"}, nil},
	"3":  {"ESC3 (enrollment agent)", "no enrollable enrollment-agent template. This step assesses ESC3 only; CA enrollment-agent restrictions are not readable from AD.", "ESC3: an enrollment-agent template is enrollable and a second template accepts agent-signed requests.", []string{"templates", "cas"}, nil},
	"4":  {"ESC4 (template ACL)", "no template is writable by a non-tier-0 principal. This step assesses template ACLs only.", "ESC4: a template can be modified by a non-tier-0 principal.", []string{"templates", "cas"}, nil},
	"5":  {"ESC5 (PKI object ACL)", "no Public Key Services object or CA enrollment object is writable by a non-tier-0 principal. This step assesses PKI object ACLs only.", "ESC5: a PKI object that controls trust or enrollment can be modified by a non-tier-0 principal.", []string{"pki"}, nil},
	"6":  {"ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)", "no CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set. This step assesses the CA policy flag only.", "ESC6: a CA accepts a requester-supplied subject alternative name.", []string{"cas"}, []string{"editFlags"}},
	"7":  {"ESC7 (CA administrative rights)", "no non-tier-0 principal holds ManageCA or ManageCertificates on any CA. This step assesses CA permissions only.", "ESC7: a non-tier-0 principal holds ManageCA or ManageCertificates on a CA.", []string{"cas"}, []string{"caAces"}},
	"8":  {"ESC8 (web enrollment relay)", "no CA web enrollment endpoint offers NTLM or Negotiate over plain HTTP. HTTPS and Extended Protection are not assessed.", "ESC8: CA web enrollment accepts integrated authentication over HTTP, which can be relayed.", []string{"cas"}, []string{"web"}},
	"9":  {"ESC9 (no security extension)", "no enrollable template sets the no-security-extension flag. This step assesses the template flag only.", "ESC9: a template issues certificates without the security extension to a low-privileged enrollee.", []string{"templates", "cas"}, nil},
	"10": {"ESC10 (weak certificate mapping)", "no domain controller allows weak certificate mapping. A DC at or above the September 9, 2025 update (matched for Server 2016, 2019 and 2022) ignores the StrongCertificateBindingEnforcement value; a DC whose build cannot be matched is reported as needing live verification.", "ESC10: a domain controller allows weak certificate-to-account mapping.", []string{"dcs"}, nil},
	"11": {"ESC11 (RPC enrollment relay)", "every CA enforces an encrypted certificate request interface. This step reads the CA interface flag only.", "ESC11: a CA accepts unencrypted RPC certificate requests, which can be relayed.", []string{"cas"}, []string{"interfaceFlags"}},
	"12": {"ESC12 (CA private key posture)", "every CA key is held by a non-software provider (assumed hardware-backed; not verified). A software provider is reported as needing review, not scored as a failure.", "ESC12: a CA signing key is held in a software provider rather than a hardware security module.", []string{"cas"}, []string{"keyProvider"}},
	"13": {"ESC13 (issuance policy to group)", "no enrollable template carries an issuance policy linked to a privileged group. This step assesses issuance-policy links only.", "ESC13: a template carries an issuance policy linked to a privileged group and is enrollable by a low-privileged principal.", []string{"templates", "cas", "oids"}, nil},
	"14": {"ESC14 (weak explicit mapping)", "no enabled account has a weak explicit certificate mapping in altSecurityIdentities. This step assesses the mapping format only.", "ESC14: an account maps certificates by a weak identifier.", []string{"accounts"}, nil},
	"15": {"ESC15 (schema version 1 template, CA build checked where published)", "no schema-version-1 template with an enrollee-supplied subject is exploitable: every CA that publishes one is at or above the CVE-2024-49019 fixed build. Builds are matched for Server 2016, 2019, 2022, 2022 23H2 and 2025; a CA whose build cannot be read or matched is reported as needing live verification, never as clean.", "ESC15: a schema-version-1 template with an enrollee-supplied subject is published on a CA below the CVE-2024-49019 fixed build.", []string{"templates", "cas"}, []string{"build"}},
}

var allCaFieldRegions = []string{"cafield_editFlags", "cafield_interfaceFlags", "cafield_keyProvider", "cafield_caAces", "cafield_web", "cafield_build"}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func escStage(n, title, what string, tel, det []string) Stage {
	info := escTable[n]
	regions := []string{"esc" + n, "dispatch", "collect"}
	var needs []string
	for _, p := range info.Needs {
		regions = append(regions, "part_"+p)
		needs = append(needs, psq(p))
	}
	var fl []string
	for _, f := range info.Fields {
		regions = append(regions, "cafield_"+f)
		fl = append(fl, psq(f))
	}
	call := fmt.Sprintf("$script:AdcsCaFields = @(%s)\nInvoke-AdcsStage %s @(%s) %s %s %s $true", strings.Join(fl, ", "), psq(n), strings.Join(needs, ", "), psq(info.Label), psq(info.Pass), psq(info.Fail))
	tech := "T1649"
	if n == "8" || n == "11" {
		tech = "T1557.001"
	}
	return Stage{
		Number: n, Title: fmt.Sprintf("ESC%s — %s", n, title), Technique: tech, Tag: "BAS-SIM-ADCS-ESC" + n,
		Call: call, Regions: regions, Timeout: 120,
		Blast:     what + readOnly,
		Telemetry: tel, Detection: det,
	}
}

var ldapTel = "DC: LDAP read of certificate template and Public Key Services objects in the Configuration partition"
var ldapDet = "SIEM: an LDAP enumeration of the Certificate Templates or Public Key Services containers from a workstation is an AD CS reconnaissance indicator"

// Stages is the stage table, in run order.
func Stages() []Stage {
	return []Stage{
		{Number: "0", Title: "Build AD CS Audit Context", Technique: "T1649", Tag: "BAS-SIM-ADCS-CTX", Call: "$script:AdcsCaFields = @('editFlags', 'interfaceFlags', 'keyProvider', 'caAces', 'web', 'build')\nInvoke-AdcsContextStage", Regions: append([]string{"context_stage"}, allCaFieldRegions...), Timeout: 120,
			Blast:     "Discovers the certification authorities, certificate templates, enrollment services and forest from the Configuration partition and reads each CA's policy values. It scores nothing; it records what later stages can and cannot read." + readOnly,
			Telemetry: []string{ldapTel, "Sysmon EID 1: powershell.exe with certutil -getreg against each CA"},
			Detection: []string{ldapDet}},
		escStage("1", "Misconfigured SAN (Enrollee-Supplied Subject)", "Reads template name and enrollment flags, EKUs, RA-signature count and the template ACL to find templates a low-privileged principal can enrol in while naming any identity.", []string{ldapTel}, []string{ldapDet, "SIEM: a template that supplies the subject, carries an authentication EKU and is enrollable by Domain Users is an ESC1 indicator"}),
		escStage("2", "Any Purpose / No EKU", "Reads template EKUs, approval and RA-signature settings and the template ACL.", []string{ldapTel}, []string{ldapDet}),
		escStage("3", "Enrollment Agent", "Reads enrollment-agent templates and the templates that accept agent-signed requests, with their ACLs. CA enrollment-agent restrictions are not readable from AD and are reported as needing live verification.", []string{ldapTel}, []string{ldapDet}),
		escStage("4", "Template ACL Exposure", "Reads each template's ACL for write rights held by non-tier-0 principals.", []string{ldapTel}, []string{ldapDet, "SIEM: directory service changes (EID 5136) on pKICertificateTemplate objects by a non-administrative account"}),
		escStage("5", "PKI Object ACL Exposure", "Reads the ACLs of NTAuthCertificates, Certification Authorities, Enrollment Services, AIA, CDP, the OID container and each CA enrollment object.", []string{ldapTel}, []string{ldapDet, "SIEM: directory service changes (EID 5136) on NTAuthCertificates or Enrollment Services by a non-administrative account"}),
		escStage("6", "EDITF_ATTRIBUTESUBJECTALTNAME2", "Reads each CA's policy EditFlags value through certutil -getreg (a registry read over RPC).", []string{"CA host: remote registry read of the policy EditFlags value", "Sysmon EID 1: powershell.exe running certutil -config <ca> -getreg"}, []string{"SIEM: certutil -getreg against a CA from a non-administrative workstation"}),
		escStage("7", "CA Administrative Rights", "Reads each CA's security descriptor from the CA host's remote registry and reports non-tier-0 principals holding ManageCA or ManageCertificates.", []string{"CA host: remote registry read of the CertSvc Configuration Security value"}, []string{"SIEM: a remote registry connection to a CA host from a non-administrative workstation"}),
		escStage("8", "Web Enrollment Relay Exposure", "Off by default: reports each CA as needing live verification. When BAS_ADCS_LIVE_PROBE=true it sends one unauthenticated HTTP GET per CA to /certsrv/ with no credentials and redirects off.", []string{"CA host: one unauthenticated HTTP GET to /certsrv/ per CA, only when BAS_ADCS_LIVE_PROBE=true"}, []string{"SIEM: an unauthenticated request to /certsrv/ from a workstation"}),
		escStage("9", "No Security Extension", "Reads template enrollment flags (no-security-extension) and the template ACL.", []string{ldapTel}, []string{ldapDet}),
		escStage("10", "Weak Certificate Mapping", "Reads each domain controller's StrongCertificateBindingEnforcement and Schannel CertificateMappingMethods values and its Windows build over remote registry. A DC at or above the September 9, 2025 update ignores the registry opt-out; a build that cannot be matched leaves explicit weak values as needing live verification.", []string{"DC: remote registry read of the Kdc and Schannel certificate-mapping values"}, []string{"SIEM: remote registry connections to several domain controllers from a workstation"}),
		escStage("11", "RPC Enrollment Relay Exposure", "Reads each CA's InterfaceFlags value through certutil -getreg.", []string{"CA host: remote registry read of the CA InterfaceFlags value"}, []string{"SIEM: certutil -getreg against a CA from a non-administrative workstation"}),
		escStage("12", "CA Private Key Exposure", "Reads each CA's key provider name through certutil -getreg. No key material is accessed.", []string{"CA host: remote registry read of the CA CSP provider value"}, []string{"SIEM: certutil -getreg against a CA from a non-administrative workstation"}),
		escStage("13", "Issuance Policy / Group Mapping", "Reads template issuance policies, the issuance-policy (OID) objects with a group link, and the linked groups' privilege markers.", []string{ldapTel, "DC: LDAP read of msPKI-Enterprise-Oid objects and linked groups"}, []string{ldapDet}),
		escStage("14", "Weak Explicit Certificate Mapping", "Reads altSecurityIdentities and adminCount on enabled user and computer accounts.", []string{"DC: LDAP search of altSecurityIdentities"}, []string{"SIEM: bulk LDAP reads of altSecurityIdentities from a non-administrative workstation"}),
		escStage("15", "Schema Version 1 Template Abuse", "Reads template schema version, name flags, approval and RA-signature settings and the template ACL, and each publishing CA's Windows build (CurrentBuildNumber and UBR over remote registry) to compare with the CVE-2024-49019 fixed build.", []string{ldapTel}, []string{ldapDet}),
		{Number: "16", Title: "Certificate Publication and Trust", Technique: "T1649", Tag: "BAS-SIM-ADCS-PUB", Call: "$script:AdcsCaFields = @()\nInvoke-AdcsPublicationStage", Regions: []string{"publication"}, Timeout: 120,
			Blast:     "Reads which templates each CA publishes, the certificates in NTAuthCertificates and each CA certificate's key size, signature algorithm and expiry." + readOnly,
			Telemetry: []string{ldapTel, "DC: LDAP read of the cACertificate attribute of NTAuthCertificates and the Enrollment Services objects"},
			Detection: []string{ldapDet}},
		{Number: "17", Title: "Privileged Identity Correlation", Technique: "T1649", Tag: "BAS-SIM-ADCS-CORR", Call: "$script:AdcsCaFields = @('editFlags', 'interfaceFlags', 'keyProvider', 'caAces', 'web', 'build')\nInvoke-AdcsCorrelationStage", Regions: []string{"correlate"}, Timeout: 240,
			Blast:     "Reads everything the earlier stages read, then joins it: a misconfiguration becomes an exploitable certificate-issuance path only when the template is published on a readable CA and a low-privileged principal can enrol." + readOnly,
			Telemetry: []string{ldapTel, "CA host: remote registry reads of the policy and Security values"},
			Detection: []string{ldapDet}},
	}
}

func jq(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s)
	return strings.TrimRight(b.String(), "\n")
}

const description = `Enterprise Active Directory Certificate Services (AD CS) assessment (T1649). Eighteen read-only stages build the AD CS context, assess each escalation class ESC1 to ESC15 on its own evidence, check certificate publication and trust, and then correlate the findings into exploitable certificate-issuance paths from low-privileged principals to privileged identities. ESC numbering alone is not proof of coverage: every stage says what it could and could not read.

Stages:
  0   Build AD CS audit context: CAs, templates, enrollment services, forest. Context only; not scored.
  1   ESC1 misconfigured SAN: enrollee-supplied subject with an authentication EKU
  2   ESC2 Any Purpose or no EKU
  3   ESC3 enrollment agent
  4   ESC4 template ACL exposure
  5   ESC5 PKI object ACL exposure: NTAuth, CA, OID and PKI containers
  6   ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA
  7   ESC7 CA administrative rights: ManageCA and ManageCertificates
  8   ESC8 web enrollment relay exposure (live check, off by default)
  9   ESC9 no security extension
  10  ESC10 weak certificate mapping on domain controllers
  11  ESC11 RPC enrollment relay exposure
  12  ESC12 CA private key protection
  13  ESC13 issuance policy to group mapping
  14  ESC14 weak explicit certificate mapping
  15  ESC15 schema version 1 template abuse: checked against the CA Windows build (CVE-2024-49019 fix)
  16  Certificate publication and trust: published templates, CA certificates, NTAuth
  17  Privileged identity correlation: paths from low-privileged principals to privileged certificate issuance

How findings are classified:
  CONFIRMED     the misconfiguration is present in what was read
  PATH          an exploitable certificate-issuance path: confirmed, on a published template or readable CA
  POTENTIAL     an exposure that needs live verification; never counted as clean
  INSUFFICIENT  the object could not be read (missing LDAP permission, unreachable CA); never counted as clean
  PASS only when every source the stage needs was read and nothing was found.

Every finding is written as: low-privileged principal -> enrollment permission -> vulnerable template or CA -> issuance conditions -> privileged identity impact.

Live check: ESC8 sends one unauthenticated HTTP GET per CA only when BAS_ADCS_LIVE_PROBE=true. Without it, each CA is reported as POTENTIAL.
Not assessed: whether a relay or enrollment would succeed, HTTPS Extended Protection, HSM assurance and CA enrollment-agent restrictions. Patch levels are matched by Windows build only for the server versions named in the ESC10 and ESC15 stages; any other build is reported as needing live verification.
SAFETY: reads configuration only. Never requests or enrols a certificate, never modifies a template, CA object or CA setting, never performs certificate-based impersonation. A FAIL shows configuration exposure or an issuance path, not that a certificate was obtained.`

var tags = []string{"adcs", "active-directory", "certificate-templates", "privilege-escalation", "t1649", "mitre", "esc1", "esc2", "esc3", "esc4", "esc5", "esc6", "esc7", "esc8", "esc9", "esc10", "esc11", "esc12", "esc13", "esc14", "esc15", "attack-path", "enterprise"}

// Generate returns the scenario YAML. It is deterministic: the same library and table always give the same bytes.
func Generate() ([]byte, error) {
	var b strings.Builder
	b.WriteString("# GENERATED by cmd/gen-adcs-scenario from internal/adcsaudit (lib.ps1 and gen.go). Do not edit by hand; re-sign after regenerating.\n")
	b.WriteString("id: adcs-esc-template-exposure-audit\nproduct_line: ad\n")
	b.WriteString("name: " + jq("ADCS ESC Template Exposure Audit") + "\n")
	b.WriteString("description: |\n")
	for _, l := range strings.Split(description, "\n") {
		if l == "" {
			b.WriteString("\n")
		} else {
			b.WriteString("  " + l + "\n")
		}
	}
	b.WriteString("author: Audspect Research\nexecutable: true\nlocal_check: false\nsupported_os: [windows]\ntags:\n")
	for _, t := range tags {
		b.WriteString("  - " + t + "\n")
	}
	b.WriteString("mitre_phases:\n  - discovery\n  - privilege-escalation\n\n")
	b.WriteString("live_policy:\n  block_on_domain_controller: false\n  require_dc_reachable: true\n  max_spray_attempts: 0\n  spray_account_allowlist: []\n  execution_window: \"\"\n\n")
	b.WriteString("steps:\n")
	for _, s := range Stages() {
		lib, err := Library(s.Regions...)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "  # %s\n", strings.Repeat("-", 73))
		fmt.Fprintf(&b, "  # Stage %s\n", s.Number)
		fmt.Fprintf(&b, "  # %s\n", strings.Repeat("-", 73))
		fmt.Fprintf(&b, "  - name: %s\n", jq(fmt.Sprintf("ADCS Stage %s — %s (%s)", s.Number, s.Title, s.Technique)))
		fmt.Fprintf(&b, "    technique_id: %s\n    framework: custom\n    executor: powershell\n    requires_priv: user\n", s.Technique)
		fmt.Fprintf(&b, "    timeout_sec: %d\n    fidelity: telemetry-safe\n    production_safe: true\n    risk: low\n    reversible: true\n", s.Timeout)
		fmt.Fprintf(&b, "    blast_radius: %s\n", jq(s.Blast))
		b.WriteString("    telemetry:\n")
		for _, t := range s.Telemetry {
			b.WriteString("      - " + jq(t) + "\n")
		}
		b.WriteString("    detection:\n")
		for _, t := range s.Detection {
			b.WriteString("      - " + jq(t) + "\n")
		}
		b.WriteString("    command: |\n")
		body := "$ErrorActionPreference = 'SilentlyContinue'\n" + lib + "\n" + s.Call
		for _, l := range strings.Split(body, "\n") {
			if strings.TrimSpace(l) == "" {
				b.WriteString("\n")
			} else {
				b.WriteString("      " + l + "\n")
			}
		}
		b.WriteString("    cleanup: \"\"\n\n")
	}
	return []byte(strings.TrimRight(b.String(), "\n") + "\n"), nil
}

// StageNumbers lists the stage numbers in order, for tests.
func StageNumbers() []string {
	var n []string
	for _, s := range Stages() {
		n = append(n, s.Number)
	}
	return n
}
