package reporting

import (
	"strings"

	"github.com/audspect/bas/internal/models"
)

// AppControlSection is the Application Control Efficacy section of a run
// report. It is built from one run's own results and is hidden when the run
// contains no application-control steps.
//
// Prevention (Outcome) and telemetry visibility are separate fields on every
// row. Families that were not run, were not applicable, or produced no
// structured evidence are listed as such and are never shown as passing.
type AppControlSection struct {
	HasData bool   `json:"hasData"`
	RunID   string `json:"runId"`
	// Hostname labels the section in a campaign report, where several runs
	// appear. It is empty for a single-run report.
	Hostname    string                   `json:"hostname,omitempty"`
	Rows        []AppControlRow          `json:"rows"`
	Families    []AppControlFamilyStatus `json:"families"`
	Limitations []string                 `json:"limitations"`
}

// AppControlRow is one evaluated path: prevention outcome and telemetry
// visibility as independent facts.
type AppControlRow struct {
	StepName  string `json:"stepName"`
	Family    string `json:"family"`
	Technique string `json:"technique"`
	// Observed is what the step measured: the controlling collection's mode,
	// or for the in-process host, its language mode and Add-Type result.
	Observed string `json:"observed"`
	// Policy is the intended policy the verdict was judged against. Empty when
	// the family has no policy input. "not stated" when the family takes one and
	// none was given, which makes the verdict UNVERIFIED.
	Policy     string `json:"policy"`
	Outcome    string `json:"outcome"`
	Visibility string `json:"visibility"`
}

// AppControlFamilyStatus is the coverage state of one behavioral family in
// this run. Status is an observed outcome, or one of: not_run, unverified,
// inconclusive (conflicting outcomes within the run).
type AppControlFamilyStatus struct {
	Family string `json:"family"`
	Status string `json:"status"`
	Note   string `json:"note"`
}

const (
	appCtlStatusNotRun     = "not_run"
	appCtlStatusUnverified = "unverified"
)

// appCtlFamilyOrder fixes the order families appear in and the vocabulary a
// family can take in a report.
var appCtlFamilyOrder = []string{
	"indirect_execution", "alternate_binary", "script_host_proxy",
	"alternate_ps_host", "parent_child_asr", "inprocess_hosting",
}

// appCtlStepFamilies maps a step name prefix to its family. It is the fallback
// when a step produced no APPCTL_FAMILY line, so a step that ran with missing
// output still appears in the report as unverified.
var appCtlStepFamilies = map[string]string{
	"Application control indirect execution":    "indirect_execution",
	"Application control alternate binary":      "alternate_binary",
	"Application control script host proxy":     "script_host_proxy",
	"Application control alternate PowerShell":  "alternate_ps_host",
	"Application control parent-child ASR":      "parent_child_asr",
	"Application control in-process PowerShell": "inprocess_hosting",
}

// appCtlMasteryStepFamilies is the same fallback for the Application Control
// Mastery scenarios, keyed by exact step name. Generated from scenarios/appcontrol-*.yaml.
var appCtlMasteryStepFamilies = map[string]string{
	"Application control Advanced Loading: DLL resolved by name from the application directory (T1574.001)":                          "dll_search_order",
	"Application control Advanced Loading: COM scriptlet activation through scrobj.dll (T1546.015)":                                  "com_activation",
	"Application control Advanced Loading: program launched by a scheduled task (T1053.005)":                                         "scheduled_task_launch",
	"Application control Advanced Loading: program launched by the service manager (T1543.003)":                                      "service_launch",
	"Application control File Enforcement: unsigned executable (T1204.002)":                                                          "unsigned_executable",
	"Application control File Enforcement: signed binary with a corrupted signature (T1553.002)":                                     "tampered_signature",
	"Application control File Enforcement: executable signed by an untrusted self-signed publisher (T1553.002)":                      "publisher_trust",
	"Application control Location Enforcement: unsigned executable run from %TEMP% (T1204.002)":                                      "exec_from_temp",
	"Application control Location Enforcement: unsigned executable run from %APPDATA% (T1204.002)":                                   "exec_from_appdata",
	"Application control Location Enforcement: downloaded unsigned executable run from Downloads (T1204.002)":                        "exec_from_downloads",
	"Application control File Identity: executable renamed to a non-executable extension (T1036.008)":                                "renamed_extension",
	"Application control Module Enforcement: unsigned DLL loaded from a user-writable path (T1129)":                                  "dll_loading",
	"Application control Module Enforcement: module with an .ocx extension loaded from a user-writable path (T1129)":                 "ocx_module_loading",
	"Application control Installer Enforcement: MSI installed through the Windows Installer API (T1218.007)":                         "msi_installation",
	"Application control Operational Reliability: enforcement log channels are enabled and retained (T1562.002)":                     "enforcement_log_health",
	"Application control Operational Reliability: application identity service runs while AppLocker enforces (T1562.001)":            "identity_service_reliability",
	"Application control Operational Reliability: allow rules open to everyone over whole drives or user-writable paths (T1562.001)": "overbroad_allow_rules",
	"Application control Packaged App Rules: Appx collection enforcement posture (T1553)":                                            "packaged_app_rules",
	"Application control Packaged App Trust: sideloading and developer mode while enforcing (T1553)":                                 "sideloading_policy",
	"Application control Installer Trust: AlwaysInstallElevated bypass (T1548)":                                                      "always_install_elevated",
	"Application control Trusted Location Trust: user-writable directories under the Windows directory (T1553)":                      "writable_allowed_paths",
	"Application control Policy Integrity: application control service tamper resistance (T1562.001)":                                "policy_service_interruption",
	"Application control Policy Integrity: local AppLocker policy modification (T1562.001)":                                          "policy_modification",
	"Application control Policy Integrity: audit-mode or missing-collection downgrade (T1562.001)":                                   "policy_downgrade",
	"Application control Policy Integrity: WDAC active policy directory trust boundary (T1562.001)":                                  "supplemental_policy",
	"Application control Policy Integrity: Managed Installer rules that trust user-writable paths (T1553)":                           "managed_installer",
	"Application control Policy Integrity: evidence that enforcement survives a reboot (T1562.001)":                                  "policy_after_reboot",
	"Application control Policy Integrity: policy drift against an approved baseline (T1562.001)":                                    "policy_lifecycle",
	"Application control Trusted Binary Proxy: Regsvr32 scriptlet execution (T1218.010)":                                             "regsvr32_proxy",
	"Application control Trusted Binary Proxy: Rundll32 INF execution through advpack (T1218.011)":                                   "rundll32_proxy",
	"Application control Trusted Binary Proxy: Mshta HTA and script execution (T1218.005)":                                           "mshta_proxy",
	"Application control Trusted Binary Proxy: Msiexec package execution (T1218.007)":                                                "msiexec_proxy",
	"Application control Trusted Binary Proxy: InstallUtil assembly execution (T1218.004)":                                           "installutil_proxy",
	"Application control Trusted Binary Proxy: Control Panel applet (CPL) loaded from a user-writable path (T1218.002)":              "control_panel_cpl",
	"Application control Trusted Binary Proxy: CMSTP INF execution (T1218.003)":                                                      "cmstp_proxy",
	"Application control Trusted Binary Proxy: XSL script processing through WMIC (T1220)":                                           "xsl_script_processing",
	"Application control Trusted Developer Utility: MSBuild inline task execution (T1127.001)":                                       "msbuild_proxy",
	"Application control Script Host: wscript.exe VBScript from a user-writable path (T1059.005)":                                    "wscript_host",
	"Application control Script Host: cmd.exe batch file from a user-writable path (T1059.003)":                                      "cmd_batch_script",
	"Application control Script Host: Windows Script File (.wsf) through cscript.exe (T1059.005)":                                    "wsf_script_host",
	"Application control Script Host: JScript from a user-writable path (T1059.007)":                                                 "user_writable_script_host",
	"Application control PowerShell: unsigned script from a user-writable path (T1059.001)":                                          "powershell_script_signing",
	"Application control PowerShell: language mode of a script from a user-writable path (T1059.001)":                                "powershell_language_mode",
	"Application control WMI: Win32_Process.Create launching a benign command (T1047)":                                               "wmi_process_create",
	"Application control Interpreters: an already-installed alternate interpreter (T1059)":                                           "alternate_interpreters",
}

// appCtlLimitations is stated in every section that has data. These are
// report-level facts, not footnotes: a passing fixture or a stubbed test is
// never evidence that a live control enforces.
var appCtlLimitations = []string{
	"Live AppLocker and ASR enforcement is verified only where this run executed on a host with those controls configured and enforced. Fixture tests that validate the report code are not evidence of enforcement.",
	"The in-process PowerShell host test measures the language mode and Add-Type result of a custom host. Its telemetry visibility is recorded from ScriptBlock logging (event 4104) only where that logging is enabled by policy; otherwise visibility is unknown. The test does not establish AMSI coverage.",
	"Telemetry visibility records whether Sysmon process-creation telemetry saw the attempt. It is not a prevention verdict and not a security-product detection verdict. Not visible does not mean the attempt did not happen.",
	"Vendor-specific correlation (Microsoft Defender, SentinelOne) is not included and remains unverified until tested against a configured tenant.",
	"Results hold only for the tested Windows build, policy version, and execution path. Families not run, not applicable, or unverified are not reported as passing.",
}

// buildAppControlSection builds the section from one run's results. The caller
// passes only that run's results, so every row maps to runID.
func buildAppControlSection(runID string, results []models.SimulationResult) AppControlSection {
	sec := AppControlSection{RunID: runID, Limitations: appCtlLimitations}
	perFamily := map[string][]string{} // family -> outcomes observed in the run
	unverified := map[string]bool{}

	for _, r := range results {
		if !isAppControlResult(r) {
			continue
		}
		sec.HasData = true
		family := appCtlFamilyOf(r)
		outcome, ok := ParseAppControlOutcome(r.RawOutput)
		if !ok {
			unverified[family] = true
			continue
		}
		vis, _ := ParseAppControlVisibility(r.RawOutput)
		if vis == "" {
			vis = "unknown"
		}
		sec.Rows = append(sec.Rows, AppControlRow{
			StepName:   r.StepName,
			Family:     family,
			Technique:  r.Technique.ID,
			Observed:   ParseAppControlObserved(r.RawOutput),
			Policy:     appCtlPolicyFor(family, r.RawOutput),
			Outcome:    outcome,
			Visibility: vis,
		})
		perFamily[family] = append(perFamily[family], outcome)
	}

	for _, fam := range appCtlFamilyOrder {
		sec.Families = append(sec.Families, appCtlFamilyStatusFor(fam, perFamily[fam], unverified[fam]))
	}
	for _, fam := range appCtlMasteryFamilies {
		if len(perFamily[fam]) > 0 || unverified[fam] {
			sec.Families = append(sec.Families, appCtlFamilyStatusFor(fam, perFamily[fam], unverified[fam]))
		}
	}
	return sec
}

func appCtlFamilyStatusFor(family string, outcomes []string, unverified bool) AppControlFamilyStatus {
	switch {
	case len(outcomes) == 0 && unverified:
		return AppControlFamilyStatus{Family: family, Status: appCtlStatusUnverified,
			Note: "step ran without a structured APPCTL_OUTCOME; no verdict"}
	case len(outcomes) == 0:
		return AppControlFamilyStatus{Family: family, Status: appCtlStatusNotRun,
			Note: "no step for this family in this run"}
	}
	first := outcomes[0]
	for _, o := range outcomes[1:] {
		if o != first {
			return AppControlFamilyStatus{Family: family, Status: "inconclusive",
				Note: "conflicting outcomes within this run"}
		}
	}
	return AppControlFamilyStatus{Family: family, Status: first}
}

// isAppControlResult reports whether a result belongs to an application-control
// step, by its structured markers or by its step name.
func isAppControlResult(r models.SimulationResult) bool {
	if strings.Contains(r.RawOutput, "APPCTL_") {
		return true
	}
	return appCtlFamilyByStepName(r.StepName) != ""
}

func appCtlFamilyOf(r models.SimulationResult) string {
	if fam, ok := ParseAppControlFamily(r.RawOutput); ok {
		return fam
	}
	if fam := appCtlFamilyByStepName(r.StepName); fam != "" {
		return fam
	}
	return "unknown"
}

func appCtlFamilyByStepName(name string) string {
	for prefix, fam := range appCtlStepFamilies {
		if strings.HasPrefix(name, prefix) {
			return fam
		}
	}
	if fam, ok := appCtlMasteryStepFamilies[name]; ok {
		return fam
	}
	return ""
}
