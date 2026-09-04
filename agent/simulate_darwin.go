//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ── macOS Helpers ─────────────────────────────────────────────────────────────

// cmdOut runs a command and returns trimmed combined stdout (stderr ignored).
func cmdOut(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// readDefaults reads a value from a macOS plist via the `defaults` tool.
func readDefaults(domain, key string) (string, error) {
	return cmdOut("defaults", "read", domain, key)
}

// ── All Checks Entry Point ──────────────────────────────────────────────────

func RunAllChecks() []SimCategory {
	return safeSimChecks()
}

// knownPostureScenarios lists the scenario IDs this Darwin/macOS agent build
// handles via RunScenarioChecks. Keep in sync with the switch cases below.
func knownPostureScenarios() []string {
	return []string{
		"safe-simulation", "apt36-spearphish", "apt36-kill-chain",
		"ransomware-drill", "ad-credential-access", "upi-fraud-killchain",
		"cscrf-mii-drill", "purplesharp-ad-drill", "lolbin-execution",
		"lolbin-execution-coverage",
	}
}

func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "safe-simulation":
		return safeSimChecks()
	case "apt36-spearphish":
		return apt36Checks()
	case "apt36-kill-chain":
		return apt36KillChainChecks()
	case "ransomware-drill":
		return ransomwareChecks()
	case "ad-credential-access":
		return adCredentialChecks()
	case "upi-fraud-killchain":
		return upiChecks()
	case "cscrf-mii-drill":
		return cscrfChecks()
	case "purplesharp-ad-drill":
		return purpleSharpADChecks()
	case "lolbin-execution":
		return notApplicableWindows("LOLBin Execution drill", "T1218", "execution")
	case "lolbin-execution-coverage":
		return notApplicableWindows("LOLBin Execution Coverage", "T1218", "execution")
	default:
		return safeSimChecks()
	}
}

// notApplicableWindows returns a single skipped result for Windows-only
// scenarios run against a macOS host.
func notApplicableWindows(name, techID, tactic string) []SimCategory {
	return []SimCategory{{Phase: tactic, Checks: []SimCheck{
		check(techID, name, tactic, "Low",
			name+" targets Windows endpoints.",
			"Run this scenario against a Windows host.",
			func() (string, string) {
				return "skipped", name + " is Windows-only — not applicable on macOS."
			})}}}
}

// ── Scenario-specific macOS check sets ────────────────────────────────────────
// The YAML steps describe Windows TTPs; on macOS we test the equivalent control
// surface for the same tactic. All checks are read-only.

// apt36-spearphish — phishing payload delivery, execution, persistence, C2 egress.
func apt36Checks() []SimCategory {
	return []SimCategory{
		{Phase: "initial-access", Checks: []SimCheck{
			checkGatekeeper(),
			checkAssessmentPolicy(),
		}},
		{Phase: "execution", Checks: []SimCheck{
			checkXProtect(),
		}},
		{Phase: "persistence", Checks: []SimCheck{
			checkLaunchAgents(),
		}},
		{Phase: "command-and-control", Checks: []SimCheck{
			checkApplicationFirewall(),
		}},
	}
}

// apt36KillChainChecks is apt36-kill-chain's macOS posture bundle. The
// three-tier rewrite only ever implemented real checks for Windows --
// apt36-kill-chain fell back to notApplicableWindows() on macOS, silently
// dropping apt36Checks()'s real coverage above whenever the legacy scenario
// (apt36-spearphish.yaml) is eventually retired. Migrated 2026-08-26: same
// checks, same functions, no new implementations.
func apt36KillChainChecks() []SimCategory {
	return apt36Checks()
}

// purpleSharpADChecks is purplesharp-ad-drill's macOS posture bundle -- same
// migration as apt36KillChainChecks above, for ad-credential-access.yaml's
// macOS coverage.
func purpleSharpADChecks() []SimCategory {
	return adCredentialChecks()
}

// ransomware-drill — defence evasion / system integrity, data-at-rest impact.
func ransomwareChecks() []SimCategory {
	return []SimCategory{
		{Phase: "defense-evasion", Checks: []SimCheck{
			checkSIP(),
			checkSIPEnforcement(),
			checkXProtect(),
		}},
		{Phase: "impact", Checks: []SimCheck{
			checkFileVault(),
			checkApplicationFirewall(),
		}},
	}
}

// ad-credential-access — credential store theft and lateral movement.
func adCredentialChecks() []SimCategory {
	return []SimCategory{
		{Phase: "credential-access", Checks: []SimCheck{
			checkKeychainLock(),
			checkFileVault(),
		}},
		{Phase: "lateral-movement", Checks: []SimCheck{
			checkSSHRemoteLogin(),
			checkScreenSharing(),
		}},
	}
}

// upi-fraud-killchain — credential harvest, remote collection, exfiltration.
func upiChecks() []SimCategory {
	return []SimCategory{
		{Phase: "credential-access", Checks: []SimCheck{
			checkKeychainLock(),
		}},
		{Phase: "collection", Checks: []SimCheck{
			checkScreenSharing(),
			checkSSHRemoteLogin(),
		}},
		{Phase: "exfiltration", Checks: []SimCheck{
			checkApplicationFirewall(),
		}},
	}
}

// cscrf-mii-drill — SEBI CSCRF five control domains mapped to macOS controls.
func cscrfChecks() []SimCategory {
	return []SimCategory{
		{Phase: "network-security", Checks: []SimCheck{
			checkApplicationFirewall(),
			checkGatekeeper(),
		}},
		{Phase: "access-management", Checks: []SimCheck{
			checkSSHRemoteLogin(),
			checkScreenSharing(),
		}},
		{Phase: "data-security", Checks: []SimCheck{
			checkFileVault(),
			checkKeychainLock(),
		}},
		{Phase: "monitoring-detection", Checks: []SimCheck{
			checkSIP(),
			checkXProtect(),
		}},
	}
}

// safeSimChecks is the macOS read-only security posture simulation. Every check
// inspects configuration via built-in tools (spctl, csrutil, fdesetup,
// socketfilterfw, launchctl, sshd_config). Nothing on the endpoint is modified.
func safeSimChecks() []SimCategory {
	base := []SimCategory{
		{Phase: "defense-evasion", Checks: []SimCheck{
			checkGatekeeper(),
			checkSIP(),
			checkXProtect(),
		}},
		{Phase: "credential-access", Checks: []SimCheck{
			checkFileVault(),
			checkKeychainLock(),
		}},
		{Phase: "execution", Checks: []SimCheck{
			checkAssessmentPolicy(),
		}},
		{Phase: "persistence", Checks: []SimCheck{
			checkLaunchAgents(),
		}},
		{Phase: "privilege-escalation", Checks: []SimCheck{
			checkSIPEnforcement(),
		}},
		{Phase: "lateral-movement", Checks: []SimCheck{
			checkSSHRemoteLogin(),
			checkScreenSharing(),
		}},
		{Phase: "impact", Checks: []SimCheck{
			checkApplicationFirewall(),
			checkFirewallStealth(),
		}},
	}
	// Section A of the POSIX posture coverage map: macOS equivalents of checks
	// the Linux agent already runs. Kept in simulate_mac_checks.go and appended
	// here so this list stays the single place that says what a macOS
	// assessment covers.
	base = append(base, macSectionAChecks()...)
	return append(base, macSectionBChecks()...)
}

// ── Defense Evasion ─────────────────────────────────────────────────────────

func checkGatekeeper() SimCheck {
	return check("T1562.001", "Gatekeeper Assessment", "defense-evasion", "High",
		"With Gatekeeper disabled, unsigned and unnotarised applications execute without warning, allowing malware delivery.",
		"Enable Gatekeeper: sudo spctl --master-enable",
		func() (string, string) {
			out, err := cmdOut("spctl", "--status")
			if err != nil {
				return "skipped", "Could not query Gatekeeper status (spctl unavailable)."
			}
			if strings.Contains(strings.ToLower(out), "assessments enabled") {
				return "pass", "Gatekeeper is enabled — unsigned applications are blocked."
			}
			return "fail", "Gatekeeper is DISABLED — unsigned/unnotarised apps can run freely."
		})
}

func checkSIP() SimCheck {
	return check("T1562.001", "System Integrity Protection (SIP)", "defense-evasion", "Critical",
		"Disabled SIP allows attackers to modify protected system files, load unsigned kexts, and disable security tooling.",
		"Enable SIP from Recovery: csrutil enable",
		func() (string, string) {
			out, err := cmdOut("csrutil", "status")
			if err != nil {
				return "skipped", "Could not query SIP status (csrutil unavailable)."
			}
			if strings.Contains(strings.ToLower(out), "enabled") {
				return "pass", "System Integrity Protection is enabled."
			}
			return "fail", "System Integrity Protection is DISABLED — system files and security tooling are modifiable."
		})
}

func checkXProtect() SimCheck {
	return check("T1562.001", "XProtect Malware Definitions", "defense-evasion", "Medium",
		"Outdated or absent XProtect definitions reduce built-in malware detection coverage.",
		"Ensure XProtect is present and updated via Software Update.",
		func() (string, string) {
			info := "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
			if _, err := os.Stat(info); err != nil {
				legacy := "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
				if _, err2 := os.Stat(legacy); err2 != nil {
					return "fail", "XProtect bundle not found — built-in malware signatures missing."
				}
			}
			return "pass", "XProtect malware definition bundle is present."
		})
}

// ── Credential Access ───────────────────────────────────────────────────────

func checkFileVault() SimCheck {
	return check("T1003", "FileVault Disk Encryption", "credential-access", "High",
		"Without FileVault, an attacker with physical access can read the disk — including credential stores and keychains — offline.",
		"Enable FileVault: System Settings → Privacy & Security → FileVault → Turn On.",
		func() (string, string) {
			out, err := cmdOut("fdesetup", "status")
			if err != nil {
				return "skipped", "Could not query FileVault status (fdesetup unavailable)."
			}
			if strings.Contains(strings.ToLower(out), "filevault is on") {
				return "pass", "FileVault full-disk encryption is ON."
			}
			return "fail", "FileVault is OFF — disk contents readable offline with physical access."
		})
}

func checkKeychainLock() SimCheck {
	return check("T1555.001", "Keychain Auto-Lock", "credential-access", "Medium",
		"A keychain that never locks leaves stored credentials accessible to any process while the session is active.",
		"Configure keychain to lock on sleep: Keychain Access → Edit → Change Settings.",
		func() (string, string) {
			out, err := cmdOut("security", "show-keychain-info")
			if err != nil {
				return "skipped", "Could not read keychain lock settings."
			}
			lower := strings.ToLower(out)
			if strings.Contains(lower, "lock-on-sleep") || strings.Contains(lower, "timeout") {
				return "pass", "Login keychain is configured to lock automatically."
			}
			return "fail", "Login keychain has no auto-lock — stored credentials remain unlocked during the session."
		})
}

// ── Execution ───────────────────────────────────────────────────────────────

func checkAssessmentPolicy() SimCheck {
	return check("T1059", "Code Execution Assessment Policy", "execution", "High",
		"Permissive assessment policy allows arbitrary downloaded binaries to execute without signature validation.",
		"Keep Gatekeeper assessment enabled so execution requires valid Developer ID signing or notarisation.",
		func() (string, string) {
			out, err := cmdOut("spctl", "--status")
			if err != nil {
				return "skipped", "Could not evaluate assessment policy (spctl unavailable)."
			}
			if strings.Contains(strings.ToLower(out), "assessments enabled") {
				return "pass", "Execution assessment enabled — only signed/notarised code runs without prompt."
			}
			return "fail", "Execution assessment disabled — unsigned binaries execute without validation."
		})
}

// ── Persistence ─────────────────────────────────────────────────────────────

func checkLaunchAgents() SimCheck {
	return check("T1547.011", "LaunchAgents Persistence Surface", "persistence", "Medium",
		"Attackers drop plists into LaunchAgents/LaunchDaemons to persist across reboots and logins.",
		"Audit /Library/LaunchAgents and /Library/LaunchDaemons against a known-good baseline.",
		func() (string, string) {
			dirs := []string{"/Library/LaunchAgents", "/Library/LaunchDaemons"}
			total := 0
			for _, d := range dirs {
				entries, err := os.ReadDir(d)
				if err != nil {
					continue
				}
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".plist") {
						total++
					}
				}
			}
			// Read-only inventory — informational, never a hard fail.
			return "pass", fmt.Sprintf("%d launch item(s) present in system LaunchAgents/LaunchDaemons — review against baseline.", total)
		})
}

// ── Privilege Escalation ──────────────────────────────────────────────────────

func checkSIPEnforcement() SimCheck {
	return check("T1548", "SIP Filesystem Enforcement", "privilege-escalation", "High",
		"Without SIP, a local attacker with admin rights can overwrite protected binaries to escalate to root persistently.",
		"Enable SIP from Recovery mode: csrutil enable.",
		func() (string, string) {
			out, err := cmdOut("csrutil", "status")
			if err != nil {
				return "skipped", "Could not query SIP enforcement (csrutil unavailable)."
			}
			if strings.Contains(strings.ToLower(out), "enabled") {
				return "pass", "SIP enforces protection on system binaries and directories."
			}
			return "fail", "SIP disabled — protected system binaries can be overwritten for privilege escalation."
		})
}

// ── Lateral Movement ──────────────────────────────────────────────────────────

func checkSSHRemoteLogin() SimCheck {
	return check("T1021.004", "SSH Remote Login", "lateral-movement", "Medium",
		"Remote Login (SSH) exposes an interactive entry point used for lateral movement if credentials are compromised.",
		"Disable if unused: System Settings → General → Sharing → Remote Login. Otherwise enforce key-based auth.",
		func() (string, string) {
			out, _ := cmdOut("systemsetup", "-getremotelogin")
			lower := strings.ToLower(out)
			if strings.Contains(lower, "off") {
				return "pass", "Remote Login (SSH) is OFF — no interactive SSH entry point exposed."
			}
			if strings.Contains(lower, "on") {
				// Check password auth in sshd_config
				if data, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil {
					if strings.Contains(strings.ToLower(string(data)), "passwordauthentication no") {
						return "pass", "Remote Login is ON but password auth is disabled — key-based only."
					}
				}
				return "fail", "Remote Login (SSH) is ON with password authentication — exposed to credential-based lateral movement."
			}
			return "skipped", "Could not determine Remote Login state (requires admin)."
		})
}

func checkScreenSharing() SimCheck {
	return check("T1021.005", "Screen Sharing / Remote Management", "lateral-movement", "Medium",
		"Enabled Screen Sharing or ARD provides a remote GUI entry point usable for lateral movement.",
		"Disable if unused: System Settings → General → Sharing → Screen Sharing / Remote Management.",
		func() (string, string) {
			out, err := cmdOut("launchctl", "list")
			if err != nil {
				return "skipped", "Could not enumerate launchd services."
			}
			lower := strings.ToLower(out)
			if strings.Contains(lower, "screensharing") || strings.Contains(lower, "com.apple.rfb") {
				return "fail", "Screen Sharing / Remote Management is active — remote GUI entry point exposed."
			}
			return "pass", "Screen Sharing and Remote Management are not active."
		})
}

// ── Impact ──────────────────────────────────────────────────────────────────

func checkApplicationFirewall() SimCheck {
	return check("T1562.004", "Application Layer Firewall", "impact", "Medium",
		"A disabled firewall allows unsolicited inbound connections, expanding attack surface for ransomware delivery and C2.",
		"Enable the firewall: System Settings → Network → Firewall → On.",
		func() (string, string) {
			out, err := cmdOut("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
			if err != nil {
				// Fall back to defaults read
				v, derr := readDefaults("/Library/Preferences/com.apple.alf", "globalstate")
				if derr != nil {
					return "skipped", "Could not query Application Firewall state."
				}
				if v == "1" || v == "2" {
					return "pass", fmt.Sprintf("Application Firewall enabled (globalstate=%s).", v)
				}
				return "fail", "Application Firewall is DISABLED (globalstate=0)."
			}
			if strings.Contains(strings.ToLower(out), "enabled") {
				return "pass", "Application Layer Firewall is enabled."
			}
			return "fail", "Application Layer Firewall is DISABLED — unsolicited inbound connections permitted."
		})
}
