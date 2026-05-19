package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// RunScenarioChecks returns checks scoped to a specific scenario ID.
// Falls back to cisUbuntuL1 for unknown IDs.
func RunScenarioChecks(scenarioID string) []SimCategory {
	switch scenarioID {
	case "cis-ubuntu-l1":
		return cisUbuntuL1()
	default:
		return cisUbuntuL1()
	}
}

func cisUbuntuL1() []SimCategory {
	return []SimCategory{
		kernelHardening(),
		filesystemHardening(),
		networkHardening(),
		sshHardening(),
		servicesChecks(),
		accessControlChecks(),
		securityToolsChecks(),
		passwordPolicyChecks(),
	}
}

// ── Kernel Hardening ──────────────────────────────────────────────────────────

func kernelHardening() SimCategory {
	return SimCategory{Phase: "kernel-hardening", Checks: []SimCheck{
		checkASLR(),
		checkCoreDumps(),
		checkPtraceScope(),
		checkNXBit(),
	}}
}

func checkASLR() SimCheck {
	return check("T1055", "ASLR Enabled (kernel.randomize_va_space)", "kernel-hardening", "High",
		"Without ASLR, attackers can predict memory addresses and reliably exploit memory corruption vulnerabilities.",
		"Set kernel.randomize_va_space = 2 in /etc/sysctl.d/99-cis.conf and run: sysctl --system",
		func() (string, string) {
			val := sysctl("kernel.randomize_va_space")
			switch val {
			case "2":
				return "pass", "kernel.randomize_va_space = 2 (full ASLR) — stack, heap, and mmap regions randomised."
			case "1":
				return "fail", "kernel.randomize_va_space = 1 (partial ASLR) — CIS requires value 2 for full randomisation."
			default:
				return "fail", fmt.Sprintf("kernel.randomize_va_space = %q — ASLR not fully enabled.", val)
			}
		})
}

func checkCoreDumps() SimCheck {
	return check("T1003", "Core Dumps Restricted (fs.suid_dumpable)", "kernel-hardening", "Medium",
		"Core dumps from SUID/SGID processes can leak sensitive memory contents including passwords and keys.",
		"Set fs.suid_dumpable = 0 in /etc/sysctl.d/99-cis.conf.",
		func() (string, string) {
			val := sysctl("fs.suid_dumpable")
			if val == "0" {
				return "pass", "fs.suid_dumpable = 0 — SUID process core dumps disabled."
			}
			return "fail", fmt.Sprintf("fs.suid_dumpable = %q — SUID processes may generate core dumps exposing credentials.", val)
		})
}

func checkPtraceScope() SimCheck {
	return check("T1055", "Ptrace Scope (kernel.yama.ptrace_scope)", "kernel-hardening", "High",
		"Unrestricted ptrace allows any process to read memory of other same-uid processes, enabling credential theft from running applications.",
		"Set kernel.yama.ptrace_scope = 1 in /etc/sysctl.d/99-cis.conf.",
		func() (string, string) {
			val := sysctl("kernel.yama.ptrace_scope")
			switch val {
			case "1":
				return "pass", "kernel.yama.ptrace_scope = 1 — ptrace restricted to parent/child relationships."
			case "2":
				return "pass", "kernel.yama.ptrace_scope = 2 — ptrace requires CAP_SYS_PTRACE capability."
			case "3":
				return "pass", "kernel.yama.ptrace_scope = 3 — ptrace fully disabled."
			case "0":
				return "fail", "kernel.yama.ptrace_scope = 0 — any process can ptrace any same-uid process (credential dumping possible)."
			default:
				return "fail", fmt.Sprintf("kernel.yama.ptrace_scope = %q — non-standard or unset.", val)
			}
		})
}

func checkNXBit() SimCheck {
	return check("T1055", "NX/Execute Disable Bit", "kernel-hardening", "High",
		"Without the NX bit, attackers inject shellcode into stack or heap and execute it directly.",
		"Enable NX in BIOS/UEFI settings. Verify with: grep -m1 ' nx ' /proc/cpuinfo",
		func() (string, string) {
			data, err := os.ReadFile("/proc/cpuinfo")
			if err != nil {
				return "skipped", "Could not read /proc/cpuinfo to verify NX bit."
			}
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "flags") || strings.HasPrefix(line, "Features") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						for _, flag := range strings.Fields(parts[1]) {
							if flag == "nx" {
								return "pass", "NX (No Execute) bit present in CPU flags — hardware DEP/XD enabled."
							}
						}
					}
					return "fail", "NX bit not found in CPU flags — execute-disable protection may be absent or BIOS-disabled."
				}
			}
			return "skipped", "Could not find CPU flags in /proc/cpuinfo."
		})
}

// ── Filesystem Hardening ──────────────────────────────────────────────────────

func filesystemHardening() SimCategory {
	return SimCategory{Phase: "filesystem", Checks: []SimCheck{
		checkTmpNoexec(),
		checkTmpNosuid(),
		checkTmpNodev(),
		checkShmNoexec(),
		checkShmNosuid(),
		checkWorldWritableStickyBit(),
	}}
}

func checkTmpNoexec() SimCheck {
	return check("T1059", "/tmp Mounted noexec", "filesystem", "High",
		"Without noexec on /tmp, attackers download and execute payloads (scripts, ELFs) directly from /tmp.",
		"Add noexec to /tmp in /etc/fstab, or override the systemd tmp.mount unit.",
		func() (string, string) {
			if mountHasOption("/tmp", "noexec") {
				return "pass", "/tmp mounted with noexec — script/binary execution from /tmp prevented."
			}
			return "fail", "/tmp does not have noexec mount option — attackers can execute payloads staged in /tmp."
		})
}

func checkTmpNosuid() SimCheck {
	return check("T1548", "/tmp Mounted nosuid", "filesystem", "High",
		"Without nosuid, SUID/SGID binaries placed in /tmp can be used for local privilege escalation.",
		"Add nosuid to /tmp in /etc/fstab.",
		func() (string, string) {
			if mountHasOption("/tmp", "nosuid") {
				return "pass", "/tmp mounted with nosuid — SUID privilege escalation from /tmp blocked."
			}
			return "fail", "/tmp lacks nosuid — SUID binaries planted in /tmp can escalate to root."
		})
}

func checkTmpNodev() SimCheck {
	return check("T1083", "/tmp Mounted nodev", "filesystem", "Medium",
		"Without nodev, device files in /tmp can be created to bypass device access controls.",
		"Add nodev to /tmp in /etc/fstab.",
		func() (string, string) {
			if mountHasOption("/tmp", "nodev") {
				return "pass", "/tmp mounted with nodev — device file creation in /tmp blocked."
			}
			return "fail", "/tmp lacks nodev — device files can be created in /tmp."
		})
}

func checkShmNoexec() SimCheck {
	return check("T1059", "/dev/shm Mounted noexec", "filesystem", "High",
		"Without noexec on /dev/shm, attackers execute memory-resident payloads from shared memory — common evasion technique.",
		"Add to /etc/fstab: none /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0",
		func() (string, string) {
			if mountHasOption("/dev/shm", "noexec") {
				return "pass", "/dev/shm mounted with noexec — shared memory execution attacks blocked."
			}
			return "fail", "/dev/shm lacks noexec — attackers can write and execute payloads from shared memory."
		})
}

func checkShmNosuid() SimCheck {
	return check("T1548", "/dev/shm Mounted nosuid", "filesystem", "High",
		"SUID files placed in /dev/shm can be used for privilege escalation via shared memory.",
		"Add nosuid to /dev/shm in /etc/fstab.",
		func() (string, string) {
			if mountHasOption("/dev/shm", "nosuid") {
				return "pass", "/dev/shm mounted with nosuid — SUID escalation via shared memory blocked."
			}
			return "fail", "/dev/shm lacks nosuid — SUID privilege escalation via shared memory is possible."
		})
}

func checkWorldWritableStickyBit() SimCheck {
	return check("T1083", "Sticky Bit on World-Writable Directories", "filesystem", "Medium",
		"World-writable directories without the sticky bit allow users to delete or rename other users' files — enabling denial-of-service and privilege escalation.",
		"Fix with: find / -xdev -type d -perm -0002 ! -perm -1000 -exec chmod +t {} \\;",
		func() (string, string) {
			out, err := exec.Command("find", "/", "-xdev", "-type", "d", "-perm", "-0002", "!", "-perm", "-1000").Output()
			if err != nil {
				return "skipped", "Could not check world-writable directories (may require elevated permissions)."
			}
			dirs := strings.TrimSpace(string(out))
			if dirs == "" {
				return "pass", "All world-writable directories have the sticky bit set."
			}
			lines := strings.Split(dirs, "\n")
			return "fail", fmt.Sprintf("%d world-writable director(ies) without sticky bit: %s", len(lines), dirs)
		})
}

// ── Network Hardening ─────────────────────────────────────────────────────────

func networkHardening() SimCategory {
	return SimCategory{Phase: "network", Checks: []SimCheck{
		checkIPForwarding(),
		checkICMPRedirectsAccepted(),
		checkICMPRedirectsSent(),
		checkMartianLogging(),
		checkSYNCookies(),
		checkIPv6RouterAdv(),
	}}
}

func checkIPForwarding() SimCheck {
	return check("T1090", "IP Forwarding Disabled (net.ipv4.ip_forward)", "network", "Medium",
		"IP forwarding enabled on non-router hosts allows traffic interception and network-layer MITM attacks.",
		"Set net.ipv4.ip_forward = 0 in /etc/sysctl.d/99-cis.conf.",
		func() (string, string) {
			val := sysctl("net.ipv4.ip_forward")
			if val == "0" {
				return "pass", "net.ipv4.ip_forward = 0 — host does not forward packets between interfaces."
			}
			return "fail", fmt.Sprintf("net.ipv4.ip_forward = %q — host is forwarding packets, enabling routing-based MITM.", val)
		})
}

func checkICMPRedirectsAccepted() SimCheck {
	return check("T1562", "ICMP Redirects Not Accepted", "network", "Medium",
		"Accepting ICMP redirects allows remote attackers to alter the host routing table for traffic interception.",
		"Set net.ipv4.conf.all.accept_redirects = 0 and net.ipv4.conf.default.accept_redirects = 0.",
		func() (string, string) {
			all := sysctl("net.ipv4.conf.all.accept_redirects")
			def := sysctl("net.ipv4.conf.default.accept_redirects")
			if all == "0" && def == "0" {
				return "pass", "ICMP redirects not accepted on any interface — routing table poisoning via ICMP blocked."
			}
			return "fail", fmt.Sprintf("ICMP redirects may be accepted (all=%s, default=%s) — routing table manipulation possible.", all, def)
		})
}

func checkICMPRedirectsSent() SimCheck {
	return check("T1562", "ICMP Redirects Not Sent", "network", "Medium",
		"Sending ICMP redirects discloses internal network topology and routing to adjacent attackers.",
		"Set net.ipv4.conf.all.send_redirects = 0 and net.ipv4.conf.default.send_redirects = 0.",
		func() (string, string) {
			all := sysctl("net.ipv4.conf.all.send_redirects")
			def := sysctl("net.ipv4.conf.default.send_redirects")
			if all == "0" && def == "0" {
				return "pass", "ICMP redirects not sent — network topology not disclosed via ICMP."
			}
			return "fail", fmt.Sprintf("ICMP redirects may be sent (all=%s, default=%s) — network topology disclosure possible.", all, def)
		})
}

func checkMartianLogging() SimCheck {
	return check("T1562", "Martian Packet Logging Enabled", "network", "Low",
		"Spoofed-source (martian) packets without logging cannot be detected or investigated after an attack.",
		"Set net.ipv4.conf.all.log_martians = 1 and net.ipv4.conf.default.log_martians = 1.",
		func() (string, string) {
			all := sysctl("net.ipv4.conf.all.log_martians")
			def := sysctl("net.ipv4.conf.default.log_martians")
			if all == "1" && def == "1" {
				return "pass", "Martian packet logging enabled on all interfaces — spoofed-source packets are logged."
			}
			return "fail", fmt.Sprintf("Martian logging incomplete (all=%s, default=%s) — IP spoofing attacks may go undetected.", all, def)
		})
}

func checkSYNCookies() SimCheck {
	return check("T1046", "TCP SYN Cookies Enabled (net.ipv4.tcp_syncookies)", "network", "Medium",
		"Without SYN cookies, a TCP SYN flood can exhaust the connection table and cause denial of service.",
		"Set net.ipv4.tcp_syncookies = 1 in /etc/sysctl.d/99-cis.conf.",
		func() (string, string) {
			val := sysctl("net.ipv4.tcp_syncookies")
			if val == "1" {
				return "pass", "net.ipv4.tcp_syncookies = 1 — SYN flood (DoS) protection enabled."
			}
			return "fail", fmt.Sprintf("net.ipv4.tcp_syncookies = %q — host is vulnerable to TCP SYN flood attacks.", val)
		})
}

func checkIPv6RouterAdv() SimCheck {
	return check("T1090", "IPv6 Router Advertisements Ignored", "network", "Medium",
		"Accepting IPv6 router advertisements allows rogue routers on the local segment to redirect IPv6 traffic.",
		"Set net.ipv6.conf.all.accept_ra = 0 and net.ipv6.conf.default.accept_ra = 0.",
		func() (string, string) {
			all := sysctl("net.ipv6.conf.all.accept_ra")
			def := sysctl("net.ipv6.conf.default.accept_ra")
			if all == "0" && def == "0" {
				return "pass", "IPv6 router advertisements ignored — rogue IPv6 router hijacking blocked."
			}
			return "fail", fmt.Sprintf("IPv6 RAs may be accepted (all=%s, default=%s) — rogue router traffic redirection possible.", all, def)
		})
}

// ── SSH Hardening ─────────────────────────────────────────────────────────────

func sshHardening() SimCategory {
	return SimCategory{Phase: "ssh-hardening", Checks: []SimCheck{
		checkSSHRootLogin(),
		checkSSHMaxAuthTries(),
		checkSSHEmptyPasswords(),
		checkSSHIgnoreRhosts(),
		checkSSHHostBasedAuth(),
		checkSSHPermitUserEnv(),
		checkSSHProtocol2(),
	}}
}

func checkSSHRootLogin() SimCheck {
	return check("T1078", "SSH Root Login Disabled (PermitRootLogin no)", "ssh-hardening", "Critical",
		"Direct root SSH access provides full system compromise without a user audit trail.",
		"Set PermitRootLogin no in /etc/ssh/sshd_config and run: systemctl restart sshd",
		func() (string, string) {
			val := sshConfigValue("PermitRootLogin")
			switch strings.ToLower(val) {
			case "no":
				return "pass", "PermitRootLogin no — direct root SSH login disabled."
			case "prohibit-password", "without-password":
				return "pass", fmt.Sprintf("PermitRootLogin = %s — root password login disabled (key-only). CIS recommends 'no'.", val)
			case "":
				return "fail", "PermitRootLogin not explicitly set — set to 'no' to ensure root login is blocked."
			default:
				return "fail", fmt.Sprintf("PermitRootLogin = %q — root SSH access permitted, full system compromise possible.", val)
			}
		})
}

func checkSSHMaxAuthTries() SimCheck {
	return check("T1110", "SSH MaxAuthTries <= 4", "ssh-hardening", "Medium",
		"A high MaxAuthTries allows brute-force attacks to test many passwords within a single SSH connection.",
		"Set MaxAuthTries 4 in /etc/ssh/sshd_config.",
		func() (string, string) {
			val := sshConfigValue("MaxAuthTries")
			if val == "" {
				return "fail", "MaxAuthTries not set — SSH default (6) allows too many brute-force attempts per connection."
			}
			n, err := strconv.Atoi(val)
			if err != nil {
				return "skipped", fmt.Sprintf("Could not parse MaxAuthTries = %q.", val)
			}
			if n <= 4 {
				return "pass", fmt.Sprintf("MaxAuthTries = %d — brute-force attempts per connection limited.", n)
			}
			return "fail", fmt.Sprintf("MaxAuthTries = %d (expected <= 4) — too many auth attempts per connection allowed.", n)
		})
}

func checkSSHEmptyPasswords() SimCheck {
	return check("T1110", "SSH Empty Passwords Forbidden (PermitEmptyPasswords no)", "ssh-hardening", "Critical",
		"Accounts with empty passwords can be accessed over SSH with no credential at all.",
		"Set PermitEmptyPasswords no in /etc/ssh/sshd_config.",
		func() (string, string) {
			val := sshConfigValue("PermitEmptyPasswords")
			if strings.ToLower(val) == "yes" {
				return "fail", "PermitEmptyPasswords yes — accounts with no password are accessible via SSH without any credential."
			}
			return "pass", "PermitEmptyPasswords no (or default) — empty-password SSH logins denied."
		})
}

func checkSSHIgnoreRhosts() SimCheck {
	return check("T1078", "SSH Ignores .rhosts Files (IgnoreRhosts yes)", "ssh-hardening", "High",
		".rhosts trust-based authentication allows host-identity bypass without password verification.",
		"Set IgnoreRhosts yes in /etc/ssh/sshd_config.",
		func() (string, string) {
			val := sshConfigValue("IgnoreRhosts")
			if strings.ToLower(val) == "no" {
				return "fail", "IgnoreRhosts no — .rhosts/.shosts trust files are processed, enabling host-trust authentication bypass."
			}
			return "pass", "IgnoreRhosts yes (or default) — .rhosts trust-based authentication ignored."
		})
}

func checkSSHHostBasedAuth() SimCheck {
	return check("T1078", "SSH Host-Based Authentication Disabled", "ssh-hardening", "High",
		"Host-based authentication trusts the source hostname rather than the user — enables lateral movement from any trusted host.",
		"Set HostbasedAuthentication no in /etc/ssh/sshd_config.",
		func() (string, string) {
			val := sshConfigValue("HostbasedAuthentication")
			if strings.ToLower(val) == "yes" {
				return "fail", "HostbasedAuthentication yes — SSH trusts source hosts, enabling lateral movement without user credentials."
			}
			return "pass", "HostbasedAuthentication no (or default) — host-trust SSH bypass disabled."
		})
}

func checkSSHPermitUserEnv() SimCheck {
	return check("T1548", "SSH User Environment Variables Forbidden", "ssh-hardening", "Medium",
		"User-controlled SSH environment variables can override PATH, LD_PRELOAD, and other critical settings to bypass restrictions.",
		"Set PermitUserEnvironment no in /etc/ssh/sshd_config.",
		func() (string, string) {
			val := sshConfigValue("PermitUserEnvironment")
			if strings.ToLower(val) == "yes" {
				return "fail", "PermitUserEnvironment yes — SSH users can set env variables including LD_PRELOAD, potentially bypassing security controls."
			}
			return "pass", "PermitUserEnvironment no (or default) — user-controlled SSH environment variables disabled."
		})
}

func checkSSHProtocol2() SimCheck {
	return check("T1110", "SSH Protocol 2 Only", "ssh-hardening", "High",
		"SSHv1 is vulnerable to man-in-the-middle attacks and credential interception.",
		"Ensure Protocol directive is absent (defaults to 2) or explicitly set to 2 in /etc/ssh/sshd_config.",
		func() (string, string) {
			val := sshConfigValue("Protocol")
			if val == "" {
				return "pass", "Protocol directive not configured — current OpenSSH uses Protocol 2 only (SSHv1 removed since 7.4)."
			}
			if val == "2" {
				return "pass", "SSH Protocol 2 explicitly set — SSHv1 disabled."
			}
			return "fail", fmt.Sprintf("SSH Protocol = %q — SSHv1 may be permitted.", val)
		})
}

// ── Services ──────────────────────────────────────────────────────────────────

func servicesChecks() SimCategory {
	return SimCategory{Phase: "services", Checks: []SimCheck{
		checkTelnetNotRunning(),
		checkRshRloginNotInstalled(),
		checkTFTPNotRunning(),
		checkSSHDRunning(),
	}}
}

func checkTelnetNotRunning() SimCheck {
	return check("T1078", "Telnet Not Installed/Running", "services", "Critical",
		"Telnet transmits all session data including passwords in cleartext — any network observer can capture credentials.",
		"Remove with: apt purge telnetd && systemctl disable --now telnet.socket",
		func() (string, string) {
			if serviceActive("telnet") || serviceActive("telnetd") || serviceActive("telnet.socket") {
				return "fail", "Telnet service is active — cleartext authentication and session data exposed on the network."
			}
			if packageInstalled("telnetd") || packageInstalled("telnet-server") || packageInstalled("inetutils-telnetd") {
				return "fail", "Telnet server package installed — remove with: apt purge telnetd."
			}
			return "pass", "Telnet not installed or active — cleartext remote access attack surface absent."
		})
}

func checkRshRloginNotInstalled() SimCheck {
	return check("T1078", "rsh/rlogin Services Not Installed", "services", "Critical",
		"rsh/rlogin provide unauthenticated remote access based on host-name trust — trivially exploitable on any network.",
		"Remove with: apt purge rsh-server rsh-client",
		func() (string, string) {
			if packageInstalled("rsh-server") || packageInstalled("rsh-client") {
				return "fail", "rsh/rlogin package(s) installed — host-trust unauthenticated remote access attack surface present."
			}
			if serviceActive("rsh") || serviceActive("rlogin") || serviceActive("rexec") {
				return "fail", "rsh/rlogin/rexec service active — insecure legacy remote shell enabled."
			}
			return "pass", "rsh/rlogin not installed or active — legacy insecure remote access absent."
		})
}

func checkTFTPNotRunning() SimCheck {
	return check("T1105", "TFTP Not Running", "services", "High",
		"TFTP has no authentication — any host can download or upload files if the service is running.",
		"Remove with: apt purge tftpd-hpa atftpd",
		func() (string, string) {
			if serviceActive("tftpd-hpa") || serviceActive("atftpd") || serviceActive("tftp") {
				return "fail", "TFTP service is active — unauthenticated file transfer enabled."
			}
			if packageInstalled("tftpd-hpa") || packageInstalled("atftpd") {
				return "fail", "TFTP server package installed — remove with: apt purge tftpd-hpa atftpd."
			}
			return "pass", "TFTP not installed or active — unauthenticated file transfer attack surface absent."
		})
}

func checkSSHDRunning() SimCheck {
	return check("T1078", "SSH Daemon Running (sshd)", "services", "High",
		"SSH daemon must be running and enabled for secure remote administration access.",
		"Enable and start: systemctl enable ssh --now",
		func() (string, string) {
			if serviceActive("ssh") || serviceActive("sshd") {
				return "pass", "SSH daemon is active — secure encrypted remote management available."
			}
			return "fail", "SSH daemon not active — secure remote management unavailable. Enable: systemctl enable ssh --now."
		})
}

// ── Access Control ────────────────────────────────────────────────────────────

func accessControlChecks() SimCategory {
	return SimCategory{Phase: "access-control", Checks: []SimCheck{
		checkCronAccess(),
		checkAuditdRunning(),
		checkRsyslogRunning(),
		checkJournaldPersistent(),
		checkLogFilesWorldReadable(),
	}}
}

func checkCronAccess() SimCheck {
	return check("T1053", "Cron Access Restricted to Authorised Users", "access-control", "Medium",
		"Unrestricted cron access allows any user to schedule persistent commands — a common privilege escalation path.",
		"Create /etc/cron.allow containing only authorised usernames (one per line).",
		func() (string, string) {
			if _, err := os.Stat("/etc/cron.allow"); err == nil {
				return "pass", "/etc/cron.allow exists — cron access limited to explicitly listed users."
			}
			if _, err := os.Stat("/etc/cron.deny"); err == nil {
				return "pass", "/etc/cron.deny exists — cron access restriction in place."
			}
			return "fail", "Neither /etc/cron.allow nor /etc/cron.deny exists — cron is unrestricted for all local users."
		})
}

func checkAuditdRunning() SimCheck {
	return check("T1070", "Auditd Running and Enabled", "access-control", "High",
		"Without auditd, file access, privilege escalation, and policy change events are not recorded — attackers operate undetected.",
		"Install and enable: apt install auditd && systemctl enable auditd --now",
		func() (string, string) {
			if serviceActive("auditd") && serviceEnabled("auditd") {
				return "pass", "auditd is running and enabled at boot — Linux kernel audit framework active."
			}
			if serviceActive("auditd") {
				return "fail", "auditd running but not enabled — will not start after reboot. Run: systemctl enable auditd."
			}
			return "fail", "auditd not running — security event auditing inactive. Install: apt install auditd."
		})
}

func checkRsyslogRunning() SimCheck {
	return check("T1070", "Rsyslog Running and Enabled", "access-control", "High",
		"Without a syslog daemon, auth, kernel, and daemon events are not captured for investigation.",
		"Enable: systemctl enable rsyslog --now",
		func() (string, string) {
			if serviceActive("rsyslog") && serviceEnabled("rsyslog") {
				return "pass", "rsyslog is running and enabled — system and auth event logging active."
			}
			if serviceActive("syslog") || serviceActive("syslog-ng") {
				return "pass", "Alternative syslog service active — system event logging active."
			}
			if serviceActive("systemd-journald") {
				return "pass", "systemd-journald active — events captured (rsyslog optional when journald persistence is configured)."
			}
			return "fail", "rsyslog not running — system and auth event logging may be inactive."
		})
}

func checkJournaldPersistent() SimCheck {
	return check("T1070", "Journald Persistent Storage Enabled", "access-control", "Medium",
		"Without persistent storage, all journal logs are lost on reboot — hindering incident response and forensics.",
		"Set Storage=persistent in /etc/systemd/journald.conf and restart: systemctl restart systemd-journald",
		func() (string, string) {
			data, err := os.ReadFile("/etc/systemd/journald.conf")
			if err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if line == "Storage=persistent" {
						return "pass", "journald Storage=persistent — logs written to /var/log/journal across reboots."
					}
					if line == "Storage=auto" {
						if _, err := os.Stat("/var/log/journal"); err == nil {
							return "pass", "journald Storage=auto with /var/log/journal present — persistent logging active."
						}
					}
				}
			}
			if _, err := os.Stat("/var/log/journal"); err == nil {
				return "pass", "/var/log/journal directory exists — journald persistent logging active."
			}
			return "fail", "Journald persistent storage not configured — logs lost on reboot. Set Storage=persistent in journald.conf."
		})
}

func checkLogFilesWorldReadable() SimCheck {
	return check("T1070", "Log Files Not World-Readable (/var/log)", "access-control", "Medium",
		"World-readable log files expose authentication attempts, sudo usage, and service errors to all local users.",
		"Remove world-read: find /var/log -type f -perm /o+r -exec chmod o-r {} \\;",
		func() (string, string) {
			out, err := exec.Command("find", "/var/log", "-type", "f", "-perm", "/o+r",
				"!", "-name", "*.gz", "-maxdepth", "4").Output()
			if err != nil {
				return "skipped", "Could not enumerate /var/log permissions."
			}
			files := strings.TrimSpace(string(out))
			if files == "" {
				return "pass", "No world-readable log files in /var/log — log access restricted to privileged users."
			}
			lines := strings.Split(files, "\n")
			return "fail", fmt.Sprintf("%d world-readable log file(s) in /var/log — auth and system events accessible to all local users.", len(lines))
		})
}

// ── Security Tools ────────────────────────────────────────────────────────────

func securityToolsChecks() SimCategory {
	return SimCategory{Phase: "security-tools", Checks: []SimCheck{
		checkUFWEnabled(),
		checkAppArmorEnforcing(),
	}}
}

func checkUFWEnabled() SimCheck {
	return check("T1046", "UFW Firewall Enabled", "security-tools", "High",
		"Without a host firewall, all listening services are reachable from the network — maximising attack surface.",
		"Enable UFW: ufw default deny incoming && ufw default allow outgoing && ufw enable",
		func() (string, string) {
			out, err := exec.Command("ufw", "status").Output()
			if err == nil {
				if strings.Contains(strings.ToLower(string(out)), "status: active") {
					return "pass", "UFW firewall is active — host-level packet filtering enabled."
				}
				return "fail", "UFW installed but inactive — host firewall disabled. Run: ufw enable."
			}
			// UFW not present — check iptables for a non-trivial ruleset
			iptOut, iptErr := exec.Command("iptables", "-L", "INPUT", "-n", "--line-numbers").Output()
			if iptErr == nil {
				lines := strings.Split(strings.TrimSpace(string(iptOut)), "\n")
				if len(lines) > 3 { // header + Chain + policy + at least one rule
					return "pass", "iptables INPUT rules present — custom firewall active (UFW not installed)."
				}
			}
			return "fail", "No host firewall detected (UFW not installed and no iptables rules) — all ports network-accessible."
		})
}

func checkAppArmorEnforcing() SimCheck {
	return check("T1068", "AppArmor Enabled and Enforcing", "security-tools", "High",
		"Without AppArmor, exploited processes run with full file system and capability access — no confinement.",
		"Enable and enforce: systemctl enable apparmor --now && aa-enforce /etc/apparmor.d/*",
		func() (string, string) {
			out, err := exec.Command("aa-status").Output()
			if err != nil {
				out, err = exec.Command("apparmor_status").Output()
			}
			if err != nil {
				if _, statErr := os.Stat("/sys/kernel/security/apparmor"); statErr == nil {
					return "pass", "AppArmor kernel module loaded (/sys/kernel/security/apparmor present)."
				}
				return "fail", "AppArmor not installed or not loaded — no mandatory access control protecting confined processes."
			}
			lower := strings.ToLower(string(out))
			if strings.Contains(lower, "apparmor module is loaded") {
				if strings.Contains(lower, "profiles are in enforce mode") && !strings.Contains(lower, "0 profiles are in enforce mode") {
					return "pass", "AppArmor loaded with profiles in enforce mode — mandatory access control active."
				}
				if strings.Contains(lower, "0 profiles are in enforce mode") {
					return "fail", "AppArmor loaded but no profiles in enforce mode — processes not confined, attacks not blocked."
				}
				return "pass", "AppArmor module loaded — verify profiles are enforcing with: aa-status."
			}
			return "fail", "AppArmor does not appear to be loaded — mandatory access control inactive."
		})
}

// ── Password Policy ───────────────────────────────────────────────────────────

func passwordPolicyChecks() SimCategory {
	return SimCategory{Phase: "password-policy", Checks: []SimCheck{
		checkPasswordMinLen(),
		checkPasswordMaxAge(),
		checkSudoLogged(),
		checkNoEmptyPasswords(),
	}}
}

func checkPasswordMinLen() SimCheck {
	return check("T1110", "Password Minimum Length >= 12 (PASS_MIN_LEN)", "password-policy", "High",
		"Short passwords are quickly cracked by dictionary and brute-force attacks against the system or its hash database.",
		"Set PASS_MIN_LEN 12 in /etc/login.defs. Also configure: minlen=12 in /etc/security/pwquality.conf.",
		func() (string, string) {
			// Check login.defs
			if data, err := os.ReadFile("/etc/login.defs"); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") {
						continue
					}
					if strings.HasPrefix(strings.ToUpper(line), "PASS_MIN_LEN") {
						fields := strings.Fields(line)
						if len(fields) >= 2 {
							if n, err := strconv.Atoi(fields[1]); err == nil {
								if n >= 12 {
									return "pass", fmt.Sprintf("PASS_MIN_LEN = %d in /etc/login.defs — meets 12-character minimum.", n)
								}
								return "fail", fmt.Sprintf("PASS_MIN_LEN = %d in /etc/login.defs — below the required 12-character minimum.", n)
							}
						}
					}
				}
			}
			// Check pam_pwquality
			if data, err := os.ReadFile("/etc/security/pwquality.conf"); err == nil {
				for _, line := range strings.Split(string(data), "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
						continue
					}
					parts := strings.SplitN(line, "=", 2)
					if strings.TrimSpace(parts[0]) == "minlen" {
						if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
							if n >= 12 {
								return "pass", fmt.Sprintf("pam_pwquality minlen = %d — meets 12-character minimum.", n)
							}
							return "fail", fmt.Sprintf("pam_pwquality minlen = %d — below the required 12-character minimum.", n)
						}
					}
				}
			}
			return "fail", "PASS_MIN_LEN not configured in /etc/login.defs or /etc/security/pwquality.conf — no password length enforcement."
		})
}

func checkPasswordMaxAge() SimCheck {
	return check("T1110", "Password Maximum Age <= 365 Days (PASS_MAX_DAYS)", "password-policy", "Medium",
		"Without password expiry, compromised credentials remain valid indefinitely — enabling long-term unauthorised access.",
		"Set PASS_MAX_DAYS 365 in /etc/login.defs.",
		func() (string, string) {
			data, err := os.ReadFile("/etc/login.defs")
			if err != nil {
				return "skipped", "Could not read /etc/login.defs."
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "#") {
					continue
				}
				if strings.HasPrefix(strings.ToUpper(line), "PASS_MAX_DAYS") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						n, err := strconv.Atoi(fields[1])
						if err == nil {
							if n == 99999 || n < 0 {
								return "fail", fmt.Sprintf("PASS_MAX_DAYS = %d — no password expiry configured.", n)
							}
							if n <= 365 {
								return "pass", fmt.Sprintf("PASS_MAX_DAYS = %d — passwords expire within a year.", n)
							}
							return "fail", fmt.Sprintf("PASS_MAX_DAYS = %d — exceeds the 365-day maximum age requirement.", n)
						}
					}
				}
			}
			return "fail", "PASS_MAX_DAYS not set in /etc/login.defs — no password expiry enforced."
		})
}

func checkSudoLogged() SimCheck {
	return check("T1548", "Sudo Usage Logged", "password-policy", "High",
		"Without sudo logging, privilege escalation via sudo is invisible to defenders and compliance audits.",
		"Add to /etc/sudoers via visudo: Defaults logfile=/var/log/sudo.log",
		func() (string, string) {
			if sudoHasOption("logfile") {
				return "pass", "Sudo logfile configured — all sudo commands logged to a dedicated log file."
			}
			if sudoHasOption("log_output") || sudoHasOption("log_input") {
				return "pass", "Sudo I/O logging configured — full command sessions recorded."
			}
			// rsyslog captures auth.info which includes sudo entries by default
			if serviceActive("rsyslog") {
				if data, err := os.ReadFile("/etc/rsyslog.conf"); err == nil {
					if strings.Contains(string(data), "auth") {
						return "pass", "rsyslog is active and capturing auth facility — sudo events logged via syslog."
					}
				}
			}
			return "fail", "Sudo logging not explicitly configured — privilege escalation via sudo not auditable."
		})
}

func checkNoEmptyPasswords() SimCheck {
	return check("T1110", "No Accounts with Empty Passwords (/etc/shadow)", "password-policy", "Critical",
		"Accounts with empty password fields can be logged into without any credential — trivial lateral movement.",
		"Lock empty-password accounts: passwd -l <username>. Set a password or disable unused accounts.",
		func() (string, string) {
			data, err := os.ReadFile("/etc/shadow")
			if err != nil {
				return "skipped", "Cannot read /etc/shadow — requires root. Run agent as root or with sudo for this check."
			}
			var empty []string
			for _, line := range strings.Split(string(data), "\n") {
				if line == "" {
					continue
				}
				parts := strings.Split(line, ":")
				if len(parts) < 2 {
					continue
				}
				user := parts[0]
				pwField := parts[1]
				// Empty field means no password (not locked with ! or *)
				if pwField == "" {
					empty = append(empty, user)
				}
			}
			if len(empty) == 0 {
				return "pass", "No accounts with empty password fields in /etc/shadow."
			}
			return "fail", fmt.Sprintf("%d account(s) with empty password: %s — immediate unauthorised access risk.", len(empty), strings.Join(empty, ", "))
		})
}
