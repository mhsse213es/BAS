package scenario

import "maps"

// ExecutionClass is the destructiveness tier B5 (the agent-side
// destructive-action guardrail) enforces per step. See
// docs/superpowers/specs/2026-09-29-destructive-action-guardrail-b5-design.md.
//
// This is a SEPARATE concern from ResourceProfile's Risk field
// (resource.go) -- that classifies concurrency-locking risk
// (observation/modification/persistence); this classifies whether
// executing the step can cause irreversible real-world damage. The two
// catalogs are deliberately never merged.
type ExecutionClass string

const (
	ClassNonDestructive         ExecutionClass = "non_destructive"
	ClassPotentiallyDestructive ExecutionClass = "potentially_destructive"
	ClassDestructive            ExecutionClass = "destructive"
)

// ExecutionClassification is the catalog's resolved answer for one
// (technique_id, action_key) pair.
type ExecutionClassification struct {
	Class ExecutionClass
	// DestructiveAction is a stable, audit/report-facing identifier for
	// what this action does (often just the action_key itself).
	DestructiveAction string
	// BlastRadius is a human-readable description for audit/reporting --
	// never itself consulted for enforcement.
	BlastRadius string
}

// unclassified is the fail-closed answer for any (technique_id,
// action_key) pair this catalog has no entry for -- see the spec's
// "Resolution rules": no fallback from an unknown pair to a
// technique-wide generic classification, ever.
var unclassified = ExecutionClassification{
	Class:             ClassDestructive,
	DestructiveAction: "unclassified",
	BlastRadius:       "No catalog entry exists for this technique/action -- treated as destructive per the fail-closed default.",
}

// executionClassifications is the Audspect-controlled catalog, keyed
// technique_id -> action_key -> classification. This is the complete
// audit of all 389 hand-authored steps across all scenarios,
// exhaustively classified during Phase 1's proof-and-classify pass.
var executionClassifications = map[string]map[string]*ExecutionClassification{
	"": {
		"default": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "BitLocker check, Get-BitLockerVolume read-only query",
		},
	},
	"T1003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sysctl reads, DPAPI folder listing, bounded self-crash-and-cleanup core-dump test (own spawned sleep process, /tmp scratch, real rm -rf cleanup)",
		},
	},
	"T1003.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "LSASS posture/capability check — OpenProcess probe and registry reads only, no credential extraction",
		},
		"handle_probe": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "OpenProcess(PROCESS_VM_READ) on lsass then CloseHandle immediately -- no memory read, no dump, explicitly NO credentials accessed; registry reads of RunAsPPL/WDigest/CredentialGuard settings",
		},
		"minidump": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "rundll32 comsvcs.dll MiniDump of REAL lsass process -- genuinely extracts credential material to a temp file (briefly, then deleted) -- real risk if a race/crash prevents cleanup",
		},
		"credential_lsass_simulation": catalogClass(ClassNonDestructive, "credential_lsass_simulation", "Get-Process lsass only; no process handle, no memory read"),
	},
	"T1003.006": {
		// Distinct action_keys for the negative (no rights) and positive
		// (rights granted) control stages -- each is a separately
		// authorizable local policy grant, since they're genuinely
		// different requests (different principal, different expected
		// outcome), not one action run twice.
		"negative": {
			Class:             ClassDestructive,
			DestructiveAction: "dcsync_replication_read",
			BlastRadius:       "DRSUAPI replication request (DCSync) as a principal WITHOUT replication rights -- genuinely attempts to retrieve real directory account secret material (password hashes) from a domain controller over the standard replication protocol. Lab-only; requires a local policy grant.",
		},
		"positive": {
			Class:             ClassDestructive,
			DestructiveAction: "dcsync_replication_read",
			BlastRadius:       "DRSUAPI replication request (DCSync) as a principal WITH replication rights deliberately granted for this verification -- genuinely retrieves real directory account secret material (password hashes) from a domain controller over the standard replication protocol. Lab-only; requires a local policy grant.",
		},
	},
	"T1003.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "SAM/SECURITY hive registry READABILITY check only (Get-Item, no reg save)",
		},
		"hive_save": {
			Class:             ClassDestructive,
			DestructiveAction: "hive_save",
			BlastRadius:       "reg.exe save of SAM/SYSTEM hives to temp then delete -- genuinely extracts real credential-hash material to disk",
		},
		"credential_sam_simulation": catalogClass(ClassNonDestructive, "credential_sam_simulation", "Read attempt on HKLM:\\SAM; blocked by default, no hive data read"),
	},
	"T1003.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "LSA secrets registry key READ attempt only (OpenSubKey, no extraction of secret values)",
		},
	},
	"T1003.005": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "CachedLogonsCount registry read + SECURITY\\Cache key open attempt (no value extraction)",
		},
	},
	"T1021.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "RDP/NLA registry posture reads only, no connection attempted",
		},
		"lateral_rdp_connectivity": catalogClass(ClassNonDestructive, "lateral_rdp_connectivity", "Port connectivity check only"),
	},
	"T1021.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "net use ADMIN$ probe (immediately /delete'd, real cleanup), SMB1/signing registry reads",
		},
		"lateral_smb_shares": catalogClass(ClassNonDestructive, "lateral_smb_shares", "Read-only share enumeration on the target"),
	},
	"T1021.006": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Test-WSMan reachability + harmless Invoke-Command echo to localhost; Get-Service WinRM status read",
		},
		"lateral_winrm_session": catalogClass(ClassPotentiallyDestructive, "lateral_winrm_session", "Opens a remote WinRM session to the target, closed by the step"),
	},
	"T1027": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "string-concat/XOR obfuscation demo, in-memory only, no disk writes",
		},
		"evasion_powershell_obfuscation": catalogClass(ClassNonDestructive, "evasion_powershell_obfuscation", "Encoded harmless command execution"),
	},
	"T1027.010": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "cmd.exe caret/envvar/delayed-expansion obfuscation demo, spawns harmless echo via cmd.exe",
		},
	},
	"T1027.013": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "base64 blob written to own TEMP file, decoded, deleted with real cleanup",
		},
	},
	"T1046": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sysctl/ufw reads, localhost-only TCP port reachability probes",
		},
		"bfsi_banking_app_discovery":     catalogClass(ClassNonDestructive, "bfsi_banking_app_discovery", "GET to the lab simulator's banking-app endpoint"),
		"bfsi_payment_gateway_discovery": catalogClass(ClassNonDestructive, "bfsi_payment_gateway_discovery", "GET to the lab simulator's payment-gateway endpoint"),
		"bfsi_atm_discovery":             catalogClass(ClassNonDestructive, "bfsi_atm_discovery", "GET to the lab simulator's ATM-switch endpoint"),
		"bfsi_cardholder_data_discovery": catalogClass(ClassNonDestructive, "bfsi_cardholder_data_discovery", "GET to the lab simulator's synthetic cardholder endpoint"),
	},
	"T1047": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "WMI Win32_Process.Create spawning a harmless echo via cmd.exe/WmiPrvSE, no payload, no persistence",
		},
	},
	"T1048": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "WebDAV PUT of synthetic data to a non-resolvable .invalid domain -- network-only, no real destination",
		},
	},
	"T1048.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "DNS tunneling of synthetic data via encoded labels to a .invalid domain -- network-only",
		},
	},
	"T1048.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "DLP validation: synthetic data via SFTP to a dedicated monitored sink host, own TEMP files deleted",
		},
	},
	"T1048.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "DLP validation: synthetic data via HTTP/FTP/SMTP/Telnet to .invalid or a dedicated monitored sink; DNS beacon to .invalid",
		},
		"exfil_dns_simulation": catalogClass(ClassNonDestructive, "exfil_dns_simulation", "DNS query under .invalid, which never resolves"),
	},
	"T1052": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "synthetic CSV to print spooler, job removed via Remove-PrintJob, temp file deleted",
		},
	},
	"T1052.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "synthetic CSV copied to removable USB then deleted; UsbStor/RemovableStorageDevices registry policy read",
		},
	},
	"T1053": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "ls /etc/cron.allow /etc/cron.deny read-only",
		},
	},
	"T1053.005": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Scheduled task enumeration — read-only Get-ScheduledTask / schtasks queries only",
		},
		"schtask_create_delete": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "schtasks.exe/Register-ScheduledTask creates a real, uniquely-named scheduled task (BAS-SIM prefixed) at SYSTEM/RunLevel=Highest, immediately deleted with cleanup backstop",
		},
	},
	"T1055": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sysctl/proc reads; OpenProcess VM_READ handle to a self-spawned notepad.exe (killed via cleanup); /proc/1/mem 1-byte read discarded to /dev/null",
		},
		"evasion_process_injection_readiness": catalogClass(ClassNonDestructive, "evasion_process_injection_readiness", "Spawns a harmless sleep process only; no injection performed"),
	},
	"T1055.012": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "step's command is EMPTY (no-op stub, incomplete scenario)",
		},
	},
	"T1056.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Keyboard logging capability check — API/module presence only (no hook installed)",
		},
		"api_check": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "user32.dll/EDR module presence check only, no hook installed",
		},
		"keyboard_hook": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "real system-wide SetWindowsHookEx WH_KEYBOARD_LL for 2s (callback is no-op passthrough, captures zero keystrokes) then guaranteed UnhookWindowsHookEx",
		},
	},
	"T1059": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "/tmp,/dev/shm noexec reads, AppIDSvc status read, writes+executes a harmless echo script in /tmp then rm -f cleanup",
		},
	},
	"T1059.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "benign marker-writing EncodedCommand/AMSI-probe/IEX/PSv2-downgrade/LOLBin-masquerade chains, all self-contained with real cleanup",
		},
	},
	"T1059.005": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "wscript->cmd chain writing a harmless echo VBS then deleting it",
		},
	},
	"T1068": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "aa-status/apparmor_status read-only",
		},
	},
	"T1069.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "net localgroup Administrators enumeration, read-only",
		},
	},
	"T1069.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "net group Domain/Enterprise Admins enumeration, read-only",
		},
	},
	"T1070": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "systemctl/grep/find reads for auditd/rsyslog/journald/log-permissions, all read-only",
		},
	},
	"T1070.001": {
		"clear_bas_owned_log": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "creates a BAS-Sim-<chain>-named custom EventLog, wevtutil cl's ONLY that throwaway log, then Remove-EventLog deletes it",
		},
		"clear_nonexistent_log_probe": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Clear-EventLog against a deliberately nonexistent log name -- guaranteed no-op",
		},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "wevtutil el (list channels) + wevtutil gli Security (metadata only) -- read-only enumeration",
		},
		"clear_real_security_log_gated": {
			Class:             ClassDestructive,
			DestructiveAction: "clear_real_security_log_gated",
			BlastRadius:       "cscrf-mii-drill -- if env var BAS_CONFIRM_LOG_CLEAR=true calls real wevtutil cl Security, irreversibly wiping the Windows Security event log",
		},
		"evasion_event_log_clearing": catalogClass(ClassDestructive, "evasion_event_log_clearing", "Clears a log; limited to the dedicated synthetic BAS-SIM-Test log but still a log clear"),
	},
	"T1070.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "swift_alliance_transactions.log is the scenario's OWN synthetic decoy file (explicitly documented as fake/BAS-SIM data), timestomp+delete touches only this self-created decoy",
		},
	},
	"T1071.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "DNS beacon to .invalid, HTTPS beacon to RFC5737 (192.0.2.1), HTTP POST to BAS listener -- all network-only synthetic C2 simulation",
		},
		"c2_http_beaconing": catalogClass(ClassNonDestructive, "c2_http_beaconing", "Five periodic GET requests to the lab simulator; no state changed"),
	},
	"T1071.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "DNS C2 beacon simulation via nslookup to .invalid domains -- network-only",
		},
	},
	"T1074.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "copies (not moves) files into a BAS-owned temp staging dir, real recursive cleanup",
		},
	},
	"T1078": {
		"dbprobe_read_only":         dbprobeClass(ClassNonDestructive, "", "read_only database probe (named, read-only transaction, row/time bounded) -- T1078"),
		"dbprobe_bounded_synthetic": dbprobeClass(ClassPotentiallyDestructive, "dbprobe_bounded_synthetic", "bounded_synthetic database probe (writes only fixture-tagged synthetic rows/roles) -- T1078"),
		"dbprobe_mutation":          dbprobeClass(ClassDestructive, "dbprobe_mutation", "mutation database probe (changes real database state) -- T1078"),
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sshd config reads, cached-logons/no-password-account reads, Guest-account status read",
		},
	},
	"T1078.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "local Administrators group membership count/read only",
		},
	},
	"T1083": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "read-only file-discovery scans (find/grep/Get-ChildItem) + synthetic decoy files created/enumerated/deleted in own TEMP dir",
		},
	},
	"T1087.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "net user/localgroup/group enumeration, read-only",
		},
	},
	"T1087.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "net group/view, nltest /dclist, LDAP DirectorySearcher enumeration -- all read-only",
		},
	},
	// Hunters International read-only checks (scenarios/hunters-international-kill-chain.yaml).
	// Each command only reads configuration, service state, or file contents; none writes,
	// connects to a remote host, or uses credentials.
	// Rhysida read-only check (scenarios/rhysida-kill-chain.yaml). wevtutil gl reads channel
	// configuration only; no channel is disabled.
	"T1562.008": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "wevtutil gl (get-log) reads the enabled state of required log channels -- read-only, no channel is changed",
		},
	},
	"T1190": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Get-Service / Get-NetTCPConnection listener check and read-only inspection of WebLogic install state -- no request is sent to any listener",
		},
	},
	"T1505.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "read-only scan of web-server root directories for web-shell signature strings -- files are read, never written or executed",
		},
	},
	"T1556": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "reads the Netlogon FullSecureChannelProtection registry value on a domain controller -- no secure-channel traffic, no password reset",
		},
	},
	"T1090": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sysctl ip_forward/accept_ra reads",
		},
	},
	"T1090.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Proxy configuration enumeration — read-only registry/OS settings checks",
		},
		"portproxy_create_delete": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "netsh interface portproxy add v4tov4 (localhost-only, port 59999) then delete -- real OS network-routing config change (registry-backed), self-contained/cleaned-up",
		},
	},
	"T1105": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "certutil/bitsadmin download attempts against RFC5737/.invalid targets, any downloaded file deleted via cleanup",
		},
		"c2_ingress_tool_transfer": catalogClass(ClassPotentiallyDestructive, "c2_ingress_tool_transfer", "Downloads one response body from the lab simulator into a per-run temp file, removed by undo"),
	},
	"T1110": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sshd/login.defs/shadow reads, net accounts policy reads",
		},
	},
	"T1110.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "single ValidateCredentials failed-auth attempt against a guaranteed-nonexistent username -- lockout-safe by design",
		},
	},
	"T1110.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "single failed domain auth against a guaranteed-nonexistent probe account -- lockout-safe by design",
		},
		"credential_password_spray": catalogClass(ClassDestructive, "credential_password_spray", "Wrong-password auth attempts against named accounts; can lock out real accounts if pointed at a real domain"),
	},
	"T1113": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "screen-bounds/display-count read only (no capture) OR a real but 1x1-pixel CopyFromScreen, immediately overwritten with blank bitmap and deleted",
		},
	},
	"T1115": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Set-Clipboard to synthetic DLP test data, checked, then explicitly restores the ORIGINAL clipboard value inline",
		},
	},
	"T1127.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "MSBuild inline task that only logs a message, own temp .proj file deleted",
		},
	},
	"T1134": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "whoami /priv read + analysis, no privilege used/activated",
		},
	},
	"T1134.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "real CreateProcess w/ spoofed PPID attribute, but child is a harmless echo terminated within 5s -- transient, no persistence",
		},
	},
	"T1135": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Win32_Share WMI query + net view, read-only",
		},
	},
	"T1136.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Local account enumeration — read-only net user / Get-LocalUser queries",
		},
		"account_create_delete": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "New-LocalUser/net user /add creates a REAL local SAM account (BAS-SIM-prefixed, randomized password) then deletes it -- real persistence-adjacent API",
		},
		"persistence_local_account_creation": catalogClass(ClassDestructive, "persistence_local_account_creation", "Creates a local user account; a failed undo leaves an account"),
	},
	"T1140": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "certutil -encode/-decode/-hashfile, local-only (no network), own temp files deleted",
		},
	},
	"T1197": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "BITS/bitsadmin job created against RFC5737 non-routable target then cancelled/removed, no file downloaded",
		},
	},
	"T1200": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "creates a synthetic 8MB loopback disk image in own /tmp scratch, mounts/tests/unmounts, real losetup -D + rm cleanup",
		},
	},
	"T1218": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "AppLocker/WDAC policy presence read-only check",
		},
	},
	"T1218.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "hh.exe spawned against a non-existent CHM path, no content executed, process killed",
		},
	},
	"T1218.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "cmstp.exe /s /ns against a minimal stub INF with no ServiceInstall/RunPreSetupCommandsSection, killed+cleaned",
		},
	},
	"T1218.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "InstallUtil /U (uninstall mode) against a never-installed benign assembly -- no-op by construction, deleted after",
		},
	},
	"T1218.005": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "mshta HTA/inline-vbscript chains spawning harmless echo; rundll32 shell32.dll,Control_RunDLL -- all killed within seconds, artifacts cleaned",
		},
	},
	"T1218.007": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "msiexec against a guaranteed-nonexistent local URL (nothing listening) -- always fails, no package installed",
		},
	},
	"T1218.009": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Regasm.exe capability check — read-only checks for COM registration capabilities",
		},
		"com_register_unregister": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "RegAsm.exe /codebase genuinely registers a COM class in the registry (HKCR\\CLSID), immediately followed by /unregister",
		},
	},
	"T1218.010": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "regsvr32 Squiblydoo pattern (/n /u /i:) deliberately does NOT register a persistent COM entry -- only inline-executes benign/empty JScript payload",
		},
	},
	"T1218.011": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "rundll32 with legitimate signed exports (advapi32.dll ProcessIdleTasks) or an ADS staged in own TEMP file, deleted after",
		},
	},
	"T1220": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "minimal literal-text XSLT (no scripting body), wmic /format: against it, cleaned",
		},
	},
	"T1221": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "HTTP fetch to localhost with no listener -- connection refused expected",
		},
	},
	"T1222": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "writes a uniquely-PID-named test file into /etc, immediately removed either branch -- bounded, no permission/ACL changes",
		},
	},
	"T1482": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "nltest /domain_trusts + net user enumeration, read-only",
		},
	},
	"T1485": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Data destruction enumeration — read-only checks for backup status / recovery capabilities",
		},
		"mass_rename_delete_sandboxed": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "creates 7 BAS-owned decoy files in own TEMP subdir, renames+deletes ONLY those self-created files, verified self-contained",
		},
	},
	"T1486": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Ransomware capability check — encryption algorithm and tool availability enumeration only",
		},
		"ransomware_sim_sandboxed": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "ALL steps operate only on BAS-owned synthetic decoy files in own TEMP subdirectory; XOR is toy cipher; verified Remove-Item -Recurse cleanup in every variant",
		},
	},
	"T1518.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "WMI SecurityCenter2 AV/FW product enumeration, read-only",
		},
		"evasion_security_software_discovery": catalogClass(ClassNonDestructive, "evasion_security_software_discovery", "Read-only service enumeration"),
	},
	"T1526": {
		"cloud_inventory_read": {Class: ClassNonDestructive, BlastRadius: "Read-only inventory listing of database or extension resources."},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "cloud CLI presence + credential file EXISTENCE checks only (Test-Path), no content read",
		},
	},
	"T1528": {
		"cloud_token_use_read": {Class: ClassNonDestructive, BlastRadius: "One read-only call with a token acquired in the same step."},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "cached identity artifact EXISTENCE checks only, no content read",
		},
	},
	"T1539": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "opens Chrome Cookies DB in Read mode only to test lock/accessibility, closes immediately, never reads content",
		},
	},
	"T1543.003": {
		"service_create_start_stop_delete": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "sc.exe create+start+stop+delete of a real BAS-SIM-named Windows service -- identical pattern to existing T1569.002 catalog entry",
		},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Win32_Service WMI query for non-system-path running services, read-only",
		},
	},
	"T1547.001": {
		"persistence_write_delete": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "writes a real value to HKCU Run/RunOnce (genuine autostart registry location) or drops a file into the REAL Windows Startup folder, then deletes it",
		},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "HKLM Run key entry count + Startup folder content count, read-only",
		},
		"persistence_registry_run_key": catalogClass(ClassPotentiallyDestructive, "persistence_registry_run_key", "Writes one BAS-SIM-named Run value, removed by undo"),
	},
	"T1548": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sysctl/proc reads, sshd config reads, UAC/policy registry reads",
		},
	},
	"T1548.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "UAC/AlwaysInstallElevated registry policy read-only checks",
		},
	},
	"T1550.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Azure/AWS IMDS metadata + token access probes (conditional SKIP if not on cloud VM); OAuth cache existence checks",
		},
	},
	"T1550.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "LmCompatibilityLevel registry read + localhost SMB loopback probe",
		},
	},
	"T1552.001": {
		"local_credential_scan": {Class: ClassNonDestructive, BlastRadius: "Local read of credential-file presence and counts; values are never printed."},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "AWS/Azure/GCP CLI credential file existence checks only (Test-Path), no content read",
		},
		"credential_unsecured_discovery": catalogClass(ClassNonDestructive, "credential_unsecured_discovery", "Read-only search for credential files"),
	},
	"T1552.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "AutoAdminLogon registry read-only",
		},
	},
	"T1552.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "BitLocker volume protection status read",
		},
	},
	"T1552.005": {
		"cloud_imds_probe":  {Class: ClassNonDestructive, BlastRadius: "Read-only request to the instance metadata service."},
		"cloud_token_issue": {Class: ClassNonDestructive, BlastRadius: "Requests a managed-identity token into memory only; nothing is stored or changed."},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Azure IMDS metadata dump + AWS IMDSv2 credential retrieval probes",
		},
	},
	"T1552.006": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "LAPS attribute readability probe via LDAP DirectorySearcher",
		},
	},
	"T1554": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "plant unique file into /usr/local/bin then rm -f cleanup; audit rule check read-only",
		},
	},
	"T1555.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Edge/Chrome Login Data file lock test (Open Read mode only, closes immediately, no content read)",
		},
		"credential_browser_discovery": catalogClass(ClassNonDestructive, "credential_browser_discovery", "Read-only check for browser credential store files"),
	},
	"T1555.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "cmdkey /list credential vault enumeration, read-only",
		},
		"credential_manager_discovery": catalogClass(ClassNonDestructive, "credential_manager_discovery", "cmdkey /list, read-only"),
	},
	"T1556.007": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Azure AD Connect (ADSync) + PTA agent service status read",
		},
	},
	"T1557.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "LLMNR EnableMulticast + NetBIOS registry policy reads",
		},
	},
	"T1558": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "klist Kerberos ticket enumeration, auth-type read, no ticket export/crack/reuse",
		},
	},
	"T1558.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "setspn SPN enumeration + LDAP servicePrincipalName search, no TGS-REP request",
		},
		"credential_kerberoasting": catalogClass(ClassNonDestructive, "credential_kerberoasting", "klist read-only check; no ticket request"),
	},
	"T1558.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "AS-REP roastable account discovery via LDAP (no AS-REQ/TGS request)",
		},
		"credential_asrep_roasting": catalogClass(ClassNonDestructive, "credential_asrep_roasting", "Read-only AD user query against the current domain"),
	},
	"T1560.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Archive/collection enumeration — read-only archive tool availability checks",
		},
		"archive_staging": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Compress-Archive creates real .zip of BAS-owned synthetic decoy files in own TEMP dir, real cleanup",
		},
		"collection_archive_data": catalogClass(ClassPotentiallyDestructive, "collection_archive_data", "Creates a staging archive in temp, removed by undo; originals untouched"),
	},
	"T1562": {
		"dbprobe_read_only":         dbprobeClass(ClassNonDestructive, "", "read_only database probe (named, read-only transaction, row/time bounded) -- T1562"),
		"dbprobe_bounded_synthetic": dbprobeClass(ClassPotentiallyDestructive, "dbprobe_bounded_synthetic", "bounded_synthetic database probe (writes only fixture-tagged synthetic rows/roles) -- T1562"),
		"dbprobe_mutation":          dbprobeClass(ClassDestructive, "dbprobe_mutation", "mutation database probe (changes real database state) -- T1562"),
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "sysctl/registry reads for ICMP/DEP/ASLR/Credential Guard/LAPS/Defender posture, all read-only",
		},
	},
	"T1562.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Defender exclusion cmdline logged to EID 4104/4688 (dry-run, no state change) OR temp disable+restore cycle with health-check verification",
		},
		"stop_auditd": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "Attempts to stop the Linux auditd service via systemctl — if it succeeds, briefly disables audit logging until cleanup restarts it",
		},
		"evasion_security_tool_impairment_probe": catalogClass(ClassNonDestructive, "evasion_security_tool_impairment_probe", "Reads Defender preferences only; no setting changed"),
	},
	"T1574.008": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "PATH-order hijack binary planted in WindowsApps + calc.exe spawned then killed via cleanup; hijack binary removed",
		},
	},
	"T1574.009": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "unquoted service path enumeration via Get-WmiObject Win32_Service, read-only",
		},
	},
	"T1615": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "gpresult + LDAP GPO enumeration, read-only",
		},
	},
	"T1620": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "reflective [Reflection.Assembly]::Load attempted but fails silently if blocked, no real assembly executed",
		},
	},
	"T1490": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only enumeration of VSS shadow copies / backup catalog (vssadmin list shadows, wbadmin get versions). No state changed.",
		},
		"backup_readiness_check": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only query of VSS service status and scheduled backup tasks (Get-Service, Get-ScheduledTask). No state changed.",
		},
		"survival": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only count of VSS shadow copies after the deletion stage (vssadmin list shadows). No state changed.",
		},
		"vss_delete": {
			Class:             ClassDestructive,
			DestructiveAction: "vss_delete",
			BlastRadius:       "Deletes VSS shadow copies (vssadmin/wbadmin/WMI Win32_ShadowCopy.Delete()) -- irreversible, removes the ransomware-recovery path.",
		},
		"wbadmin_delete_catalog": {
			Class:             ClassDestructive,
			DestructiveAction: "wbadmin_delete_catalog",
			BlastRadius:       "Deletes the Windows Server Backup catalog (wbadmin delete catalog) -- irreversible.",
		},
		"bootloader_recovery_disable": {
			Class:             ClassDestructive,
			DestructiveAction: "bootloader_recovery_disable",
			BlastRadius:       "Disables Windows Recovery Environment via bcdedit (recoveryenabled no / bootstatuspolicy ignoreallfailures) -- removes the final recovery path.",
		},
	},
	"T1489": {
		"backup_service_stop": {
			Class:             ClassDestructive,
			DestructiveAction: "backup_service_stop",
			BlastRadius:       "Runs 'net stop' against wbengine (Windows Backup Engine) and vss (Volume Shadow Copy service) -- if it succeeds, disables the host's native backup infrastructure until manually restarted.",
		},
	},
	"T1562.001_auditd": {
		"stop_auditd": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "Attempts to stop the Linux auditd service via systemctl -- if it succeeds, briefly disables audit logging until cleanup restarts it.",
		},
	},
	"T1569.002": {
		"service_create_start_stop_delete": {
			Class:             ClassPotentiallyDestructive,
			DestructiveAction: "",
			BlastRadius:       "Creates a BAS-owned, uniquely-named decoy Windows service (rundll32 binpath), starts it, stops it, deletes it. Self-contained -- never touches a pre-existing real service.",
		},
		"lateral_remote_service": catalogClass(ClassDestructive, "lateral_remote_service", "Creates, starts and deletes a service on the target host"),
	},
	"T1003.003": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Read-only probes",
		},
	},
	"T1016": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Network configuration read-only query (ipconfig, Get-NetAdapter, etc.)",
		},
	},
	"T1018": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Remote system enumeration via network queries (nbtstat, ping, Get-WmiObject, etc.)",
		},
		"lateral_system_discovery": catalogClass(ClassNonDestructive, "lateral_system_discovery", "Read-only remote system query"),
	},
	"T1057": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Process enumeration via tasklist, Get-Process, ps, etc. — read-only",
		},
	},
	"T1082": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "System information collection (systeminfo, Get-ComputerInfo, uname, etc.) — read-only",
		},
	},
	"T1562.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Disable cloud logging enumeration — read-only checks of cloud service logging status",
		},
	},
	"T1562.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Disable/modify notifications and alerts — enumeration of alert settings only (read-only)",
		},
	},
	"T1565.001": {
		"dbprobe_read_only":         dbprobeClass(ClassNonDestructive, "", "read_only database probe (named, read-only transaction, row/time bounded) -- T1565.001"),
		"dbprobe_bounded_synthetic": dbprobeClass(ClassPotentiallyDestructive, "dbprobe_bounded_synthetic", "bounded_synthetic database probe (writes only fixture-tagged synthetic rows/roles) -- T1565.001"),
		"dbprobe_mutation":          dbprobeClass(ClassDestructive, "dbprobe_mutation", "mutation database probe (changes real database state) -- T1565.001"),
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Data destruction enumeration — read-only checks for backup/archive locations",
		},
		"financial_transaction_manipulation":         catalogClass(ClassPotentiallyDestructive, "financial_transaction_manipulation", "Ledger write on the lab simulator only, removed by undo"),
		"financial_payment_instruction_manipulation": catalogClass(ClassPotentiallyDestructive, "financial_payment_instruction_manipulation", "Ledger write on the lab simulator only, removed by undo"),
		"financial_atm_dispense_manipulation":        catalogClass(ClassPotentiallyDestructive, "financial_atm_dispense_manipulation", "Ledger write and reconcile on the lab simulator only, removed by undo"),
		"financial_fraud_pattern_simulation":         catalogClass(ClassPotentiallyDestructive, "financial_fraud_pattern_simulation", "Several ledger writes on the lab simulator only, removed by undo"),
		"financial_transaction_limit_bypass":         catalogClass(ClassPotentiallyDestructive, "financial_transaction_limit_bypass", "Ledger write on the lab simulator only, removed by undo"),
		"financial_reconciliation_manipulation":      catalogClass(ClassPotentiallyDestructive, "financial_reconciliation_manipulation", "Ledger write and reconcile on the lab simulator only, removed by undo"),
	},
	"T1566.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Phishing enumeration — read-only configuration checks for email filtering/rules",
		},
	},
	"T1567": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Exfiltration over network — traffic sent to non-routable/.invalid domains (network-only simulation)",
		},
	},
	"T1567.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Exfiltration over web service — synthetic data sent to RFC5737 or .invalid endpoints (network-only)",
		},
	},
	"T1567.002": {
		"cloud_synthetic_upload": {Class: ClassDestructive, DestructiveAction: "synthetic_upload_then_delete", BlastRadius: "Uploads one 1 KB synthetic object to an operator-named test container and deletes it; cleanup is verified in-script. Tests egress to cloud storage."},
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Exfiltration over file transfer protocol — synthetic data sent to .invalid/monitored sink destinations (network-only)",
		},
	},
	"T1213": {
		"dbprobe_read_only":         dbprobeClass(ClassNonDestructive, "", "read_only database probe (named, read-only transaction, row/time bounded) -- T1213"),
		"dbprobe_bounded_synthetic": dbprobeClass(ClassPotentiallyDestructive, "dbprobe_bounded_synthetic", "bounded_synthetic database probe (writes only fixture-tagged synthetic rows/roles) -- T1213"),
		"dbprobe_mutation":          dbprobeClass(ClassDestructive, "dbprobe_mutation", "mutation database probe (changes real database state) -- T1213"),
	},
	"T1567.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Exfiltration over DNS — synthetic data in DNS queries to .invalid domains (network-only)",
		},
	},
	"T1574.001": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "DLL search order hijack — PATH verification only (read-only)",
		},
	},
	"T1574.007": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Environment variable injection — read-only PATH/library-path enumeration",
		},
	},

	// discoveryProfiles-derived defaults (C2, 8ec2f4db), lost in the
	// e8371b57 catalog rewrite. T1057/T1082/T1016/T1018 have their own
	// entries above. T1120 is deliberately absent: see
	// discoveryDefaultClassification.
	"T1012": {"enumerate": discoveryDefaultClassification},
	"T1007": {"enumerate": discoveryDefaultClassification},
	"T1518": {"enumerate": discoveryDefaultClassification},
	"T1010": {"enumerate": discoveryDefaultClassification},
	"T1033": {"enumerate": discoveryDefaultClassification},
	"T1124": {"enumerate": discoveryDefaultClassification},
	"T1049": {"enumerate": discoveryDefaultClassification},
	"T1087": {
		"enumerate":                 discoveryDefaultClassification,
		"dbprobe_read_only":         dbprobeClass(ClassNonDestructive, "", "read_only database probe (named, read-only transaction, row/time bounded) -- T1087"),
		"dbprobe_bounded_synthetic": dbprobeClass(ClassPotentiallyDestructive, "dbprobe_bounded_synthetic", "bounded_synthetic database probe (writes only fixture-tagged synthetic rows/roles) -- T1087"),
		"dbprobe_mutation":          dbprobeClass(ClassDestructive, "dbprobe_mutation", "mutation database probe (changes real database state) -- T1087"),
	},
	"T1069": {"enumerate": discoveryDefaultClassification},
	"T1652": {"enumerate": discoveryDefaultClassification},
	"T1649": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "read-only LDAP reads of the AD Configuration partition (certificate templates, PKI containers, CA objects); no writes, no enrollment, no template or ACL changes",
		},
	},
	"T1580": {
		"cloud_inventory_read": {Class: ClassNonDestructive, BlastRadius: "Read-only inventory listing (names and counts)."},
	},
	"T1619": {
		"cloud_inventory_read": {Class: ClassNonDestructive, BlastRadius: "Read-only listing of storage bucket names."},
	},
	"T1069.003": {
		"cloud_role_read": {Class: ClassNonDestructive, BlastRadius: "Read-only listing of role assignments or attached policies."},
	},
	"T1087.004": {
		"cloud_identity_read": {Class: ClassNonDestructive, BlastRadius: "Caller identity lookup, which every principal may perform."},
	},
	"T1555": {
		"cloud_secret_name_read":  {Class: ClassNonDestructive, BlastRadius: "Lists secret names only; no value is requested."},
		"cloud_secret_value_read": {Class: ClassPotentiallyDestructive, BlastRadius: "Requests one synthetic test secret value into memory; only its length is recorded and the value is discarded."},
	},
	"T1098": {
		"policy_simulation_read":           {Class: ClassNonDestructive, BlastRadius: "IAM policy simulation only; no change is made."},
		"cloud_role_assume":                {Class: ClassPotentiallyDestructive, BlastRadius: "Asks the cloud to issue temporary credentials for one operator-named test role; returned credentials are discarded."},
		"persistence_account_manipulation": catalogClass(ClassDestructive, "persistence_account_manipulation", "Adds a local account to the built-in Users group; a failed undo leaves membership"),
	},
	"T1098.001": {
		"cloud_access_key_create": {Class: ClassDestructive, DestructiveAction: "create_then_delete_access_key", BlastRadius: "Creates one access key for an operator-named test user and deletes it; cleanup is verified in-script."},
		"cloud_client_secret_add": {Class: ClassDestructive, DestructiveAction: "add_then_remove_client_secret", BlastRadius: "Adds one client secret to an operator-named test application and removes it; cleanup is verified in-script."},
	},
	"T1021": {
		"remote_mgmt_exposure_read": {Class: ClassNonDestructive, BlastRadius: "Read-only SSH or WinRM listener and firewall state check."},
	},
	"T1574": {
		"startup_location_read": {Class: ClassNonDestructive, BlastRadius: "Read-only permission check of startup script locations; nothing is written."},
	},
	"T1530": {
		"cloud_object_list_read": {Class: ClassNonDestructive, BlastRadius: "Lists container or bucket names on a synthetic test account."},
		"cloud_object_head_read": {Class: ClassNonDestructive, BlastRadius: "Metadata-only request for one synthetic object; the body is never read."},
	},
	"T1573": {
		"c2_encrypted_channel": catalogClass(ClassPotentiallyDestructive, "c2_encrypted_channel", "Loopback TLS session; self-signed cert in CurrentUser\\My, removed by step and undo"),
	},
	"T1571": {
		"c2_non_standard_port": catalogClass(ClassNonDestructive, "c2_non_standard_port", "One GET to the lab simulator on a non-standard port; no state changed"),
	},
	"T1005": {
		"collection_local_data": catalogClass(ClassNonDestructive, "collection_local_data", "Read-only enumeration and staging copies of synthetic files"),
	},
	"T1039": {
		"collection_network_share": catalogClass(ClassNonDestructive, "collection_network_share", "Read-only enumeration of a lab share"),
	},
	"T1114.001": {
		"collection_email_presence": catalogClass(ClassNonDestructive, "collection_email_presence", "Read-only check for mail-client data presence"),
	},
	"T1041": {
		"exfil_over_c2_simulation": catalogClass(ClassPotentiallyDestructive, "exfil_over_c2_simulation", "Writes one synthetic row to the lab simulator ledger, removed by undo"),
	},
	"T1036": {
		"evasion_masquerading_executable": catalogClass(ClassPotentiallyDestructive, "evasion_masquerading_executable", "Copies a renamed harmless binary into temp, removed by undo"),
	},
	"T1112": {
		"evasion_registry_modification": catalogClass(ClassPotentiallyDestructive, "evasion_registry_modification", "Writes a BAS-SIM-named value under HKCU, removed by undo"),
	},
	"T1499": {
		"financial_resilience_check": catalogClass(ClassNonDestructive, "financial_resilience_check", "Read-only GETs to the lab simulator"),
	},
	"T1546.003": {
		"persistence_wmi_event_subscription": catalogClass(ClassDestructive, "persistence_wmi_event_subscription", "Creates a WMI filter, consumer and binding under root\\subscription; a failed undo leaves persistence"),
	},
	"T1590.001": {
		"recon_subdomain_enumeration": catalogClass(ClassNonDestructive, "recon_subdomain_enumeration", "DNS queries under bas-sim.test, a reserved TLD"),
	},
	"T1589.003": {
		"recon_employee_discovery": catalogClass(ClassNonDestructive, "recon_employee_discovery", "Read-only GET to the lab simulator's synthetic directory"),
	},
	"T1078.002": {
		"access_valid_account_logon": catalogClass(ClassDestructive, "access_valid_account_logon", "Creates a synthetic local account, logs on with it, and removes it in undo; a failed undo leaves an account"),
	},
	"T1059.003": {
		"exe_command_shell": catalogClass(ClassNonDestructive, "exe_command_shell", "Runs one harmless echo through cmd.exe; no state changed"),
	},
}

// discoveryDefaultClassification covers the read-only ATT&CK discovery
// techniques in resource.go's discoveryProfiles, which were audited against
// real production ART command text and proven non-mutating -- so a step with
// no action_key for one of them doesn't fail closed to destructive. T1120 is
// excluded even though it's in discoveryProfiles: that map rates it read-only
// for resource/concurrency purposes only, and one of its real atomics
// ("WinPwn - printercheck") downloads and executes an arbitrary third-party
// script, which is exactly the unverifiable case this catalog fails closed on.
var discoveryDefaultClassification = &ExecutionClassification{
	Class:             ClassNonDestructive,
	DestructiveAction: "",
	BlastRadius:       "Read-only ATT&CK discovery technique from resource.go's discoveryProfiles set, audited against real production ART command text and proven non-mutating. No state changed.",
}

// handAuthoredExecutionClassifications is a frozen, independent copy of
// the hand-authored catalog above, taken at package-variable-initialization
// time -- which the Go spec guarantees completes, for every file in a
// package, before any init() function in that package runs. execclass_generated.go's
// init() mutates executionClassifications directly, including (on a
// second real run of cmd/auditcorpus) re-adding every entry from its own
// PREVIOUS output before that tool's main() even starts. Without this
// independent snapshot, a lookup against executionClassifications cannot
// tell a genuinely hand-authored entry from the tool's own prior
// generated output, and the audit tool mistakes the latter for the
// former -- silently dropping those entries the next time it regenerates
// the file. IsHandAuthored below is the only thing allowed to read this.
var handAuthoredExecutionClassifications = cloneExecutionClassifications(executionClassifications)

func cloneExecutionClassifications(src map[string]map[string]*ExecutionClassification) map[string]map[string]*ExecutionClassification {
	dst := make(map[string]map[string]*ExecutionClassification, len(src))
	for tech, inner := range src {
		innerCopy := make(map[string]*ExecutionClassification, len(inner))
		maps.Copy(innerCopy, inner)
		dst[tech] = innerCopy
	}
	return dst
}

// IsHandAuthored reports whether (techniqueID, actionKey) is a genuinely
// hand-authored catalog entry -- never an entry added later by
// execclass_generated.go's init() (including by the generator's own
// prior run). This is what cmd/auditcorpus must use to decide whether an
// item is already covered by this file, specifically so the generator is
// safe to re-run: ResolveExecutionClass/the live executionClassifications
// map are deliberately NOT used here, since they reflect generated
// entries too and would make the tool mistake its own previous output for
// a hand-authored one.
func IsHandAuthored(techniqueID, actionKey string) bool {
	techniques, ok := handAuthoredExecutionClassifications[techniqueID]
	if !ok {
		return false
	}
	_, ok = techniques[actionKey]
	return ok
}

// ResolveExecutionClass looks up the classification for a given
// (technique_id, action_key) pair. Unknown pairs fail closed as destructive.
func ResolveExecutionClass(techniqueID, actionKey string) ExecutionClassification {
	if actionKey == "" {
		if techniqueID == "" {
			actionKey = "default"
		} else {
			actionKey = "enumerate"
		}
	}

	techniques, ok := executionClassifications[techniqueID]
	if !ok {
		return unclassified
	}

	classification, ok := techniques[actionKey]
	if !ok {
		return unclassified
	}

	return *classification
}

// AttachExecutionClassifications resolves and assigns execution classifications
// to each step based on its technique_id and action_key, using the canonical
// catalog in executionClassifications. Runs at scenario compile time.
func AttachExecutionClassifications(steps []ScenarioStep) {
	for i := range steps {
		c := ResolveExecutionClass(steps[i].TechniqueID, steps[i].ActionKey)
		steps[i].ExecutionClass = c.Class
		steps[i].DestructiveAction = c.DestructiveAction
		steps[i].BlastRadius = c.BlastRadius
	}
}

// catalogClass builds a hand-authored catalog entry for an explicitly classified step.
func catalogClass(c ExecutionClass, action, blast string) *ExecutionClassification {
	return &ExecutionClassification{Class: c, DestructiveAction: action, BlastRadius: blast}
}

// dbprobeClass builds a catalog entry for a dbsim probe class (spec A6). The
// action keys are issued by the dbsim builder from the probe registry class
// ("dbprobe_" + class), never chosen by a scenario author.
func dbprobeClass(c ExecutionClass, action, blast string) *ExecutionClassification {
	return &ExecutionClassification{Class: c, DestructiveAction: action, BlastRadius: blast}
}
