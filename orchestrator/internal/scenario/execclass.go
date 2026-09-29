package scenario

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
	},
	"T1021.002": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "net use ADMIN$ probe (immediately /delete'd, real cleanup), SMB1/signing registry reads",
		},
	},
	"T1021.006": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Test-WSMan reachability + harmless Invoke-Command echo to localhost; Get-Service WinRM status read",
		},
	},
	"T1027": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "string-concat/XOR obfuscation demo, in-memory only, no disk writes",
		},
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
	},
	"T1526": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "cloud CLI presence + credential file EXISTENCE checks only (Test-Path), no content read",
		},
	},
	"T1528": {
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
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "AWS/Azure/GCP CLI credential file existence checks only (Test-Path), no content read",
		},
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
	},
	"T1555.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "cmdkey /list credential vault enumeration, read-only",
		},
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
	},
	"T1558.004": {
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "AS-REP roastable account discovery via LDAP (no AS-REQ/TGS request)",
		},
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
	},
	"T1562": {
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
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Data destruction enumeration — read-only checks for backup/archive locations",
		},
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
		"enumerate": {
			Class:             ClassNonDestructive,
			DestructiveAction: "",
			BlastRadius:       "Exfiltration over file transfer protocol — synthetic data sent to .invalid/monitored sink destinations (network-only)",
		},
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
