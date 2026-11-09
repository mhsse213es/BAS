"""Static scan of the Windows ART atomics for changes a run can leave behind.

  python scan.py atomics.json out.json

atomics.json: [{technique_id, name, executor, command, cleanup, platform}], exported from art_atomic_tests.

For each test it finds (a) registry paths written and whether each lies under a location the agent's restore guard or
Run-key restore puts back, and (b) other persistent changes (services, tasks, accounts, Defender, firewall, WMI,
certificates, ...), with whether the agent restores that kind of change and whether the test ships its own cleanup.

This is a text scan of the command, not an execution: it finds what a test may do, not what it did on a machine.
"""
import json
import re
import sys

# ---- what the agent restores (keep in step with agent/reghijack_guard_windows.go and agent/snapshot_windows.go) ----
CLASSES_KEYS = ["folder", "directory", "drive", "*", "allfilesystemobjects", "applications", "exefile", "batfile",
                "cmdfile", "comfile", "scrfile", "lnkfile", "cplfile", "mscfile", "htafile", "ms-settings", ".exe",
                ".bat", ".cmd", ".com", ".scr", ".lnk", ".cpl", ".msc", ".hta", ".ps1", ".vbs", ".js"]
GUARD = []  # (hive, lower-case path prefix)
for hive in ("HKCU", "HKLM"):
    for k in CLASSES_KEYS:
        GUARD.append((hive, "software\\classes\\" + k))
GUARD += [
    ("HKCU", "software\\classes\\clsid"),
    ("HKCU", "software\\microsoft\\windows\\currentversion\\app paths"),
    ("HKLM", "software\\microsoft\\windows\\currentversion\\app paths"),
    ("HKLM", "software\\microsoft\\windows nt\\currentversion\\image file execution options"),
    ("HKLM", "software\\microsoft\\windows nt\\currentversion\\silentprocessexit"),
    ("HKLM", "software\\microsoft\\windows\\currentversion\\explorer\\shellexecutehooks"),
    ("HKLM", "software\\microsoft\\windows nt\\currentversion\\windows"),
    ("HKCU", "software\\microsoft\\windows nt\\currentversion\\windows"),
    ("HKLM", "software\\microsoft\\windows nt\\currentversion\\winlogon"),
    ("HKLM", "software\\microsoft\\command processor"),
    ("HKCU", "software\\microsoft\\command processor"),
    ("HKCU", "environment"),
    ("HKLM", "software\\microsoft\\windows\\currentversion\\policies"),
    ("HKCU", "software\\microsoft\\windows\\currentversion\\policies"),
    ("HKLM", "software\\policies\\microsoft"),
    ("HKCU", "software\\policies\\microsoft"),
    # added after the first scan (agent/reghijack_guard_windows.go, "found by the static scan")
    ("HKLM", "system\\currentcontrolset\\control\\terminal server"),
    ("HKLM", "system\\currentcontrolset\\control\\session manager"),
    ("HKLM", "system\\currentcontrolset\\control\\safeboot"),
    ("HKLM", "system\\currentcontrolset\\control\\networkprovider"),
    ("HKLM", "system\\currentcontrolset\\control\\filesystem"),
    ("HKLM", "system\\currentcontrolset\\control\\wmi\\autologger"),
    ("HKLM", "system\\currentcontrolset\\services\\lanmanserver\\parameters"),
    ("HKLM", "system\\currentcontrolset\\services\\w32time"),
    ("HKLM", "system\\currentcontrolset\\services\\termservice\\parameters"),
    ("HKCU", "software\\microsoft\\windows\\currentversion\\internet settings"),
    ("HKCU", "software\\microsoft\\windows\\currentversion\\winlogon"),
    ("HKLM", "software\\microsoft\\windows\\currentversion\\winevt\\channels"),
    ("HKLM", "software\\microsoft\\active setup\\installed components"),
    ("HKCU", "software\\microsoft\\active setup\\installed components"),
    ("HKLM", "software\\microsoft\\.netframework"),
    ("HKLM", "software\\microsoft\\provisioning\\commands"),
    ("HKCU", "software\\microsoft\\office\\16.0\\excel\\security"),
    ("HKCU", "software\\microsoft\\office\\16.0\\word\\security"),
    ("HKCU", "software\\microsoft\\office\\16.0\\outlook\\security"),
    ("HKCU", "software\\microsoft\\office\\16.0\\powerpoint\\security"),
    ("HKLM", "system\\currentcontrolset\\control\\lsa"),
    ("HKLM", "system\\currentcontrolset\\control\\securityproviders\\wdigest"),
    # the older snapshot's Run-key restore
    ("HKCU", "software\\microsoft\\windows\\currentversion\\run"),
    ("HKLM", "software\\microsoft\\windows\\currentversion\\run"),
]

HIVES = {"hkcu": "HKCU", "hkey_current_user": "HKCU", "hklm": "HKLM", "hkey_local_machine": "HKLM",
         "hkcr": "HKCR", "hkey_classes_root": "HKCR", "hku": "HKU", "hkey_users": "HKU"}
REG_PATH = re.compile(r"(?i)(?:registry::)?\b(hkcu|hklm|hkcr|hku|hkey_current_user|hkey_local_machine|hkey_classes_root|hkey_users)(?::)?[\\/]+([^\s\"'|;,)`]+)")
REG_WRITE = re.compile(r"(?i)\breg(?:\.exe)?\s+(?:add|import|copy|save|restore|load)\b|\b(?:New-Item|New-ItemProperty|Set-ItemProperty|Set-Item|Copy-Item|Rename-ItemProperty|Rename-Item)\b|(?<![\w-])(?:ni|sp|si)\s+(?:-|[\"']?hk|[\"']?registry)|\[Microsoft\.Win32\.Registry\]|\.SetValue\(|\.CreateSubKey\(|\bsc(?:\.exe)?\s+config\b")

# non-registry persistent changes: name -> (regex, restored by the agent?, why/what restores it)
KINDS = {
    "service-create": (r"(?i)\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\b|\bNew-Service\b|\bInstallUtil\b|sc\s+config\b", "partial", "stopped and disabled, not deleted"),
    "scheduled-task": (r"(?i)\bschtasks(?:\.exe)?\b[^\n]*?/create|\bRegister-ScheduledTask\b|\bNew-ScheduledTask\b|\bat\.exe\s+\d", "yes", "deleted if new"),
    "startup-folder": (r"(?i)start menu\\programs\\startup|shell:startup|shell:common startup", "yes", "new files removed"),
    "wmi-persistence": (r"(?i)__EventFilter|__EventConsumer|CommandLineEventConsumer|ActiveScriptEventConsumer|FilterToConsumerBinding|Register-WmiEvent|Set-WmiInstance|Register-CimIndicationEvent", "no", "not recorded or removed"),
    "local-account": (r"(?i)\bnet(?:1)?\s+user\s+\S+\s+\S*\s*/add|\bNew-LocalUser\b|\bnet(?:1)?\s+localgroup\s+\S+\s+\S+\s+/add|\bAdd-LocalGroupMember\b|\bnet(?:1)?\s+user\s+[^\n]*?/add", "no", "accounts and group changes not recorded"),
    "defender-config": (r"(?i)\bSet-MpPreference\b|\bAdd-MpPreference\b|\bsc(?:\.exe)?\s+(?:stop|config)\s+(?:windefend|wdnissvc|sense)|\bDisableRealtimeMonitoring\b|\bmpcmdrun\b[^\n]*?-(?:removedefinitions|disable)|\bnetsh\s+advfirewall\s+set\b", "partial", "policy keys under HKLM\\SOFTWARE\\Policies are restored; Set-MpPreference (stored elsewhere) and service state are not"),
    "firewall": (r"(?i)\bnetsh\s+(?:adv)?firewall\s+(?:firewall\s+)?add\b|\bNew-NetFirewallRule\b|\bnetsh\s+advfirewall\s+firewall\b", "partial", "rules captured; revert coverage not verified here"),
    "certificate-store": (r"(?i)certutil[^\n]*?-addstore|\bImport-Certificate\b|\bImport-PfxCertificate\b|certmgr[^\n]*?/add", "no", "certificates not recorded or removed"),
    "file-association": (r"(?i)\bassoc\s+\.|\bftype\s+\w", "partial", "the HKCU/HKLM Classes keys are restored, assoc/ftype write HKLM\\Classes"),
    "environment": (r"(?i)\bsetx(?:\.exe)?\b|\[Environment\]::SetEnvironmentVariable", "partial", "HKCU\\Environment restored; HKLM environment (setx /m) is not"),
    "boot-config": (r"(?i)\bbcdedit\b", "no", "boot configuration not recorded"),
    "hosts-file": (r"(?i)drivers\\etc\\hosts", "yes", "hosts file restored"),
    "winrm-remoting": (r"(?i)\bEnable-PSRemoting\b|\bwinrm\s+(?:quickconfig|set)\b|\bSet-WSManInstance\b", "no", "WinRM / listener configuration not recorded"),
    "port-proxy-or-share": (r"(?i)netsh\s+interface\s+portproxy|\bnet\s+share\b[^\n]*?\b/?(?:\w+=|/grant)|\bNew-SmbShare\b", "no", "port proxies and shares not recorded"),
    "permissions-change": (r"(?i)\bicacls(?:\.exe)?\b[^\n]*?/(?:grant|deny|setowner|reset)|\btakeown\b|\bSet-Acl\b|\bcacls\b", "no", "ACL changes not recorded"),
    "optional-feature": (r"(?i)\bEnable-WindowsOptionalFeature\b|\bdism(?:\.exe)?\b[^\n]*?/enable-feature|\bAdd-WindowsCapability\b", "no", "feature state not recorded"),
    "log-or-backup-destruction": (r"(?i)\bwevtutil(?:\.exe)?\s+cl\b|\bClear-EventLog\b|\bvssadmin(?:\.exe)?\s+delete\b|\bwbadmin\s+delete\b|\bfsutil(?:\.exe)?\s+usn\s+deletejournal\b|\bcipher(?:\.exe)?\s+/w\b|\bRemove-WmiObject\s+Win32_ShadowCopy|\bwmic\s+shadowcopy\s+delete\b|\bbcdedit[^\n]*?recoveryenabled", "no", "IRREVERSIBLE: logs, shadow copies and backups cannot be restored"),
    "process-injection-or-kill": (r"(?i)\btaskkill\b|\bStop-Process\b|\bStop-Service\b|\bnet\s+stop\b", "no", "stopped processes / services are not restarted"),
    "time-or-timezone": (r"(?i)\bw32tm\b[^\n]*?/(?:config|resync)|\bSet-Date\b|\bSet-TimeZone\b|\btzutil\b[^\n]*?/s", "no", "clock configuration not recorded"),
    "file-drop-outside-temp": (r"(?i)(?:copy|move|xcopy|Copy-Item|Move-Item|Out-File|Set-Content|Add-Content|\bcertutil\b[^\n]*?-urlcache)[^\n]*?(?:c:\\windows\\|%windir%\\|%systemroot%\\|c:\\program files|c:\\programdata\\(?!atomic)|%programdata%\\|%appdata%\\|\$env:appdata\\|c:\\users\\public\\)", "no", "files outside %TEMP% are not recorded or removed"),
}
KINDS = {k: (re.compile(v[0]), v[1], v[2]) for k, v in KINDS.items()}



# A registry path may contain spaces ("...\Terminal Server") when it is quoted, so a quoted path is read whole first;
# whatever is left is scanned for unquoted paths.
QUOTED_REG = re.compile(r"(?i)[\"']\s*(?:registry::)?(hkcu|hklm|hkcr|hku|hkey_current_user|hkey_local_machine|hkey_classes_root|hkey_users)(?::)?[\\/]+([^\"']+)[\"']")


def reg_paths(cmd):
    class M:
        def __init__(self, hive, rest):
            self._g = (None, hive, rest)

        def group(self, i):
            return self._g[i]
    out = [M(m.group(1), m.group(2).strip()) for m in QUOTED_REG.finditer(cmd)]
    rest = QUOTED_REG.sub(" ", cmd)
    out += [M(m.group(1), m.group(2)) for m in REG_PATH.finditer(rest)]
    return out


def norm_path(hive, rest):
    rest = rest.replace("/", "\\").strip("\\").rstrip("\\").lower()
    rest = re.sub(r"^software\\wow6432node\\", "software\\\\", rest)
    return hive, rest


def covered(hive, rest):
    for h, pre in GUARD:
        if hive == h and (rest == pre or rest.startswith(pre + "\\")):
            return True
        if hive == "HKCR" and h == "HKLM" and ("software\\classes\\" + rest).startswith(pre) :
            return True
    return False


def scan_test(t):
    cmd, clean = t["command"] or "", t["cleanup"] or ""
    out = {"id": t["technique_id"], "name": t["name"], "hasCleanup": bool(clean.strip()), "findings": []}
    if REG_WRITE.search(cmd):
        seen = set()
        for m in reg_paths(cmd):
            hive, rest = norm_path(HIVES[m.group(1).lower()], m.group(2))
            if "#{" in rest or rest.startswith("$") or not rest:
                rest = rest if rest else ""
            key = (hive, rest)
            if key in seen:
                continue
            seen.add(key)
            if hive == "HKU":
                out["findings"].append({"kind": "registry", "path": "HKU\\" + rest, "covered": False,
                                        "note": "HKEY_USERS write: not in the guard's roots"})
                continue
            out["findings"].append({"kind": "registry", "path": hive + "\\" + rest, "covered": covered(hive, rest)})
    for kind, (rx, status, why) in KINDS.items():
        if rx.search(cmd):
            out["findings"].append({"kind": kind, "covered": status == "yes", "restored": status, "note": why})
    return out


def main():
    atomics = [t for t in json.load(open(sys.argv[1], encoding="utf8")) if t["platform"] == "windows"]
    results = [scan_test(t) for t in atomics]
    json.dump({"tests": len(results), "results": results}, open(sys.argv[2], "w", encoding="utf8"), indent=1, ensure_ascii=False)
    flagged = [r for r in results if r["findings"]]
    print("windows tests: %d, with a persistent change found: %d" % (len(results), len(flagged)))


if __name__ == "__main__":
    main()
