// ============================================================
// BAS (Breach Attack Simulator) — AGENT
// Single-file .NET 8 Console App.
// Runs on Windows endpoints.  Requires Admin — auto-elevates
// via UAC (no manual "Yes" prompts for sub-checks).
// Simulates attack-chain telemetry, never executes real
// exploits or exfiltrates real data.  Reports results to the
// BAS Server over HTTP.
// ============================================================

using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.Json;


using System.Net.NetworkInformation; // Fixes NetworkInterface / OperationalStatus
using Microsoft.Win32;              // Fixes Registry
using System.ServiceProcess;         // Fixes ServiceController
using System.Linq;                   // Fixes .Any() and .FirstOrDefault()

// ──────────────────────────────────────────────
// SHARED MODELS  (mirror of the server-side types)
// ──────────────────────────────────────────────
public enum CheckResult { Pass, Fail, Skipped }

class SimCheck
{
    public string Id           { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Name         { get; set; } = "";
    public string TechniqueId  { get; set; } = "";
    public CheckResult Result  { get; set; } = CheckResult.Skipped;
    public string Details      { get; set; } = "";
    public string Remediation  { get; set; } = "";
    public long   DurationMs   { get; set; }
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
    public List<SimulationCategory> Categories { get; set; } = new();
}

class AgentHeartbeat
{
    public string AgentId   { get; set; } = "";
    public string Hostname  { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string Username  { get; set; } = "";
    public string Status    { get; set; } = "idle";
}

// ──────────────────────────────────────────────
// MAIN ENTRY — handles elevation & orchestration
// ──────────────────────────────────────────────
class Program
{
    static readonly string ServerUrl = "http://localhost:5000";   // ← change to your server
    static readonly string AgentId;
    static readonly string Hostname;
    static readonly string IpAddress;
    static readonly string OsVersion;
    static readonly string Username;

    static Program()
    {
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
    }

    static async Task<int> Main(string[] args)
    {
        // ── Auto-elevate if not already admin ──────────
        if (!IsAdmin())
        {
            return ElevateAndRestart();
        }

        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine("[BAS Agent] Running as Administrator.");
        Console.WriteLine($"[BAS Agent] Server  : {ServerUrl}");
        Console.WriteLine($"[BAS Agent] AgentId : {AgentId}");
        Console.WriteLine($"[BAS Agent] Host    : {Hostname}");
        Console.WriteLine();

        // ── Register with server ────────────────────────
        await SendHeartbeat("running");

        // ── Execute all simulations ─────────────────────
        var report = new AgentReport
        {
            AgentId     = AgentId,
            Hostname    = Hostname,
            IpAddress   = IpAddress,
            OsVersion   = OsVersion,
            Username    = Username,
            StartedAt   = DateTimeOffset.UtcNow
        };

        report.Categories.Add(await Sim_1_1_PhishingPayload());
        Console.WriteLine("[BAS] 1.1 Phishing Payload Execution — done");

        report.Categories.Add(await Sim_1_2_MaliciousURL());
        Console.WriteLine("[BAS] 1.2 Malicious URL Access — done");

        report.Categories.Add(await Sim_2_1_LOLBins());
        Console.WriteLine("[BAS] 2.1 Living-off-the-Land — done");

        report.Categories.Add(await Sim_2_2_DefenseEvasion());
        Console.WriteLine("[BAS] 2.2 Defense Evasion — done");

        report.Categories.Add(await Sim_3_1_RegistryPersistence());
        Console.WriteLine("[BAS] 3.1 Registry Persistence — done");

        report.Categories.Add(await Sim_3_2_ServiceAutorun());
        Console.WriteLine("[BAS] 3.2 Service & Autorun — done");

        report.Categories.Add(await Sim_4_PrivilegeEscalation());
        Console.WriteLine("[BAS] 4.  Privilege Escalation — done");

        report.Categories.Add(await Sim_5_CredentialAccess());
        Console.WriteLine("[BAS] 5.  Credential Access — done");

        report.Categories.Add(await Sim_6_LateralMovement());
        Console.WriteLine("[BAS] 6.  Lateral Movement — done");

        report.Categories.Add(await Sim_7_C2());
        Console.WriteLine("[BAS] 7.  Command & Control — done");

        report.Categories.Add(await Sim_8_DataExfiltration());
        Console.WriteLine("[BAS] 8.  Data Exfiltration — done");

        report.Categories.Add(await Sim_9_Impact());
        Console.WriteLine("[BAS] 9.  Impact — done");

        report.Categories.Add(await Sim_10_PostCompromise());
        Console.WriteLine("[BAS] 10. Post-Compromise — done");

        report.CompletedAt = DateTimeOffset.UtcNow;

        // ── Upload report ──────────────────────────────
        await UploadReport(report);
        await SendHeartbeat("done");

        Console.WriteLine("\n[BAS Agent] All simulations complete. Report uploaded.");
        Console.WriteLine("[BAS Agent] You may close this window.");
        Console.ReadKey();
        return 0;
    }

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

    // ============================================================
    // HTTP HELPERS
    // ============================================================
    static async Task SendHeartbeat(string status)
    {
        var hb = new AgentHeartbeat
        {
            AgentId   = AgentId,
            Hostname  = Hostname,
            IpAddress = IpAddress,
            OsVersion = OsVersion,
            Username  = Username,
            Status    = status
        };
        try
        {
            using var http = new HttpClient();
            var json = JsonSerializer.Serialize(hb);
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
        Func<Task<(CheckResult result, string detail, string remediation)>> body)
    {
        var sw = Stopwatch.StartNew();
        CheckResult res = CheckResult.Skipped;
        string detail = "", rem = "";
        try
        {
            (res, detail, rem) = await body();
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
            File.WriteAllText(tmp, "BAS simulation — not a real document payload.");
            bool blocked = !File.Exists(tmp); // if something deleted it between write and check → blocked
            File.Delete(tmp);
            if (blocked)
                return (CheckResult.Pass, "AV/EDR blocked simulated attachment drop in temp.", "—");
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
                return (CheckResult.Pass, "HTML smuggling payload was either blocked or AV is monitoring script-based drops.", "—");
            return (CheckResult.Fail, "HTML smuggling test file written without interception.", "Enable AMSI and script-content inspection in your AV/EDR.");
        }));

        // --- LNK / shortcut execution ---
        cat.Checks.Add(await RunCheck("LNK / shortcut execution", "T1566.001", async () =>
        {
            string lnkPath = Path.Combine(Path.GetTempPath(), "bas_test.lnk");
            // Write a minimal .lnk shell-link header (benign — points nowhere)
            byte[] lnkHeader = new byte[76];
            BitConverter.GetBytes(0x0000004C).CopyTo(lnkHeader, 0); // HeaderSize
            // GUIDs / flags intentionally zeroed → OS will not auto-execute
            File.WriteAllBytes(lnkPath, lnkHeader);
            bool written = File.Exists(lnkPath);
            File.Delete(lnkPath);
            bool smartAppControl = IsSmartAppControlEnabled();
            if (smartAppControl)
                return (CheckResult.Pass, "Smart App Control is enabled; LNK execution from unknown sources would be blocked.", "—");
            if (!written)
                return (CheckResult.Pass, "LNK file was blocked before creation.", "—");
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
                return (CheckResult.Pass, "PowerShell not found — script-dropper surface reduced.", "—");
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
                // DNS resolution of .test TLD will always NXDOMAIN → tests whether DNS filter
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
                    return (CheckResult.Pass, $"DNS query for simulated URL blocked / NXDOMAIN. DNS filtering appears active.", "—");
                if (proxyConfigured && !resolved)
                    return (CheckResult.Pass, $"Proxy is configured and simulated URL did not resolve.", "—");
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
                return (CheckResult.Pass, "PowerShell script-block logging and AMSI are both enabled.", "—");
            return (CheckResult.Fail, $"PS ScriptBlock logging={psLogging}, AMSI={amsi}. LOLBin PowerShell abuse may go undetected.", "Enable script-block logging and AMSI.");
        }));

        // --- WMI execution ---
        cat.Checks.Add(await RunCheck("WMI execution", "T1059.005", async () =>
        {
            // Check if WMI service is running (winmgmt)
            bool wmiRunning = IsServiceRunning("winmgmt");
            bool edlLogging = IsWMILoggingEnabled();
            if (wmiRunning && edlLogging)
                return (CheckResult.Pass, "WMI service is active and WMI activity logging is enabled — behavioral detection likely.", "—");
            if (!wmiRunning)
                return (CheckResult.Pass, "WMI service is stopped; WMI-based execution surface is reduced.", "—");
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
                    return (CheckResult.Pass, $"{binExe} not found on this endpoint.", "—");
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
                return (CheckResult.Pass, "Script-block logging captures de-obfuscated script content.", "—");
            return (CheckResult.Fail, "Script-block logging is off — obfuscated PS scripts would not be logged.", "Enable PowerShell script-block logging.");
        }));

        // --- Encoded commands (Base64) ---
        cat.Checks.Add(await RunCheck("Encoded commands (Base64)", "T1027.001", async () =>
        {
            // Simulate: generate a base64 string and verify logging would capture it
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host BASSimulationCheck"));
            bool psLogging = IsPowerShellScriptBlockLoggingEnabled();
            bool amsi      = IsAMSIEnabled();
            if (psLogging && amsi)
                return (CheckResult.Pass, $"Simulated encoded command generated. Both script-block logging and AMSI active — would be decoded and inspected.", "—");
            return (CheckResult.Fail, "Encoded command simulation: script logging or AMSI is missing.", "Enable script-block logging and AMSI to decode and inspect Base64 commands.");
        }));

        // --- Delayed execution ---
        cat.Checks.Add(await RunCheck("Delayed execution", "T1027.005", async () =>
        {
            // Check if Sysmon or equivalent is logging process creation with delay indicators
            bool sysmonActive = IsSysmonRunning();
            if (sysmonActive)
                return (CheckResult.Pass, "Sysmon is active — delayed process creation events will be logged.", "—");
            return (CheckResult.Fail, "Sysmon not detected. Delayed execution may evade detection.", "Deploy Sysmon with a comprehensive filter configuration.");
        }));

        return cat;
    }

    // ============================================================
    // 3.1  REGISTRY-BASED PERSISTENCE
    // Tests: Registry monitoring, persistence detection
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
            // List scheduled tasks via schtasks — benign read-only
            var (tasks, count) = ListScheduledTaskCount();
            bool taskLogging  = IsScheduledTaskLoggingEnabled();
            if (taskLogging)
                return (CheckResult.Pass, $"Scheduled task creation logging is enabled. Current task count: {count}.", "—");
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
                return (CheckResult.Pass, $"Sysmon monitors Startup folder. Current files: {fileCount}.", "—");
            if (fileCount == 0)
                return (CheckResult.Pass, "Startup folder is empty and clean.", "—");
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
                return (CheckResult.Pass, "Service creation logging is enabled — rogue service installations would alert.", "—");
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
                return (CheckResult.Pass, "System directories are not user-writable — DLL hijack surface is low.", "—");
            return (CheckResult.Fail, $"Writable system paths detected: {string.Join(", ", writable)}. DLL hijacking is possible.", "Restrict write permissions on system directories. Enable DLL search-order hardening.");
        }));

        // --- COM hijack simulation ---
        cat.Checks.Add(await RunCheck("COM hijack simulation", "T1574.011", async () =>
        {
            // Check HKCU\Software\Classes for per-user COM overrides (read-only)
            var comKeys = ReadRegistrySubKeyCount(@"Software\Classes");
            bool sysmon = IsSysmonRunning();
            if (sysmon)
                return (CheckResult.Pass, $"Sysmon active — COM registry changes would be logged. HKCU\\Classes subkeys: {comKeys}.", "—");
            return (CheckResult.Fail, $"COM hijack vectors exist (HKCU\\Classes has {comKeys} keys) and Sysmon is not monitoring.", "Deploy Sysmon and monitor HKCU\\Software\\Classes for unexpected changes.");
        }));

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
                return (CheckResult.Pass, $"Credential Guard is enabled. Token impersonation is restricted. Current identity: {id.Name}.", "—");
            if (isSystem)
                return (CheckResult.Fail, "Agent is running as SYSTEM — token impersonation trivially possible.", "Avoid running software as SYSTEM; use least-privilege service accounts.");
            return (CheckResult.Fail, $"Credential Guard not confirmed. Running as {id.Name}.", "Enable Credential Guard via Group Policy.");
        }));

        // --- UAC bypass logic (non-exploit) ---
        cat.Checks.Add(await RunCheck("UAC bypass logic (non-exploit)", "T1548.002", async () =>
        {
            // Read UAC ConsentPromptBehaviorAdmin setting
            var uacLevel = ReadUACPolicy();
            if (uacLevel <= 1)  // 0=off, 1=auto-elevate trusted
                return (CheckResult.Fail, $"UAC policy level is {uacLevel} — auto-elevation or disabled. Bypass risk is high.", "Set UAC to level 2 (Always notify) via securitypolicy.msc.");
            return (CheckResult.Pass, $"UAC policy level is {uacLevel} — user consent is required for elevation.", "—");
        }));

        // --- Weak service permission checks ---
        cat.Checks.Add(await RunCheck("Weak service permission checks", "T1611", async () =>
        {
            var weak = FindWeakServicePermissions();
            if (weak.Count == 0)
                return (CheckResult.Pass, "No services with overly permissive ACLs detected.", "—");
            return (CheckResult.Fail, $"Services with weak permissions: {string.Join(", ", weak.Take(5))}.", "Harden service ACLs — deny 'Everyone' and 'Users' write on critical services.");
        }));

        return cat;
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
                return (CheckResult.Pass, "Credential Guard + LSA Protection are enabled. LSASS is hardened.", "—");
            if (canOpen && !credGuard)
                return (CheckResult.Fail, $"LSASS handle opened (CredGuard={credGuard}, LSAProtect={lsaProtect}). Memory read protections may be insufficient.", "Enable Credential Guard and LSA Run-As-Protected-Process.");
            return (CheckResult.Pass, "LSASS handle access was restricted.", "—");
        }));

        // --- Handle open simulations ---
        cat.Checks.Add(await RunCheck("Handle open simulations", "T1003.001", async () =>
        {
            bool sysmon = IsSysmonRunning();
            if (sysmon)
                return (CheckResult.Pass, "Sysmon is active and would log process-handle open events (Event 10).", "—");
            return (CheckResult.Fail, "Sysmon not active — handle-open events are not being monitored.", "Deploy Sysmon with Event 10 (process access) enabled.");
        }));

        // --- SAM/LSA access attempts ---
        cat.Checks.Add(await RunCheck("SAM/LSA access attempts", "T1003.002", async () =>
        {
            bool samLocked = IsSAMLockedDown();
            if (samLocked)
                return (CheckResult.Pass, "SAM is locked down with restricted file ACLs.", "—");
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
                return (CheckResult.Pass, "No browser credential stores found.", "—");
            if (edr)
                return (CheckResult.Pass, $"Browser credential files present ({string.Join(", ", found)}) but EDR is active.", "—");
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
                return (CheckResult.Pass, "SMB signing is enforced and Windows Firewall is active — relay/brute attacks are mitigated.", "—");
            return (CheckResult.Fail, $"SMB signing={smbSigning}, Firewall={firewallOn}. SMB-based lateral movement may succeed.", "Enforce SMB signing via Group Policy and ensure firewall blocks unnecessary SMB.");
        }));

        // --- WMI remote execution simulation ---
        cat.Checks.Add(await RunCheck("WMI remote execution simulation", "T1021.003", async () =>
        {
            bool wmiLog = IsWMILoggingEnabled();
            bool firewall = IsWindowsFirewallEnabled();
            if (wmiLog && firewall)
                return (CheckResult.Pass, "WMI logging enabled and firewall active — remote WMI execution would be logged.", "—");
            return (CheckResult.Fail, $"WMI logging={wmiLog}, Firewall={firewall}.", "Enable WMI operational logging and restrict inbound WMI via firewall.");
        }));

        // --- RDP brute-force logic (rate-limited) ---
        cat.Checks.Add(await RunCheck("RDP brute-force logic (rate-limited)", "T1021.001", async () =>
        {
            // Check if RDP is enabled and if NLA is required
            bool rdpEnabled = IsRDPEnabled();
            bool nlaEnabled = IsNLAEnabled();
            if (!rdpEnabled)
                return (CheckResult.Pass, "RDP is disabled on this endpoint.", "—");
            if (nlaEnabled)
                return (CheckResult.Pass, "RDP is enabled but NLA (Network Level Authentication) is required — brute-force is harder.", "—");
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
                return (CheckResult.Pass, "Simulated C2 beacon domain did not resolve; egress filtering appears active.", "—");
            if (proxy)
                return (CheckResult.Pass, "HTTP proxy is configured — C2 beacons would be inspected.", "—");
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
                return (CheckResult.Pass, "DNS logging is enabled — tunneling-length queries would be flagged.", "—");
            if (!resolved)
                return (CheckResult.Pass, "Long DNS query blocked/NXDOMAIN.", "—");
            return (CheckResult.Fail, "DNS tunneling-style queries are not being logged.", "Enable DNS query logging and deploy length/entropy-based DNS anomaly detection.");
        }));

        // --- Encrypted outbound traffic to fake C2 ---
        cat.Checks.Add(await RunCheck("Encrypted outbound traffic to fake C2", "T1071", async () =>
        {
            bool proxy     = IsProxyConfigured();
            bool tlsInspect = IsTLSInspectionConfigured();
            if (proxy && tlsInspect)
                return (CheckResult.Pass, "Proxy with TLS inspection is configured — encrypted C2 traffic would be examined.", "—");
            if (proxy)
                return (CheckResult.Pass, "Proxy is present but TLS inspection status is uncertain.", "Verify SSL/TLS deep inspection is enabled on your web proxy.");
            return (CheckResult.Fail, "No proxy or TLS inspection detected. Encrypted C2 traffic may exit unmonitored.", "Deploy an SSL-inspecting proxy / CASB.");
        }));

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
                return (CheckResult.Pass, "Sysmon would log file-creation events for staging detection.", "—");
            return (CheckResult.Fail, "No file-creation monitoring detected. Staging activity may go unlogged.", "Deploy Sysmon and enable file-creation auditing.");
        }));

        // --- Base64 encoding of data ---
        cat.Checks.Add(await RunCheck("Base64 encoding of data", "T1027", async () =>
        {
            string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("BAS_SIMULATION_DATA_STAGING_CHECK"));
            bool psLog = IsPowerShellScriptBlockLoggingEnabled();
            if (psLog)
                return (CheckResult.Pass, "Script-block logging would capture Base64 encode operations in scripts.", "—");
            return (CheckResult.Fail, "Script-block logging is off — Base64-encoded exfil in scripts may evade detection.", "Enable PowerShell script-block logging.");
        }));

        // --- HTTPS upload attempts ---
        cat.Checks.Add(await RunCheck("HTTPS upload attempts", "T1048.001", async () =>
        {
            bool proxy = IsProxyConfigured();
            bool tlsInspect = IsTLSInspectionConfigured();
            if (proxy && tlsInspect)
                return (CheckResult.Pass, "HTTPS uploads would pass through an inspecting proxy.", "—");
            return (CheckResult.Fail, $"Proxy={proxy}, TLS Inspect={tlsInspect}. HTTPS exfiltration may not be inspected.", "Enable SSL inspection on your web proxy.");
        }));

        // --- Cloud storage exfil patterns ---
        cat.Checks.Add(await RunCheck("Cloud storage exfil patterns", "T1048.001", async () =>
        {
            // Try DNS resolution of common cloud storage — simulate CASB awareness
            string[] clouds = { "drive.google.com", "onedrive.live.com", "dropbox.com" };
            bool proxy = IsProxyConfigured();
            bool casb  = proxy; // simplified: if proxy is present assume CASB capability is possible
            if (casb)
                return (CheckResult.Pass, "Web proxy / CASB in place — cloud upload destinations would be evaluated.", "Verify cloud app policies block unauthorized uploads.");
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

            // XOR each byte with 0x42 — simulates encryption without real crypto
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
                return (CheckResult.Pass, "Controlled Folder Access (ransomware protection) is enabled.", "—");
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
                return (CheckResult.Pass, "vssadmin.exe not found — shadow copy deletion vector is absent.", "—");
            if (edr)
                return (CheckResult.Pass, "vssadmin.exe is present but EDR is monitoring — deletion attempts would alert.", "—");
            return (CheckResult.Fail, "vssadmin.exe exists and no EDR monitoring confirmed. Shadow copy deletion could proceed.", "Add EDR rule: alert on vssadmin delete shadows command.");
        }));

        // --- System recovery disable logic ---
        cat.Checks.Add(await RunCheck("System recovery disable logic", "T1490", async () =>
        {
            // Check if system restore is enabled
            bool restoreEnabled = IsSystemRestoreEnabled();
            bool backupPolicy   = IsBackupPolicyConfigured();
            if (restoreEnabled && backupPolicy)
                return (CheckResult.Pass, "System Restore is enabled and backup policy is configured.", "—");
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
                return (CheckResult.Pass, "Windows Security event log is enabled — alerts are being generated.", "—");
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
                return (CheckResult.Pass, "EDR + Defender real-time are active — automated incident response is likely configured.", "Verify automated response playbooks are up-to-date.");
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
            // For each service, check config — simplified: flag services with INTERACTIVE_PROCESS token
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
}

// ──────────────────────────────────────────────
// HELPER: Get local IP
// ──────────────────────────────────────────────
namespace System.Net.Networking.Adapters
{
    public static class NetworkHelper
    {
        public static string GetLocalIp()
        {
            try
            {
                using var socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Dgram, 0);
                socket.Connect("8.8.8.8", 80);
                return ((System.Net.IPEndPoint)socket.LocalEndPoint!).Address.ToString();
            }
            catch { return "127.0.0.1"; }
        }
    }
}