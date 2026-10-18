// bas-pshost: a custom PowerShell host for the application-control
// inprocess_hosting family.
//
// It hosts PowerShell through System.Management.Automation inside its own
// process, not powershell.exe. The test asks whether that custom host runs
// under Constrained Language Mode, and whether a type-creating operation
// (Add-Type) is blocked by it. It reports two facts on stdout:
//
//   HOST_LANGUAGE_MODE: <FullLanguage|ConstrainedLanguage|...>
//   HOST_ADDTYPE: <allowed|blocked>
//
// and echoes the marker argument so the caller can prove the host ran.
//
// This is a benign probe. It does not change any policy and it writes no files.
// Build with tools/inprocess-host/build.ps1, which uses the .NET Framework
// compiler already on Windows and does not download anything.

using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

internal static class BasPshost
{
    private static int Main(string[] args)
    {
        // --positive-control-constrained starts the runspace in Constrained
        // Language Mode explicitly. It exists only so the probe can be shown to
        // detect a restricted host. The scenario never passes it, so the
        // scenario measures the host as it is configured.
        bool positiveControl = Array.IndexOf(args, "--positive-control-constrained") >= 0;
        string marker = "BAS-SIM-INPROC";
        foreach (string a in args)
        {
            if (!a.StartsWith("--", StringComparison.Ordinal)) { marker = a; }
        }
        try
        {
            InitialSessionState iss = InitialSessionState.CreateDefault();
            if (positiveControl)
            {
                iss.LanguageMode = PSLanguageMode.ConstrainedLanguage;
            }
            using (Runspace rs = RunspaceFactory.CreateRunspace(iss))
            {
                rs.Open();

                string mode = Invoke(rs, "$ExecutionContext.SessionState.LanguageMode.ToString()");
                // Add-Type is the probe: it creates a type, which Constrained
                // Language Mode forbids. Success means the restriction is absent.
                string addType = Invoke(rs,
                    "try { Add-Type -TypeDefinition 'public class BasProbe { }' -ErrorAction Stop | Out-Null; 'allowed' } " +
                    "catch { 'blocked' }");

                Console.Out.WriteLine("HOST_LANGUAGE_MODE: " + mode.Trim());
                Console.Out.WriteLine("HOST_ADDTYPE: " + addType.Trim());
                Console.Out.WriteLine(marker);
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Out.WriteLine("HOST_ERROR: " + ex.GetType().Name);
            return 2;
        }
    }

    private static string Invoke(Runspace rs, string script)
    {
        using (PowerShell ps = PowerShell.Create())
        {
            ps.Runspace = rs;
            ps.AddScript(script);
            var results = ps.Invoke();
            var sb = new System.Text.StringBuilder();
            foreach (PSObject o in results)
            {
                sb.Append(o == null ? "" : o.ToString());
            }
            return sb.ToString();
        }
    }
}
