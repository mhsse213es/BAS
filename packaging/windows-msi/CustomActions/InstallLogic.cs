using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;

namespace Audspect.Installer
{
    /// <summary>Outcome of running the agent executable.</summary>
    public sealed class AgentRun
    {
        public int ExitCode;
        public string Output;   // already redacted
        public bool TimedOut;
    }

    /// <summary>
    /// Pure installer logic, kept out of the MSI session so it can be unit
    /// tested. The agent secret is only ever passed on the child's stdin: it is
    /// never part of the command line, and any text returned for logging is
    /// redacted.
    /// </summary>
    public static class InstallLogic
    {
        public const int MaxSecretLength = 4096;

        static string NormalizeFingerprint(string fp)
        {
            if (fp == null) return null;
            var c = new string(fp.Where(ch => ch != ':' && !char.IsWhiteSpace(ch)).ToArray()).ToLowerInvariant();
            return c.Length == 64 && c.All(ch => (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) ? c : null;
        }

        /// <summary>Written beside the MSI by the server that built the download: the signing-key fingerprint.</summary>
        public const string FingerprintFile = "deployment.fingerprint";

        /// <summary>Written beside the MSI only when the server issues enrolment tokens.</summary>
        public const string TokenMarkerFile = "enrollment-token.required";

        /// <summary>
        /// The fingerprint the server wrote beside the MSI, or null when there is no such file or its content is not
        /// a fingerprint (the wizard then asks for it as before; a bad file is never half-used).
        /// </summary>
        public static string ReadBundledFingerprint(string originalDatabase, Func<string, bool> exists, Func<string, string> read)
        {
            var dir = string.IsNullOrWhiteSpace(originalDatabase) ? null : Path.GetDirectoryName(originalDatabase);
            if (string.IsNullOrEmpty(dir)) return null;
            var path = Path.Combine(dir, FingerprintFile);
            if (!exists(path)) return null;
            try { return NormalizeFingerprint(read(path)); }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }

        /// <summary>True when the server that built this download issues enrolment tokens, so the wizard must ask for one.</summary>
        public static bool BundleRequiresToken(string originalDatabase, Func<string, bool> exists)
        {
            var dir = string.IsNullOrWhiteSpace(originalDatabase) ? null : Path.GetDirectoryName(originalDatabase);
            return !string.IsNullOrEmpty(dir) && exists(Path.Combine(dir, TokenMarkerFile));
        }

        public const string SecretEnvVar = "AUDSPECT_AGENT_SECRET";

        /// <summary>Set to 1 on the agent the uninstall action runs, so it leaves the executable to Windows Installer.</summary>
        public const string MsiRemovingEnvVar = "BAS_REMOVED_BY_MSI";

        /// <summary>Environment variable a silent install uses for the single-use enrolment token.</summary>
        public const string TokenEnvVar = "AUDSPECT_ENROLLMENT_TOKEN";

        /// <summary>Environment variable the agent reads its enrolment token from (child process only).</summary>
        const string AgentTokenEnvVar = "BAS_ENROLLMENT_TOKEN";

        public const int MaxTokenLength = 1024;

        /// <summary>
        /// Where deployment.json is. A full path given by the caller (or the wizard) is used as is; otherwise the
        /// file is looked for next to the MSI itself. [SourceDir] cannot be relied on for this: it is empty in a
        /// quiet install from a package path, which made the installer look for a bare "deployment.json".
        /// </summary>
        public static string ResolveConfigPath(string property, string originalDatabase)
        {
            const string fileName = "deployment.json";
            var p = (property ?? "").Trim();
            if (p.Length > 0 && Path.IsPathRooted(p))
                return p.EndsWith("\\") || p.EndsWith("/") ? Path.Combine(p, fileName) : p;
            var dir = string.IsNullOrWhiteSpace(originalDatabase) ? null : Path.GetDirectoryName(originalDatabase);
            if (string.IsNullOrEmpty(dir)) return p.Length == 0 ? "" : p;
            return Path.Combine(dir, p.Length == 0 || !p.EndsWith(".json", StringComparison.OrdinalIgnoreCase) ? fileName : p);
        }

        /// <summary>
        /// The ENROLLMENT_TOKEN property (typed in the wizard) wins; otherwise the environment variable of the
        /// msiexec process. A token is single use and bound to one host, so the generic installer never contains one
        /// and a silent install must supply it per host, through the environment and not a command-line property.
        /// </summary>
        public static string ResolveToken(string property, string environmentValue)
            => !string.IsNullOrEmpty(property) ? property : (environmentValue ?? "");

        /// <summary>Null when the token is empty (optional) or well formed; the message never contains the token.</summary>
        public static string ValidateToken(string token)
        {
            if (string.IsNullOrEmpty(token)) return null;
            if (token.Length > MaxTokenLength) return "The enrollment token is too long.";
            if (token.Any(ch => ch <= 0x20 || ch == 0x7f))
                return "The enrollment token must be a single word without spaces or control characters.";
            return null;
        }

        /// <summary>
        /// The AGENT_SECRET property (typed in the wizard) wins; otherwise the environment variable
        /// of the msiexec process. Silent installs should use the environment: a command-line
        /// property is visible in the process list of every user.
        /// </summary>
        public static string ResolveSecret(string property, string environmentValue)
            => !string.IsNullOrEmpty(property) ? property : (environmentValue ?? "");

        /// <summary>Returns null when the inputs are usable, otherwise a message that never contains the secret.</summary>
        public static string ValidateInstallInputs(string configPath, string fingerprint, string secret, Func<string, bool> fileExists)
        {
            if (string.IsNullOrWhiteSpace(configPath) || !fileExists(configPath))
                return "The signed deployment configuration (deployment.json) was not found next to the installer.";
            if (NormalizeFingerprint(fingerprint) == null)
                return "CONFIG_FINGERPRINT is required: the 64-character SHA-256 fingerprint shown in the Audspect dashboard.";
            if (string.IsNullOrEmpty(secret))
                return "AGENT_SECRET is required.";
            if (secret.Length > MaxSecretLength)
                return "AGENT_SECRET is too long.";
            if (secret.Any(ch => ch < 0x20 || ch == 0x7f))
                return "AGENT_SECRET must be a single line without control characters.";
            return null;
        }

        /// <summary>Null when the label is empty or uses only letters, digits, space, dot, underscore, hyphen (max 64).</summary>
        public static string ValidateEnvLabel(string label)
        {
            if (string.IsNullOrEmpty(label)) return null;
            if (label.Length > 64 || !label.All(ch => char.IsLetterOrDigit(ch) || ch == ' ' || ch == '.' || ch == '_' || ch == '-'))
                return "The environment label may contain only letters, digits, spaces, dots, underscores and hyphens (64 characters at most).";
            return null;
        }

        /// <summary>Command line for the agent. Contains the config path, fingerprint and optional label, never the secret.</summary>
        public static string BuildInstallArgs(string configPath, string fingerprint, string envLabel = null)
        {
            var fp = NormalizeFingerprint(fingerprint);
            if (fp == null) throw new ArgumentException("invalid fingerprint");
            if (configPath.IndexOf('"') >= 0) throw new ArgumentException("invalid config path");
            if (ValidateEnvLabel(envLabel) != null) throw new ArgumentException("invalid environment label");
            var env = string.IsNullOrEmpty(envLabel) ? "" : " --env \"" + envLabel + "\"";
            return "--install --config \"" + configPath + "\" --config-fingerprint " + fp + env + " --secret-stdin";
        }

        /// <summary>Config page check: no secret needed yet.</summary>
        public static string ValidateConfigPageInputs(string configPath, string fingerprint, Func<string, bool> fileExists)
        {
            if (string.IsNullOrWhiteSpace(configPath) || !fileExists(configPath))
                return "The signed deployment configuration (deployment.json) was not found.";
            if (NormalizeFingerprint(fingerprint) == null)
                return "Enter the 64-character SHA-256 fingerprint shown in the Audspect dashboard.";
            return null;
        }

        /// <summary>Asks the agent whether its installed identity belongs to the CA in the bundle; changes nothing.</summary>
        public static string BuildIdentityStatusArgs(string configPath, string fingerprint)
            => "--identity-status --config \"" + Checked(configPath) + "\" --config-fingerprint " + Fp(fingerprint);

        /// <summary>Re-enrols an installed agent whose identity belongs to a different CA; the secret goes on stdin.</summary>
        public static string BuildResetIdentityArgs(string configPath, string fingerprint)
            => "--reset-identity --config \"" + Checked(configPath) + "\" --config-fingerprint " + Fp(fingerprint) + " --secret-stdin";

        /// <summary>--identity-status exit code 29: the installed identity was not issued by the bundle's CA.</summary>
        public static bool IdentityIsStale(int exitCode) => exitCode == 29;

        public static string BuildVerifyArgs(string configPath, string fingerprint)
            => "--verify-config --config \"" + Checked(configPath) + "\" --config-fingerprint " + Fp(fingerprint);

        public static string BuildPreflightArgs(string configPath, string fingerprint)
            => "--preflight --config \"" + Checked(configPath) + "\" --config-fingerprint " + Fp(fingerprint) + " --secret-stdin";

        static string Checked(string path)
        {
            if (path == null || path.IndexOf('"') >= 0) throw new ArgumentException("invalid config path");
            return path;
        }

        static string Fp(string fingerprint)
        {
            var fp = NormalizeFingerprint(fingerprint);
            if (fp == null) throw new ArgumentException("invalid fingerprint");
            return fp;
        }

        public static bool PreflightPassed(int exitCode) => exitCode == 0;

        /// <summary>SKIPPREFLIGHT is an advanced escape hatch and only the exact value 1 enables it.</summary>
        public static bool SkipPreflight(string value) => value == "1";

        public static string Redact(string text, string secret)
        {
            if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(secret)) return text;
            return text.Replace(secret, "***");
        }

        static string RedactAll(string text, string secret, string token) => Redact(Redact(text, secret), token);

        public static string DescribeExitCode(int code)
        {
            switch (code)
            {
                case 20: return "The agent rejected its inputs as invalid.";
                case 21: return "The Audspect server could not be reached. Check the network, firewall and the server address.";
                case 22: return "The server rejected the agent secret. Check AGENT_SECRET.";
                case 23: return "The server's certificate is not trusted by the deployment CA. The connection was not made.";
                case 24: return "The deployment CA is invalid.";
                case 26: return "The server refused the enrollment token (invalid, expired, already used, or issued for a different host). Ask the administrator for a new token for this host.";
                case 27: return "The server could not be reached to enroll (this is a connection problem, not a token problem). Check the network, firewall and the enrolment port.";
                case 28: return "The server already has an active agent for this host and will not replace it on the shared secret alone. Ask an administrator to use Force Remove Agent for this host in the console, or to issue an enrollment token for it, then install again.";
                case 25: return "The deployment configuration was rejected: the signing key fingerprint did not match or the file is invalid. Do not install until an administrator confirms the fingerprint.";
                default: return "The agent installer failed (exit code " + code + ").";
            }
        }

        const int MaxDetailLength = 300;

        /// <summary>
        /// The text of the dialog shown when the pre-install check fails: the generic line for the exit code, then what the
        /// agent itself reported (it names the host and port it could not reach), cut to its first line and bounded. For an
        /// unreachable server it also says that antivirus or endpoint protection can block the check.
        /// </summary>
        public static string PreflightFailureMessage(int exitCode, string agentOutput, bool timedOut)
        {
            if (timedOut) return "Pre-install check failed: the check did not finish in time. Check the network and firewall, then try again.";
            var msg = "Pre-install check failed (preflight exit code " + exitCode + "): " + DescribeExitCode(exitCode);
            var detail = (agentOutput ?? "").Trim();
            var eol = detail.IndexOfAny(new[] { '\r', '\n' });
            if (eol >= 0) detail = detail.Substring(0, eol).Trim();
            if (detail.Length > MaxDetailLength) detail = detail.Substring(0, MaxDetailLength) + "...";
            if (detail.Length > 0) msg += " Detail: " + detail;
            if (exitCode == 21)
                msg += " If antivirus or other endpoint protection is running on this computer, it can also block the check: allow the folder C:\\ProgramData\\Audspect (or ask your administrator to), then try again.";
            return msg;
        }

        /// <summary>Runs an executable, writing <paramref name="secret"/> and a newline to its stdin.</summary>
        public static AgentRun RunAgent(string exe, string args, string secret, int timeoutMs, string token = null, bool msiRemoving = false)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            // The token goes to the child only through its own environment (never the command line); a token that
            // happens to be set in this process's environment is not passed on unless it was given explicitly.
            psi.EnvironmentVariables.Remove(AgentTokenEnvVar);
            if (!string.IsNullOrEmpty(token)) psi.EnvironmentVariables[AgentTokenEnvVar] = token;
            psi.EnvironmentVariables.Remove(MsiRemovingEnvVar);
            if (msiRemoving) psi.EnvironmentVariables[MsiRemovingEnvVar] = "1";
            var sb = new StringBuilder();
            object gate = new object();
            Process p;
            try { p = Process.Start(psi); }
            catch (Win32Exception ex)
            {
                var hint = ex.NativeErrorCode == 225
                    ? " Security software blocked the check. Allow the folder " + Path.GetDirectoryName(Path.GetDirectoryName(exe)) + " (or ask your administrator to), then press Verify again."
                    : "";
                return new AgentRun { ExitCode = 1, Output = RedactAll("could not start " + Path.GetFileName(exe) + ": " + ex.Message + hint, secret, token) };
            }
            using (p)
            {
                p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (gate) sb.AppendLine(e.Data); };
                p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (gate) sb.AppendLine(e.Data); };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();
                try
                {
                    var bytes = new UTF8Encoding(false).GetBytes((secret ?? "") + "\n");
                    p.StandardInput.BaseStream.Write(bytes, 0, bytes.Length);
                    p.StandardInput.BaseStream.Flush();
                    p.StandardInput.Close();
                }
                catch (IOException) { /* child exited before reading; its exit code explains why */ }

                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch (InvalidOperationException) { }
                    p.WaitForExit();
                    return new AgentRun { ExitCode = 1, TimedOut = true, Output = RedactAll(Snapshot(sb, gate), secret, token) };
                }
                p.WaitForExit(); // flush async readers
                return new AgentRun { ExitCode = p.ExitCode, Output = RedactAll(Snapshot(sb, gate), secret, token) };
            }
        }

        static string Snapshot(StringBuilder sb, object gate) { lock (gate) return sb.ToString().Trim(); }
    }
}
