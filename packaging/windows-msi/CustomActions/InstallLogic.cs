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

        public const string SecretEnvVar = "AUDSPECT_AGENT_SECRET";

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

        public static string DescribeExitCode(int code)
        {
            switch (code)
            {
                case 20: return "The agent rejected its inputs as invalid.";
                case 21: return "The Audspect server could not be reached. Check the network, firewall and the server address.";
                case 22: return "The server rejected the agent secret. Check AGENT_SECRET.";
                case 23: return "The server's certificate is not trusted by the deployment CA. The connection was not made.";
                case 24: return "The deployment CA is invalid.";
                case 25: return "The deployment configuration was rejected: the signing key fingerprint did not match or the file is invalid. Do not install until an administrator confirms the fingerprint.";
                default: return "The agent installer failed (exit code " + code + ").";
            }
        }

        /// <summary>Runs an executable, writing <paramref name="secret"/> and a newline to its stdin.</summary>
        public static AgentRun RunAgent(string exe, string args, string secret, int timeoutMs)
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
            var sb = new StringBuilder();
            object gate = new object();
            Process p;
            try { p = Process.Start(psi); }
            catch (Win32Exception ex)
            {
                return new AgentRun { ExitCode = 1, Output = Redact("could not start " + Path.GetFileName(exe) + ": " + ex.Message, secret) };
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
                    return new AgentRun { ExitCode = 1, TimedOut = true, Output = Redact(Snapshot(sb, gate), secret) };
                }
                p.WaitForExit(); // flush async readers
                return new AgentRun { ExitCode = p.ExitCode, Output = Redact(Snapshot(sb, gate), secret) };
            }
        }

        static string Snapshot(StringBuilder sb, object gate) { lock (gate) return sb.ToString().Trim(); }
    }
}
