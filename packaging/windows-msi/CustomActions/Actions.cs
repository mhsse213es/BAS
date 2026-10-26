using System;
using System.IO;
using System.ServiceProcess;
using WixToolset.Dtf.WindowsInstaller;

namespace Audspect.Installer
{
    /// <summary>
    /// MSI custom actions. They only orchestrate; the agent executable does the
    /// real work (service registration, trust checks, enrollment inputs), so
    /// there is one implementation of those rules.
    ///
    /// The agent secret reaches the deferred action through CustomActionData in
    /// a property listed in MsiHiddenProperties (so the MSI log masks it) and
    /// is handed to the agent on stdin only.
    /// </summary>
    public class Actions
    {
        const string ServiceName = "Audspect Agent";
        const string LegacyServiceName = "BASAgent";
        const int AgentTimeoutMs = 120000;

        static bool ServiceExists(string name)
        {
            try
            {
                foreach (var s in ServiceController.GetServices())
                {
                    using (s) { if (string.Equals(s.ServiceName, name, StringComparison.OrdinalIgnoreCase)) return true; }
                }
            }
            catch (InvalidOperationException) { }
            return false;
        }

        static bool AgentServiceExists() => ServiceExists(ServiceName) || ServiceExists(LegacyServiceName);

        static void Fail(Session session, string message)
        {
            session.Log("Audspect: " + message);
            using (var rec = new Record(1)) { rec[1] = message; session.Message(InstallMessage.Error, rec); }
        }

        static string AgentExe(string installFolder) => Path.Combine(installFolder, "bas_agent.exe");

        /// <summary>
        /// Immediate: on a first install, validate the inputs and stage the data for the
        /// deferred action. When a service is already registered (upgrade, repair, or an
        /// agent installed by the legacy setup) nothing is required and nothing is staged.
        /// </summary>
        [CustomAction]
        public static ActionResult PrepareAgentInstall(Session session)
        {
            if (AgentServiceExists())
            {
                session.Log("Audspect: an agent service is already registered; keeping its enrollment and configuration.");
                session["AGENT_SERVICE_EXISTS"] = "1";
                return ActionResult.Success;
            }
            var config = InstallLogic.ResolveConfigPath(session["DEPLOYMENT_CONFIG"], session["OriginalDatabase"]);
            var fp = session["CONFIG_FINGERPRINT"];
            if (string.IsNullOrWhiteSpace(fp)) fp = InstallLogic.ReadBundledFingerprint(session["OriginalDatabase"], File.Exists, File.ReadAllText) ?? fp;
            var secret = InstallLogic.ResolveSecret(session["AGENT_SECRET"], Environment.GetEnvironmentVariable(InstallLogic.SecretEnvVar));
            var token = InstallLogic.ResolveToken(session["ENROLLMENT_TOKEN"], Environment.GetEnvironmentVariable(InstallLogic.TokenEnvVar));
            var problem = InstallLogic.ValidateInstallInputs(config, fp, secret, File.Exists) ?? InstallLogic.ValidateEnvLabel(session["ENV_LABEL"]) ?? InstallLogic.ValidateToken(token);
            if (problem != null) { Fail(session, problem); return ActionResult.Failure; }

            // Check connectivity, CA trust and the secret before changing anything, unless the
            // wizard's Test page already passed or an advanced user set SKIPPREFLIGHT=1.
            if (session["PREFLIGHT_OK"] != "1" && !InstallLogic.SkipPreflight(session["SKIPPREFLIGHT"]))
            {
                string dir = null;
                try
                {
                    var exe = ExtractAgent(session, out dir);
                    var run = InstallLogic.RunAgent(exe, InstallLogic.BuildPreflightArgs(config, fp), secret, 45000);
                    if (!string.IsNullOrEmpty(run.Output)) session.Log("Audspect preflight: " + run.Output);
                    if (run.TimedOut || !InstallLogic.PreflightPassed(run.ExitCode))
                    {
                        Fail(session, "Pre-install check failed (preflight exit code " + run.ExitCode + "): " + InstallLogic.DescribeExitCode(run.ExitCode));
                        return ActionResult.Failure;
                    }
                }
                catch (Exception ex) when (ex is InvalidOperationException || ex is IOException || ex is ArgumentException)
                {
                    Fail(session, "The pre-install check could not run: " + ex.Message);
                    return ActionResult.Failure;
                }
                finally { if (dir != null) TryDelete(dir); }
            }

            var data = new CustomActionData();
            data["exe"] = AgentExe(session["INSTALLFOLDER"]);
            data["config"] = config;
            data["fp"] = fp;
            data["secret"] = secret;
            data["token"] = token;
            data["env"] = session["ENV_LABEL"];
            session["RunAgentInstall"] = data.ToString();
            return ActionResult.Success;
        }

        /// <summary>Deferred (SYSTEM): registers the service through the agent. Secret on stdin only.</summary>
        [CustomAction]
        public static ActionResult RunAgentInstall(Session session)
        {
            var d = session.CustomActionData;
            var secret = d["secret"];
            string args;
            try { args = InstallLogic.BuildInstallArgs(d["config"], d["fp"], d["env"]); }
            catch (ArgumentException) { Fail(session, "The deployment configuration inputs are invalid."); return ActionResult.Failure; }

            session.Log("Audspect: registering the agent service (the secret is passed on stdin).");
            var run = InstallLogic.RunAgent(d["exe"], args, secret, AgentTimeoutMs, d["token"]);
            if (!string.IsNullOrEmpty(run.Output)) session.Log("Audspect agent output:\n" + run.Output);
            if (run.TimedOut) { Fail(session, "The agent installer did not finish in time."); return ActionResult.Failure; }
            if (run.ExitCode != 0) { Fail(session, InstallLogic.DescribeExitCode(run.ExitCode)); return ActionResult.Failure; }
            return ActionResult.Success;
        }

        /// <summary>Immediate: stages the data for the uninstall and rollback actions.</summary>
        [CustomAction]
        public static ActionResult PrepareAgentRemoval(Session session)
        {
            var data = new CustomActionData();
            data["exe"] = AgentExe(session["INSTALLFOLDER"]);
            var s = data.ToString();
            session["RunAgentUninstall"] = s;
            session["RollbackAgentInstall"] = s;
            session["RefreshAgentIntegrity"] = s;
            return ActionResult.Success;
        }

        static ActionResult Uninstall(Session session, bool failIfStillRegistered)
        {
            if (!AgentServiceExists()) return ActionResult.Success;
            var run = InstallLogic.RunAgent(session.CustomActionData["exe"], "--uninstall", "", AgentTimeoutMs);
            if (!string.IsNullOrEmpty(run.Output)) session.Log("Audspect agent output:\n" + run.Output);
            if (AgentServiceExists() && failIfStillRegistered)
            {
                Fail(session, "The agent service could not be removed (exit code " + run.ExitCode + "). Nothing was uninstalled.");
                return ActionResult.Failure;
            }
            return ActionResult.Success;
        }

        /// <summary>Deferred (SYSTEM): removes the service through the agent so the server is told and tray/run entries are cleaned.</summary>
        [CustomAction] public static ActionResult RunAgentUninstall(Session session) => Uninstall(session, true);

        /// <summary>Rollback: undoes a service registration made earlier in this transaction.</summary>
        [CustomAction] public static ActionResult RollbackAgentInstall(Session session) => Uninstall(session, false);

        /// <summary>Deferred (SYSTEM): after files are replaced on upgrade/repair, refresh the stored integrity hash.</summary>
        [CustomAction]
        public static ActionResult RefreshAgentIntegrity(Session session)
        {
            var run = InstallLogic.RunAgent(session.CustomActionData["exe"], "--refresh-integrity", "", 60000);
            if (!string.IsNullOrEmpty(run.Output)) session.Log("Audspect agent output:\n" + run.Output);
            if (run.ExitCode != 0) session.Log("Audspect: could not refresh the stored integrity hash (exit code " + run.ExitCode + "); the server-side manifest check is unaffected.");
            return ActionResult.Success;
        }

        // ── Wizard (UI sequence) ─────────────────────────────────────────────────

        /// <summary>Writes the agent embedded in the MSI (Binary table) to a private temp directory.</summary>
        static string ExtractAgent(Session session, out string dir)
        {
            dir = Path.Combine(Path.GetTempPath(), "audspect-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            var exe = Path.Combine(dir, "bas_agent.exe");
            using (var view = session.Database.OpenView("SELECT `Data` FROM `Binary` WHERE `Name`='AgentForPreflight'"))
            {
                view.Execute();
                using (var rec = view.Fetch())
                {
                    if (rec == null) throw new InvalidOperationException("the agent is not embedded in this installer");
                    rec.GetStream(1, exe);
                }
            }
            return exe;
        }

        static void TryDelete(string dir)
        {
            try { Directory.Delete(dir, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }

        /// <summary>
        /// Configuration page: verifies the signed deployment.json against the fingerprint the
        /// operator typed, using the agent's own verifier, and shows what it points at.
        /// Sets CONFIG_OK (1/0) and CONFIG_MESSAGE.
        /// </summary>
        /// <summary>
        /// Immediate (UI): when the server's download put deployment.json and its fingerprint beside the MSI, adopt both
        /// and run the normal configuration check, so the wizard can skip the configuration page and ask only for the
        /// agent secret. Also shows the token field when that server issues tokens. Anything missing or malformed
        /// leaves CONFIG_OK at 0 and the wizard asks as before.
        /// </summary>
        [CustomAction]
        public static ActionResult LoadBundledDeployment(Session session)
        {
            session["CONFIG_OK"] = "0";
            var msi = session["OriginalDatabase"];
            if (string.IsNullOrWhiteSpace(session["CONFIG_FINGERPRINT"]))
            {
                var fp = InstallLogic.ReadBundledFingerprint(msi, File.Exists, File.ReadAllText);
                if (fp == null) return ActionResult.Success;
                session["CONFIG_FINGERPRINT"] = fp;
            }
            if (string.IsNullOrWhiteSpace(session["DEPLOYMENT_CONFIG"]))
                session["DEPLOYMENT_CONFIG"] = InstallLogic.ResolveConfigPath("", msi);
            if (InstallLogic.BundleRequiresToken(msi, File.Exists)) session["SHOW_TOKEN"] = "1";
            return CheckDeploymentConfig(session);
        }

        [CustomAction]
        public static ActionResult CheckDeploymentConfig(Session session)
        {
            session["CONFIG_OK"] = "0";
            var config = InstallLogic.ResolveConfigPath(session["DEPLOYMENT_CONFIG"], session["OriginalDatabase"]);
            var fp = session["CONFIG_FINGERPRINT"];
            var problem = InstallLogic.ValidateConfigPageInputs(config, fp, File.Exists);
            if (problem != null) { session["CONFIG_MESSAGE"] = problem; return ActionResult.Success; }
            string dir = null;
            try
            {
                var exe = ExtractAgent(session, out dir);
                var run = InstallLogic.RunAgent(exe, InstallLogic.BuildVerifyArgs(config, fp), "", 30000);
                session["CONFIG_MESSAGE"] = run.TimedOut ? "The check did not finish in time." : (string.IsNullOrEmpty(run.Output) ? InstallLogic.DescribeExitCode(run.ExitCode) : run.Output);
                if (run.ExitCode == 0 && !run.TimedOut) session["CONFIG_OK"] = "1";
            }
            catch (Exception ex) when (ex is InvalidOperationException || ex is IOException || ex is ArgumentException)
            {
                session["CONFIG_MESSAGE"] = "The configuration could not be checked: " + ex.Message;
            }
            finally { if (dir != null) TryDelete(dir); }
            return ActionResult.Success;
        }

        /// <summary>
        /// Test connection page: runs the agent's preflight (TLS against the deployment CA,
        /// then the secret) with the secret on stdin. Sets PREFLIGHT_OK (1/0) and PREFLIGHT_MESSAGE.
        /// Nothing is installed or written.
        /// </summary>
        [CustomAction]
        public static ActionResult TestAgentConnection(Session session)
        {
            session["PREFLIGHT_OK"] = "0";
            var config = InstallLogic.ResolveConfigPath(session["DEPLOYMENT_CONFIG"], session["OriginalDatabase"]);
            var fp = session["CONFIG_FINGERPRINT"];
            var secret = InstallLogic.ResolveSecret(session["AGENT_SECRET"], Environment.GetEnvironmentVariable(InstallLogic.SecretEnvVar));
            var problem = InstallLogic.ValidateInstallInputs(config, fp, secret, File.Exists);
            if (problem != null) { session["PREFLIGHT_MESSAGE"] = problem; return ActionResult.Success; }
            string dir = null;
            try
            {
                var exe = ExtractAgent(session, out dir);
                var run = InstallLogic.RunAgent(exe, InstallLogic.BuildPreflightArgs(config, fp), secret, 45000);
                session["PREFLIGHT_MESSAGE"] = run.TimedOut ? "The connection test did not finish in time." : (string.IsNullOrEmpty(run.Output) ? InstallLogic.DescribeExitCode(run.ExitCode) : run.Output);
                if (InstallLogic.PreflightPassed(run.ExitCode) && !run.TimedOut) session["PREFLIGHT_OK"] = "1";
            }
            catch (Exception ex) when (ex is InvalidOperationException || ex is IOException || ex is ArgumentException)
            {
                session["PREFLIGHT_MESSAGE"] = "The connection test could not run: " + ex.Message;
            }
            finally { if (dir != null) TryDelete(dir); }
            return ActionResult.Success;
        }
    }
}
