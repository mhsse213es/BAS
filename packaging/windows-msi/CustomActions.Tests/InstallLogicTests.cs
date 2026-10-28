using System;
using Audspect.Installer;
using Xunit;

public class InstallLogicTests
{
    const string Fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void ValidInputsPass()
        => Assert.Null(InstallLogic.ValidateInstallInputs(@"C:\x\deployment.json", Fp, "s3cret", _ => true));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("abcd")]
    [InlineData("zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    public void MissingOrMalformedFingerprintFailsClosed(string fp)
        => Assert.NotNull(InstallLogic.ValidateInstallInputs(@"C:\x\d.json", fp, "s3cret", _ => true));

    [Fact]
    public void FormattedFingerprintIsAccepted()
        => Assert.Null(InstallLogic.ValidateInstallInputs("d.json", "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF", "s", _ => true));

    [Fact]
    public void MissingConfigFileFails()
        => Assert.NotNull(InstallLogic.ValidateInstallInputs("d.json", Fp, "s3cret", _ => false));

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("two\nlines")]
    [InlineData("tab\tchar")]
    public void MissingOrMalformedSecretFails(string secret)
        => Assert.NotNull(InstallLogic.ValidateInstallInputs("d.json", Fp, secret, _ => true));

    [Fact]
    public void OverlongSecretFails()
        => Assert.NotNull(InstallLogic.ValidateInstallInputs("d.json", Fp, new string('a', 4097), _ => true));

    [Fact]
    public void ErrorMessagesNeverContainTheSecret()
    {
        var m = InstallLogic.ValidateInstallInputs("d.json", "bad", "TOPSECRET-VALUE", _ => true);
        Assert.DoesNotContain("TOPSECRET-VALUE", m);
    }

    [Fact]
    public void ArgsCarryConfigAndFingerprintButNeverTheSecret()
    {
        var a = InstallLogic.BuildInstallArgs(@"C:\Program Files\x y\deployment.json", "01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF");
        Assert.Contains("--install", a);
        Assert.Contains("--secret-stdin", a);
        Assert.Contains("--config \"" + @"C:\Program Files\x y\deployment.json" + "\"", a);
        Assert.Contains("--config-fingerprint 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", a);
        Assert.DoesNotContain("--secret ", a);
    }

    [Fact]
    public void RedactReplacesEverySecretOccurrence()
        => Assert.Equal("a *** b *** c", InstallLogic.Redact("a hunter2 b hunter2 c", "hunter2"));

    [Fact]
    public void RedactWithEmptySecretIsNoop()
        => Assert.Equal("abc", InstallLogic.Redact("abc", ""));

    [Theory]
    [InlineData(20, "invalid")]
    [InlineData(21, "reach")]
    [InlineData(22, "secret")]
    [InlineData(23, "certificate")]
    [InlineData(24, "CA")]
    [InlineData(25, "fingerprint")]
    [InlineData(28, "Force Remove")]
    public void ExitCodesHaveDistinctActionableMessages(int code, string fragment)
        => Assert.Contains(fragment, InstallLogic.DescribeExitCode(code), StringComparison.OrdinalIgnoreCase);

    // The wizard dialog must show what the agent itself reported (it names the host and port it could not reach),
    // not only the generic line for the exit code.
    [Fact]
    public void PreflightFailureMessageShowsTheAgentsOwnDetail()
    {
        var m = InstallLogic.PreflightFailureMessage(21, "cannot reach the server at audspecterver:9444: check the URL, port and firewall", false);
        Assert.Contains("exit code 21", m);
        Assert.Contains("audspecterver:9444", m);
        Assert.Contains("could not be reached", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PreflightFailureMessageForAnUnreachableServerMentionsSecuritySoftware()
    {
        var m = InstallLogic.PreflightFailureMessage(21, "", false);
        Assert.Contains("antivirus", m, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ProgramData", m);
    }

    [Fact]
    public void PreflightFailureMessageOmitsTheDetailWhenThereIsNone()
    {
        var m = InstallLogic.PreflightFailureMessage(22, "", false);
        Assert.DoesNotContain("Detail", m);
        Assert.Contains("secret", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PreflightFailureMessageKeepsLongOutputBounded()
    {
        var m = InstallLogic.PreflightFailureMessage(21, new string('x', 5000) + Environment.NewLine + "second line", false);
        Assert.True(m.Length < 1200, "message length " + m.Length);
        Assert.DoesNotContain("second line", m);
    }

    [Fact]
    public void PreflightFailureMessageSaysSoWhenTheCheckTimedOut()
    {
        var m = InstallLogic.PreflightFailureMessage(-1, "", true);
        Assert.Contains("did not finish", m, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RunAgentPassesSecretOnStdinAndRedactsOutput()
    {
        const string ps = "-NoProfile -NonInteractive -Command \"$s=[Console]::In.ReadLine(); Write-Output ('echo:'+$s); if ($s -eq 'topsecret') {exit 0} else {exit 22}\"";
        var r = InstallLogic.RunAgent("powershell.exe", ps, "topsecret", 30000);
        Assert.Equal(0, r.ExitCode);
        Assert.DoesNotContain("topsecret", r.Output);
        Assert.Contains("echo:***", r.Output);
    }

    [Fact]
    public void RunAgentReportsNonZeroExit()
    {
        var r = InstallLogic.RunAgent("powershell.exe", "-NoProfile -Command \"exit 22\"", "x", 30000);
        Assert.Equal(22, r.ExitCode);
    }

    [Fact]
    public void RunAgentTimesOutAndKills()
    {
        var r = InstallLogic.RunAgent("powershell.exe", "-NoProfile -Command \"Start-Sleep 30\"", "x", 1500);
        Assert.True(r.TimedOut);
        Assert.NotEqual(0, r.ExitCode);
    }

    [Fact]
    public void RunAgentMissingExecutableFailsCleanly()
    {
        var r = InstallLogic.RunAgent(@"C:\nope\missing.exe", "", "x", 5000);
        Assert.NotEqual(0, r.ExitCode);
        Assert.False(string.IsNullOrEmpty(r.Output));
    }

    [Fact]
    public void ConfigPageRequiresExistingFileAndValidFingerprintButNoSecret()
    {
        Assert.Null(InstallLogic.ValidateConfigPageInputs("d.json", Fp, _ => true));
        Assert.NotNull(InstallLogic.ValidateConfigPageInputs("d.json", Fp, _ => false));
        Assert.NotNull(InstallLogic.ValidateConfigPageInputs("d.json", "", _ => true));
        Assert.NotNull(InstallLogic.ValidateConfigPageInputs("", Fp, _ => true));
    }

    [Fact]
    public void IdentityStatusAndResetArgsUseTheConfigAndNeverTheSecretOnTheCommandLine()
    {
        Assert.Equal("--identity-status --config \"d.json\" --config-fingerprint " + Fp, InstallLogic.BuildIdentityStatusArgs("d.json", Fp));
        var r = InstallLogic.BuildResetIdentityArgs("d.json", Fp);
        Assert.Equal("--reset-identity --config \"d.json\" --config-fingerprint " + Fp + " --secret-stdin", r);
        Assert.DoesNotContain("--secret ", r);
        Assert.Throws<ArgumentException>(() => InstallLogic.BuildResetIdentityArgs("a\"b.json", Fp));
    }

    [Theory]
    [InlineData(29, true)]
    [InlineData(0, false)]
    [InlineData(25, false)]
    [InlineData(1, false)]
    public void OnlyExitCode29MeansTheIdentityIsStale(int code, bool stale)
        => Assert.Equal(stale, InstallLogic.IdentityIsStale(code));

    [Fact]
    public void VerifyAndPreflightArgsUseTheConfigAndNeverTheSecret()
    {
        var v = InstallLogic.BuildVerifyArgs("d.json", Fp);
        Assert.Equal("--verify-config --config \"d.json\" --config-fingerprint " + Fp, v);
        var p = InstallLogic.BuildPreflightArgs("d.json", Fp);
        Assert.Equal("--preflight --config \"d.json\" --config-fingerprint " + Fp + " --secret-stdin", p);
        Assert.DoesNotContain("--secret ", p);
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(25, false)]
    public void PreflightOkOnlyForExitZero(int code, bool ok)
        => Assert.Equal(ok, InstallLogic.PreflightPassed(code));

    [Fact]
    public void SkipPreflightHonouredOnlyWhenExactlyOne()
    {
        Assert.True(InstallLogic.SkipPreflight("1"));
        Assert.False(InstallLogic.SkipPreflight(""));
        Assert.False(InstallLogic.SkipPreflight("0"));
        Assert.False(InstallLogic.SkipPreflight("true"));
        Assert.False(InstallLogic.SkipPreflight(null));
    }

    [Fact]
    public void EnvLabelIsPassedOnlyWhenSafe()
    {
        var a = InstallLogic.BuildInstallArgs("d.json", Fp, "Staging 2");
        Assert.Contains("--env \"Staging 2\"", a);
        Assert.DoesNotContain("--env", InstallLogic.BuildInstallArgs("d.json", Fp, ""));
        Assert.DoesNotContain("--env", InstallLogic.BuildInstallArgs("d.json", Fp, null));
        foreach (var bad in new[] { "a\"b", "x & y", "a|b", "line"+(char)10+"break", new string('a', 65) })
            Assert.Throws<ArgumentException>(() => InstallLogic.BuildInstallArgs("d.json", Fp, bad));
        Assert.NotNull(InstallLogic.ValidateEnvLabel("bad;label"));
        Assert.Null(InstallLogic.ValidateEnvLabel("Production-1.a_b"));
        Assert.Null(InstallLogic.ValidateEnvLabel(""));
    }

    [Fact]
    public void SecretComesFromThePropertyElseTheEnvironment()
    {
        Assert.Equal("fromprop", InstallLogic.ResolveSecret("fromprop", "fromenv"));
        Assert.Equal("fromenv", InstallLogic.ResolveSecret("", "fromenv"));
        Assert.Equal("fromenv", InstallLogic.ResolveSecret(null, "fromenv"));
        Assert.Equal("", InstallLogic.ResolveSecret("", ""));
        Assert.Equal("", InstallLogic.ResolveSecret(null, null));
    }

    [Fact]
    public void TokenComesFromThePropertyElseTheEnvironmentAndIsOptional()
    {
        Assert.Equal("bas_enr_a", InstallLogic.ResolveToken("bas_enr_a", "bas_enr_env"));
        Assert.Equal("bas_enr_env", InstallLogic.ResolveToken("", "bas_enr_env"));
        Assert.Equal("", InstallLogic.ResolveToken(null, null));
        Assert.Equal(InstallLogic.TokenEnvVar, "AUDSPECT_ENROLLMENT_TOKEN");
    }

    [Theory]
    [InlineData("")]
    [InlineData("bas_enr_abcDEF-123_xyz")]
    public void ValidOrEmptyTokenPasses(string token) => Assert.Null(InstallLogic.ValidateToken(token));

    [Theory]
    [InlineData("has space")]
    [InlineData("line\nbreak")]
    [InlineData("tab\there")]
    public void MalformedTokenFailsWithoutEchoingIt(string token)
    {
        var msg = InstallLogic.ValidateToken(token);
        Assert.NotNull(msg);
        Assert.DoesNotContain(token, msg);
    }

    [Fact]
    public void OverlongTokenFails() => Assert.NotNull(InstallLogic.ValidateToken(new string('a', 1025)));

    [Fact]
    public void RunAgentPassesTheTokenInTheEnvironmentNotTheArgumentsAndRedactsIt()
    {
        var ps = "-NoProfile -Command \"Write-Output ('ENV=' + $env:BAS_ENROLLMENT_TOKEN); Write-Output ('ARGS=' + ($args -join ' '))\" ";
        var r = InstallLogic.RunAgent("powershell.exe", ps, "s3cret", 30000, "bas_enr_TOKENVALUE");
        Assert.DoesNotContain("TOKENVALUE", r.Output);
        Assert.Contains("ENV=***", r.Output);
    }

    [Fact]
    public void RunAgentWithoutATokenDoesNotInheritOne()
    {
        Environment.SetEnvironmentVariable("BAS_ENROLLMENT_TOKEN", "bas_enr_LEAKED");
        try
        {
            var r = InstallLogic.RunAgent("powershell.exe", "-NoProfile -Command \"Write-Output ('ENV=[' + $env:BAS_ENROLLMENT_TOKEN + ']')\"", "x", 30000);
            Assert.Contains("ENV=[]", r.Output);
        }
        finally { Environment.SetEnvironmentVariable("BAS_ENROLLMENT_TOKEN", null); }
    }

    [Fact]
    public void RefusedTokenAndUnreachableServerAreDescribedDifferently()
    {
        var refused = InstallLogic.DescribeExitCode(26);
        var unreachable = InstallLogic.DescribeExitCode(27);
        Assert.Contains("token", refused, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("refused", refused, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("could not be reached", unreachable, StringComparison.OrdinalIgnoreCase);
        Assert.NotEqual(refused, unreachable);
    }

    // The deployment.json lookup must not depend on [SourceDir], which is empty when the product is installed
    // from a package path after an uninstall: the installer then looked for a bare "deployment.json".
    [Theory]
    [InlineData("", @"C:\agent\AudspectAgent-x64.msi", @"C:\agent\deployment.json")]
    [InlineData("deployment.json", @"C:\agent\AudspectAgent-x64.msi", @"C:\agent\deployment.json")]
    [InlineData(@"C:\other\d.json", @"C:\agent\AudspectAgent-x64.msi", @"C:\other\d.json")]
    [InlineData(@"D:\media\", @"C:\agent\AudspectAgent-x64.msi", @"D:\media\deployment.json")]
    public void ConfigPathResolvesNextToTheMsiUnlessAFullPathWasGiven(string property, string originalDatabase, string expected)
        => Assert.Equal(expected, InstallLogic.ResolveConfigPath(property, originalDatabase));

    [Fact]
    public void ConfigPathWithNothingToGoOnStaysEmptyAndFailsValidationLater()
        => Assert.Equal("", InstallLogic.ResolveConfigPath("", ""));

    // One-prompt install: the fingerprint arrives in a file beside the MSI (written by the server that built the
    // bundle), so the person installing is asked for the agent secret only.
    const string Msi = @"C:\agent\AudspectAgent-x64.msi";

    [Fact]
    public void BundledFingerprintIsReadFromBesideTheMsi()
        => Assert.Equal(Fp, InstallLogic.ReadBundledFingerprint(Msi, p => p == @"C:\agent\deployment.fingerprint", p => "  " + Fp.ToUpperInvariant() + "\r\n"));

    [Fact]
    public void NoBundledFingerprintFileMeansTheWizardKeepsAskingForIt()
        => Assert.Null(InstallLogic.ReadBundledFingerprint(Msi, _ => false, _ => throw new InvalidOperationException()));

    [Theory]
    [InlineData("")]
    [InlineData("not a fingerprint")]
    [InlineData("0123abcd")]
    public void AMalformedBundledFingerprintIsNeverUsed(string content)
        => Assert.Null(InstallLogic.ReadBundledFingerprint(Msi, _ => true, _ => content));

    [Fact]
    public void ATokenIsRequestedOnlyWhenTheServerSaysSo()
    {
        Assert.True(InstallLogic.BundleRequiresToken(Msi, p => p == @"C:\agent\enrollment-token.required"));
        Assert.False(InstallLogic.BundleRequiresToken(Msi, _ => false));
    }

    // The agent (agent/pendingdelete.go: msiRemovingEnv) reads this name to know Windows Installer is removing its
    // executable; the two sides must agree or a delete-at-restart order is left behind.
    [Fact]
    public void TheMsiTellsTheAgentItIsRemovingTheFileThroughAnAgreedVariable()
        => Assert.Equal("BAS_REMOVED_BY_MSI", InstallLogic.MsiRemovingEnvVar);
}
