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
    public void ExitCodesHaveDistinctActionableMessages(int code, string fragment)
        => Assert.Contains(fragment, InstallLogic.DescribeExitCode(code), StringComparison.OrdinalIgnoreCase);

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
}
