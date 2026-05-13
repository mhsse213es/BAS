namespace BAS.Server;

public static class ScoringEngine
{
    // Kill-chain phase weights (higher = deeper attacker penetration)
    private static int PhaseWeight(string? phase) => (phase ?? "").ToLowerInvariant() switch
    {
        var p when p.Contains("initial access")           => 1,
        var p when p.Contains("execution")                => 2,
        var p when p.Contains("defense evasion")          => 2,
        var p when p.Contains("persistence")              => 3,
        var p when p.Contains("privilege")                => 4,
        var p when p.Contains("credential")               => 5,
        var p when p.Contains("lateral")                  => 6,
        var p when p.Contains("command")                  => 6,
        var p when p.Contains("exfiltration") || p.Contains("c2") => 7,
        var p when p.Contains("impact")                   => 7,
        var p when p.Contains("post-compromise")          => 7,
        _ => 1
    };

    public static SimulationScore Compute(AgentReport report)
    {
        var cats      = report.Categories ?? new();
        var allChecks = cats.SelectMany(c => c.Checks ?? new()).ToList();
        if (allChecks.Count == 0)
            return new SimulationScore { Classification = "Unknown" };

        int ap = AttackProgression(cats);
        int os = ObjectiveSuccess(allChecks);
        int dt = DetectionTiming(cats);
        int br = BlastRadius(cats);
        int pe = PreventionEffectiveness(allChecks);

        int risk = Math.Clamp(ap + os + dt + br - pe, 0, 100);

        return new SimulationScore
        {
            RiskScore                = risk,
            Classification           = Classify(risk),
            Confidence               = Confidence(allChecks),
            ExecutionReliability     = Reliability(allChecks),
            AttackProgression        = ap,
            ObjectiveSuccess         = os,
            DetectionTiming          = dt,
            BlastRadius              = br,
            PreventionEffectiveness  = pe
        };
    }

    // ── Components ────────────────────────────────────────────────────

    // How far did the attack progress through the kill chain? (0–30)
    // Anchored to the deepest phase where any check was Fail.
    static int AttackProgression(List<SimulationCategory> cats)
    {
        int max = cats
            .Where(c => (c.Checks ?? new()).Any(ch => ch.Result == CheckResult.Fail))
            .Select(c => PhaseWeight(c.Phase))
            .DefaultIfEmpty(0)
            .Max();
        return (int)Math.Round(max / 7.0 * 30);
    }

    // How many attacker objectives succeeded? (0–25)
    // Fail = attacker succeeded; weighted by kill-chain depth.
    static int ObjectiveSuccess(List<SimCheck> checks)
    {
        int countable = checks.Count(c => c.Result != CheckResult.Skipped);
        if (countable == 0) return 0;
        int failed = checks.Count(c => c.Result == CheckResult.Fail);
        return (int)Math.Round((double)failed / countable * 25);
    }

    // How late did defenses respond? (0–25)
    // Early block = low score. Attacker slipping past multiple phases undetected = high score.
    static int DetectionTiming(List<SimulationCategory> cats)
    {
        int deepestFail  = cats
            .Where(c => (c.Checks ?? new()).Any(ch => ch.Result == CheckResult.Fail))
            .Select(c => PhaseWeight(c.Phase))
            .DefaultIfEmpty(0).Max();

        if (deepestFail == 0) return 0; // Nothing got through

        int firstDefense = cats
            .Where(c => (c.Checks ?? new()).Any(ch => ch.Result is CheckResult.Pass or CheckResult.Blocked))
            .Select(c => PhaseWeight(c.Phase))
            .DefaultIfEmpty(int.MaxValue).Min();

        if (firstDefense == int.MaxValue) return 25; // Never defended

        // Gap between deepest attacker success and earliest defense
        int gap = Math.Max(0, deepestFail - firstDefense);
        return (int)Math.Round(gap / 6.0 * 25);
    }

    // What access level did the attacker achieve? (0–20)
    static int BlastRadius(List<SimulationCategory> cats)
    {
        int deepestFail = cats
            .Where(c => (c.Checks ?? new()).Any(ch => ch.Result == CheckResult.Fail))
            .Select(c => PhaseWeight(c.Phase))
            .DefaultIfEmpty(0).Max();

        return deepestFail switch
        {
            >= 7 => 20,  // Exfiltration / Impact / Post-compromise
            >= 5 => 14,  // Credential access / C2
            >= 3 => 8,   // Persistence / Privilege escalation
            >= 1 => 3,   // Execution / Initial access
            _    => 0
        };
    }

    // How much of the attack did defenses prevent? Subtracted from score. (0–50)
    static int PreventionEffectiveness(List<SimCheck> checks)
    {
        int total = checks.Count;
        if (total == 0) return 0;
        int prevented = checks.Count(c => c.Result is CheckResult.Pass or CheckResult.Blocked);
        return (int)Math.Round((double)prevented / total * 50);
    }

    // What % of attacks were stopped by defenses? (0–100)
    // Pass = defense blocked the technique; Blocked = fully neutralized.
    // Higher = better protected. Inversely correlates with risk score.
    static int Confidence(List<SimCheck> checks)
    {
        int countable = checks.Count(c => c.Result != CheckResult.Skipped);
        if (countable == 0) return 0;
        int prevented = checks.Count(c => c.Result is CheckResult.Pass or CheckResult.Blocked);
        return (int)Math.Round((double)prevented / countable * 100);
    }

    // What % of attack techniques succeeded against defenses? (0–100)
    // Fail = attacker got through. Higher = more exposed. Correlates with risk score.
    static int Reliability(List<SimCheck> checks)
    {
        int countable = checks.Count(c => c.Result != CheckResult.Skipped);
        if (countable == 0) return 0;
        int failed = checks.Count(c => c.Result == CheckResult.Fail);
        return (int)Math.Round((double)failed / countable * 100);
    }

    static string Classify(int risk) => risk switch
    {
        <= 20 => "Protected",
        <= 40 => "Low Risk",
        <= 60 => "Medium Risk",
        <= 80 => "High Risk",
        _      => "Critical"
    };
}

public class SimulationScore
{
    public int    RiskScore                { get; set; }
    public string Classification           { get; set; } = "Unknown";
    public int    Confidence               { get; set; }
    public int    ExecutionReliability     { get; set; }
    // Components
    public int    AttackProgression        { get; set; }
    public int    ObjectiveSuccess         { get; set; }
    public int    DetectionTiming          { get; set; }
    public int    BlastRadius              { get; set; }
    public int    PreventionEffectiveness  { get; set; }
}
