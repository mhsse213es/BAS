using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace BAS.Server;

public class SqlServerStore
{
    private readonly IDbContextFactory<BASDbContext> _dbFactory;
    private readonly ILogger<SqlServerStore> _logger;

    public SqlServerStore(IDbContextFactory<BASDbContext> dbFactory, ILogger<SqlServerStore> logger)
    {
        _dbFactory = dbFactory;
        _logger = logger;
    }

    // ========== AGENT OPERATIONS ==========

    public async Task<bool> PutAgentAsync(AgentHeartbeat agent)
    {
        try
        {
            using var db = await _dbFactory.CreateDbContextAsync();
            var record = await db.Agents.FindAsync(agent.AgentId);
            if (record == null)
            {
                record = new AgentRecord { AgentId = agent.AgentId };
                db.Agents.Add(record);
            }
            record.TenantId         = agent.TenantId ?? "default";
            record.Hostname         = agent.Hostname ?? "";
            record.IpAddress        = agent.IpAddress ?? "";
            record.OsVersion        = agent.OsVersion ?? "";
            record.Username         = agent.Username ?? "";
            record.Status           = agent.Status ?? "idle";
            record.EnvironmentLabel = agent.EnvironmentLabel ?? "Production";
            record.LastUpdate       = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to put agent {AgentId}", agent.AgentId);
            return false;
        }
    }

    public async Task<IEnumerable<AgentHeartbeat>> GetAllAgentsAsync(string? tenantId = null)
    {
        try
        {
            using var db = await _dbFactory.CreateDbContextAsync();
            var query = db.Agents.AsQueryable();
            if (tenantId != null)
                query = query.Where(a => a.TenantId == tenantId);
            var records = await query.OrderByDescending(a => a.LastUpdate).ToListAsync();
            return records.Select(ToHeartbeat);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get all agents");
            return Enumerable.Empty<AgentHeartbeat>();
        }
    }

    // ========== REPORT OPERATIONS ==========

    public async Task<bool> PutReportAsync(AgentReport report)
    {
        try
        {
            var tenantId = report.TenantId ?? "default";
            using var db = await _dbFactory.CreateDbContextAsync();

            // Mark agent as having a report
            var agentRecord = await db.Agents.FindAsync(report.AgentId);
            if (agentRecord != null)
            {
                agentRecord.HasReport  = true;
                agentRecord.Status     = report.Status.ToString();
                agentRecord.LastUpdate = DateTimeOffset.UtcNow;
            }

            // Upsert report
            var reportRecord = await db.Reports.FindAsync(report.AgentId);
            if (reportRecord == null)
            {
                reportRecord = new ReportRecord { AgentId = report.AgentId };
                db.Reports.Add(reportRecord);
            }
            reportRecord.TenantId          = tenantId;
            reportRecord.Hostname          = report.Hostname ?? "";
            reportRecord.IpAddress         = report.IpAddress ?? "";
            reportRecord.OsVersion         = report.OsVersion ?? "";
            reportRecord.Username          = report.Username ?? "";
            reportRecord.StartedAt         = report.StartedAt;
            reportRecord.Status            = report.Status.ToString();
            reportRecord.EnvironmentLabel  = report.EnvironmentLabel ?? "Production";
            reportRecord.SecurityToolsJson = JsonSerializer.Serialize(report.SecurityTools ?? new());
            reportRecord.CategoriesJson    = JsonSerializer.Serialize(report.Categories ?? new());
            reportRecord.ScoreJson         = JsonSerializer.Serialize(ScoringEngine.Compute(report));
            reportRecord.LastUpdate        = DateTimeOffset.UtcNow;

            await db.SaveChangesAsync();
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to put report for {AgentId}", report.AgentId);
            return false;
        }
    }

    public async Task<AgentReport?> GetReportAsync(string agentId, string? tenantId = null)
    {
        try
        {
            using var db = await _dbFactory.CreateDbContextAsync();
            var record = await db.Reports.FindAsync(agentId);
            if (record == null) return null;
            return ToReport(record);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get report for {AgentId}", agentId);
            return null;
        }
    }

    // ========== HELPERS ==========

    private static AgentHeartbeat ToHeartbeat(AgentRecord r) => new()
    {
        AgentId          = r.AgentId,
        TenantId         = r.TenantId,
        Hostname         = r.Hostname,
        IpAddress        = r.IpAddress,
        OsVersion        = r.OsVersion,
        Username         = r.Username,
        Status           = r.Status,
        EnvironmentLabel = r.EnvironmentLabel,
        HasReport        = r.HasReport,
        LastUpdate       = r.LastUpdate
    };

    private static AgentReport ToReport(ReportRecord r) => new()
    {
        AgentId         = r.AgentId,
        TenantId        = r.TenantId,
        Hostname        = r.Hostname,
        IpAddress       = r.IpAddress,
        OsVersion       = r.OsVersion,
        Username        = r.Username,
        StartedAt       = r.StartedAt,
        Status          = Enum.TryParse<SimulationStatus>(r.Status, out var s) ? s : SimulationStatus.Completed,
        EnvironmentLabel = r.EnvironmentLabel,
        SecurityTools   = JsonSerializer.Deserialize<List<SecurityTool>>(r.SecurityToolsJson) ?? new(),
        Categories      = JsonSerializer.Deserialize<List<SimulationCategory>>(r.CategoriesJson) ?? new(),
        Score           = string.IsNullOrEmpty(r.ScoreJson) || r.ScoreJson == "{}"
                            ? null
                            : JsonSerializer.Deserialize<SimulationScore>(r.ScoreJson),
        LastUpdate      = r.LastUpdate
    };
}
