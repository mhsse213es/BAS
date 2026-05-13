using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using BAS.Server;
using System.Text.Json.Serialization;
using System.Collections.Concurrent;

var builder = WebApplication.CreateBuilder(args);

// 1. CONFIGURATION
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);
builder.Configuration.AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true);
builder.Configuration.AddEnvironmentVariables();

// 2. SQL SERVER
builder.Services.AddDbContextFactory<BASDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// 3. REGISTER SERVICES
builder.Services.AddSignalR();
builder.Services.AddHttpClient();
builder.Services.AddSingleton<SqlServerStore>();
builder.Services.AddProblemDetails();
builder.Services.AddHealthChecks();

// Increase body size limit for agent report uploads (reports can be large)
builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
{
    options.Limits.MaxRequestBodySize = 52_428_800; // 50 MB
});
builder.WebHost.UseKestrel(o => o.Limits.MaxRequestBodySize = 52_428_800);

builder.Services.ConfigureHttpJsonOptions(options => {
    options.SerializerOptions.PropertyNameCaseInsensitive = true;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var app = builder.Build();

// 4. ENSURE DATABASE SCHEMA EXISTS
// Uses EF Core's own connection so it hits the exact same SQL Server instance as all queries.
using (var scope = app.Services.CreateScope())
{
    var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<BASDbContext>>();
    using var db = factory.CreateDbContext();

    Console.WriteLine("[*] Verifying SQL Server schema...");
    try
    {
        // Open the connection EF uses — this is the authoritative connection
        var conn = db.Database.GetDbConnection();
        await conn.OpenAsync();

        Console.WriteLine($"[*] Connected to: {conn.DataSource}  Database: {conn.Database}");

        async Task Exec(string sql)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = sql;
            await cmd.ExecuteNonQueryAsync();
        }

        // Drop Agents table if LastUpdate column has wrong type (bigint from old EnsureCreated)
        await Exec(@"
            IF OBJECT_ID('dbo.Agents','U') IS NOT NULL
              AND NOT EXISTS (
                SELECT 1 FROM sys.columns c
                JOIN sys.types t ON c.user_type_id = t.user_type_id
                WHERE c.object_id = OBJECT_ID('dbo.Agents','U')
                  AND c.name = 'LastUpdate' AND t.name = 'datetimeoffset'
              )
            DROP TABLE dbo.Agents;");

        // Create Agents table if missing
        await Exec(@"
            IF OBJECT_ID('dbo.Agents','U') IS NULL
            CREATE TABLE dbo.Agents (
                AgentId          nvarchar(128)  NOT NULL CONSTRAINT PK_Agents  PRIMARY KEY,
                TenantId         nvarchar(128)  NOT NULL DEFAULT 'default',
                Hostname         nvarchar(256)  NOT NULL DEFAULT '',
                IpAddress        nvarchar(64)   NOT NULL DEFAULT '',
                OsVersion        nvarchar(256)  NOT NULL DEFAULT '',
                Username         nvarchar(256)  NOT NULL DEFAULT '',
                Status           nvarchar(64)   NOT NULL DEFAULT 'idle',
                EnvironmentLabel nvarchar(128)  NOT NULL DEFAULT 'Production',
                HasReport        bit            NOT NULL DEFAULT 0,
                LastUpdate       datetimeoffset NOT NULL DEFAULT SYSDATETIMEOFFSET()
            );");
        Console.WriteLine("[+] dbo.Agents — OK");

        // Drop Reports table if LastUpdate/StartedAt columns have wrong type
        await Exec(@"
            IF OBJECT_ID('dbo.Reports','U') IS NOT NULL
              AND NOT EXISTS (
                SELECT 1 FROM sys.columns c
                JOIN sys.types t ON c.user_type_id = t.user_type_id
                WHERE c.object_id = OBJECT_ID('dbo.Reports','U')
                  AND c.name = 'LastUpdate' AND t.name = 'datetimeoffset'
              )
            DROP TABLE dbo.Reports;");

        // Create Reports table if missing
        await Exec(@"
            IF OBJECT_ID('dbo.Reports','U') IS NULL
            CREATE TABLE dbo.Reports (
                AgentId           nvarchar(128)  NOT NULL CONSTRAINT PK_Reports PRIMARY KEY,
                TenantId          nvarchar(128)  NOT NULL DEFAULT 'default',
                Hostname          nvarchar(256)  NOT NULL DEFAULT '',
                IpAddress         nvarchar(64)   NOT NULL DEFAULT '',
                OsVersion         nvarchar(256)  NOT NULL DEFAULT '',
                Username          nvarchar(256)  NOT NULL DEFAULT '',
                StartedAt         datetimeoffset NOT NULL DEFAULT SYSDATETIMEOFFSET(),
                Status            nvarchar(64)   NOT NULL DEFAULT 'Completed',
                EnvironmentLabel  nvarchar(128)  NOT NULL DEFAULT 'Production',
                SecurityToolsJson nvarchar(max)  NOT NULL DEFAULT '[]',
                CategoriesJson    nvarchar(max)  NOT NULL DEFAULT '[]',
                ScoreJson         nvarchar(max)  NOT NULL DEFAULT '{}',
                LastUpdate        datetimeoffset NOT NULL DEFAULT SYSDATETIMEOFFSET()
            );");
        Console.WriteLine("[+] dbo.Reports — OK");

        // Verify both tables are queryable
        using var verifyCmd = conn.CreateCommand();
        verifyCmd.CommandText = "SELECT COUNT(*) FROM dbo.Agents; SELECT COUNT(*) FROM dbo.Reports;";
        await verifyCmd.ExecuteNonQueryAsync();
        Console.WriteLine("[+] Schema verified — server is ready.");

        await conn.CloseAsync();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[!!!] FATAL: Cannot create/verify schema: {ex.Message}");
        Console.WriteLine("[!!!] Fix the connection string in appsettings.json and restart.");
        throw; // Crash loudly — don't serve 500s on every request
    }
}

// 5. MIDDLEWARE PIPELINE
app.UseStaticFiles();

// 6. HEALTH CHECK ENDPOINT
app.MapHealthChecks("/health");

// 6. SIGNALR HUB
app.MapHub<BASHub>("/bashub");

// ─── In-memory patch install status (per agent) ───────────────────
var _patchStatuses = new ConcurrentDictionary<string, PatchInstallStatus>();
List<BAS.Server.CtiIoc> _cachedIocs = new();
DateTime _lastCtiFetch = DateTime.MinValue;

// 7. API ENDPOINTS

// Agent Heartbeat
app.MapPost("/api/heartbeat", async (AgentHeartbeat hb, SqlServerStore store, IHubContext<BASHub> hub) =>
{
    hb.TenantId = "default";
    await store.PutAgentAsync(hb);
    await hub.Clients.All.SendAsync("agentUpdate", hb);
    return Results.Ok();
});

// Agent Report Upload (partial with Status=Running, or final with Status=Completed)
app.MapPost("/api/report", async (AgentReport report, SqlServerStore store, IHubContext<BASHub> hub) =>
{
    report.TenantId = "default";
    await store.PutReportAsync(report);
    await hub.Clients.All.SendAsync("reportReady", new {
        AgentId = report.AgentId,
        Hostname = report.Hostname,
        Status  = report.Status.ToString()
    });
    return Results.Ok();
});

// Trigger scan via HTTP
app.MapPost("/api/scan/{id}", async (string id, IHubContext<BASHub> hub) =>
{
    await hub.Clients.All.SendAsync("command_scan", id);
    return Results.Accepted();
});

// Trigger patch installation via HTTP
app.MapPost("/api/install-patches/{agentId}", async (string agentId, IHubContext<BASHub> hub) =>
{
    _patchStatuses[agentId] = new PatchInstallStatus { Phase = "scanning", Log = "Command sent. Agent is searching for updates..." };
    await hub.Clients.All.SendAsync("patch_status_update", agentId, _patchStatuses[agentId]);
    await hub.Clients.All.SendAsync("command_install_patches", agentId);
    return Results.Accepted();
});

// CTI Feed Endpoint (Cached) - Exposes open-source threat intelligence to agents
app.MapGet("/api/cti/latest", async (IHttpClientFactory clientFactory) =>
{
    if (DateTime.UtcNow.Subtract(_lastCtiFetch).TotalHours < 1 && _cachedIocs.Count > 0)
        return Results.Ok(_cachedIocs);

    var iocs = new List<BAS.Server.CtiIoc>();
    try
    {
        var client = clientFactory.CreateClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("BAS-Architecture-Agent/1.0");
        var response = await client.GetStringAsync("https://urlhaus.abuse.ch/downloads/csv_recent/");
        var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            if (line.StartsWith("#")) continue;
            var parts = line.Split("\",\"");
            if (parts.Length > 2)
            {
                var url = parts[2].Trim('\"');
                if (url.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                    iocs.Add(new BAS.Server.CtiIoc { Type = "url", Value = url, Source = "URLhaus (Abuse.ch)", DateAdded = parts[1].Trim('\"') });
            }
            if (iocs.Count >= 10) break;
        }
        _cachedIocs = iocs;
        _lastCtiFetch = DateTime.UtcNow;
    }
    catch (Exception ex) { Console.WriteLine($"[!] Failed to pull CTI: {ex.Message}"); }
    return Results.Ok(_cachedIocs);
});

// Receive live patch status from agent
app.MapPost("/api/patch-status", async (PatchStatusUpdate update, IHubContext<BASHub> hub) =>
{
    var status = new PatchInstallStatus { Phase = update.Phase, Log = update.Log };
    _patchStatuses[update.AgentId] = status;
    await hub.Clients.All.SendAsync("patch_status_update", update.AgentId, status);
    return Results.Ok();
});

// Dashboard queries this on page load to restore current install state
app.MapGet("/api/patch-status/{agentId}", (string agentId) =>
{
    return _patchStatuses.TryGetValue(agentId, out var status)
        ? Results.Ok(status)
        : Results.Ok(new PatchInstallStatus { Phase = "idle", Log = "" });
});

// Get all agents
app.MapGet("/api/agents", async (SqlServerStore store) =>
{
    var agents = await store.GetAllAgentsAsync("default");
    return Results.Ok(agents);
});

// Get report by ID
app.MapGet("/api/report/{id}", async (string id, SqlServerStore store) =>
{
    var report = await store.GetReportAsync(id, "default");
    return report != null ? Results.Ok(report) : Results.NotFound();
});

// Download Agent endpoint (serves complete ZIP package)
app.MapGet("/api/download-agent", async (IWebHostEnvironment env) =>
{
    var agentZipPath = Path.Combine(env.WebRootPath, "downloads", "BASAgent.zip");
    if (!File.Exists(agentZipPath))
        return Results.NotFound("Agent package not found. Please build and package the agent first.");
    return Results.File(agentZipPath, "application/zip", "BASAgent.zip");
});

// Fallback to index.html
app.MapFallback(async (HttpContext ctx) => {
    ctx.Response.ContentType = "text/html; charset=utf-8";
    var path = Path.Combine(app.Environment.WebRootPath, "index.html");
    if (File.Exists(path)) await ctx.Response.SendFileAsync(path);
});

app.Run();

// ──────────────────────────────────────────────
// MODELS & STORE
// ──────────────────────────────────────────────
namespace BAS.Server
{
    public class BASHub : Hub {
        public async Task RequestAgentScan(string agentId)
        {
            await Clients.All.SendAsync("command_scan", agentId);
        }
    }


    public enum CheckResult { Pass, Fail, Skipped, Blocked }
    public enum SimulationStatus { Pending, Running, Completed, Error }

    public class AgentHeartbeat {
        public string? TenantId { get; set; }
        public string AgentId { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string IpAddress { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public string Username { get; set; } = "";
        public string Status { get; set; } = "idle";
        public string EnvironmentLabel { get; set; } = "Production";
        public bool HasReport { get; set; } = false;
        public DateTimeOffset LastUpdate { get; set; } = DateTimeOffset.UtcNow;
    }

    public class AgentReport {
        public string? TenantId { get; set; }
        public string AgentId { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string IpAddress { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public string Username { get; set; } = "";
        public DateTimeOffset StartedAt { get; set; }
        public SimulationStatus Status { get; set; }
        public string EnvironmentLabel { get; set; } = "Production";
        public List<SecurityTool> SecurityTools { get; set; } = new();
        public List<SimulationCategory> Categories { get; set; } = new();
        public SimulationScore? Score { get; set; }
        public DateTimeOffset LastUpdate { get; set; } = DateTimeOffset.UtcNow;
    }

    public class SecurityTool
    {
        public string Name    { get; set; } = "";
        public string Vendor  { get; set; } = "";
        public string Type    { get; set; } = "";   // AV | EDR | Firewall | HIDS | DLP | Other
        public string Status  { get; set; } = "";   // Active | Inactive | Unknown
    }

    public class SimulationCategory {
        public string Name { get; set; } = "";
        public string Phase { get; set; } = "";
        public List<SimCheck> Checks { get; set; } = new();
    }

    public class SimCheck {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string TechniqueId  { get; set; } = "";
        public CheckResult Result { get; set; }
        public string Severity     { get; set; } = "";
        public string ThreatImpact { get; set; } = "";
        public string Details { get; set; } = "";
        public string Remediation  { get; set; } = "";
        public long   DurationMs   { get; set; }
        public bool IsNew { get; set; } = true;
    }

    public class PatchInstallStatus
    {
        public string Phase { get; set; } = "idle";
        public string Log   { get; set; } = "";
    }

    public class PatchStatusUpdate
    {
        [JsonPropertyName("agentId")]  public string AgentId  { get; set; } = "";
        [JsonPropertyName("tenantId")] public string TenantId { get; set; } = "";
        [JsonPropertyName("phase")]    public string Phase    { get; set; } = "";
        [JsonPropertyName("log")]      public string Log      { get; set; } = "";
    }

    public class CtiIoc
    {
        public string Type { get; set; } = "";
        public string Value { get; set; } = "";
        public string Source { get; set; } = "";
        public string Severity { get; set; } = "High";
        public string DateAdded { get; set; } = "";
    }
}
