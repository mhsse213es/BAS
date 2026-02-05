using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// 1. REGISTER SERVICES
builder.Services.AddSignalR(); 

builder.Services.AddSingleton<BASStore>(); 
builder.Services.AddProblemDetails();

builder.Services.ConfigureHttpJsonOptions(options => {
    options.SerializerOptions.PropertyNameCaseInsensitive = true; 
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

var app = builder.Build();

// 2. PIPELINE
app.UseStaticFiles();
app.MapHub<BASHub>("/bashub"); 

// Agent Heartbeat
app.MapPost("/api/heartbeat", async (AgentHeartbeat hb, BASStore store, IHubContext<BASHub> hub) =>
{
    store.Agents[hb.AgentId] = hb;
    await hub.Clients.All.SendAsync("agentUpdate", hb);
    return Results.Ok();
});

// Agent Report Upload
app.MapPost("/api/report", async (AgentReport report, BASStore store, IHubContext<BASHub> hub) =>
{
    report.Status = SimulationStatus.Completed;
    store.Reports[report.AgentId] = report; // Store by AgentId for easy lookup

    if (store.Agents.TryGetValue(report.AgentId, out var hb))
    {
        hb.Status = "done";
        store.Agents[report.AgentId] = hb;
    }
    // Notify dashboard that a report is ready
    await hub.Clients.All.SendAsync("reportReady", new { AgentId = report.AgentId, Hostname = report.Hostname });
    
});

app.MapGet("/api/agents", (BASStore store) => store.Agents.Values);
app.MapGet("/api/report/{id}", (string id, BASStore store) => 
    store.Reports.TryGetValue(id, out var report) ? Results.Ok(report) : Results.NotFound());

app.MapFallback(async (HttpContext ctx) => {
    ctx.Response.ContentType = "text/html; charset=utf-8";
    var path = Path.Combine(app.Environment.WebRootPath, "index.html");
    if (File.Exists(path)) await ctx.Response.SendFileAsync(path);
});

app.Run();
// ──────────────────────────────────────────────
// MODELS & STORE
// ──────────────────────────────────────────────
public class BASHub : Hub { }

public class BASStore {
    public ConcurrentDictionary<string, AgentHeartbeat> Agents { get; } = new();
    public ConcurrentDictionary<string, AgentReport> Reports { get; } = new();
}

public enum CheckResult { Pass, Fail, Skipped }
public enum SimulationStatus { Pending, Running, Completed, Error }

public class AgentHeartbeat {
    public string AgentId { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public string Username { get; set; } = "";
    public string Status { get; set; } = "idle";
}

public class AgentReport {
    public string AgentId { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string IpAddress { get; set; } = "";   // Required for Dashboard line 555
    public string OsVersion { get; set; } = "";   // Required for Dashboard line 556
    public string Username { get; set; } = "";    // Required for Dashboard line 557
    public DateTimeOffset StartedAt { get; set; } // Required for Dashboard line 558
    public SimulationStatus Status { get; set; }
    public List<SimulationCategory> Categories { get; set; } = new();
}

public class SimulationCategory {
    public string Name { get; set; } = "";
    public string Phase { get; set; } = ""; // Required for Dashboard line 597
    public List<SimCheck> Checks { get; set; } = new();
}

public class SimCheck {
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public CheckResult Result { get; set; }
    public string Details { get; set; } = "";
}