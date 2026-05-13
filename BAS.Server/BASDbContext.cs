using Microsoft.EntityFrameworkCore;

namespace BAS.Server;

public class BASDbContext : DbContext
{
    public BASDbContext(DbContextOptions<BASDbContext> options) : base(options) { }

    public DbSet<AgentRecord> Agents => Set<AgentRecord>();
    public DbSet<ReportRecord> Reports => Set<ReportRecord>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AgentRecord>(e =>
        {
            e.ToTable("Agents");
            e.HasKey(a => a.AgentId);
            e.Property(a => a.AgentId).HasMaxLength(128);
            e.Property(a => a.TenantId).HasMaxLength(128);
            e.Property(a => a.Hostname).HasMaxLength(256);
            e.Property(a => a.IpAddress).HasMaxLength(64);
            e.Property(a => a.OsVersion).HasMaxLength(256);
            e.Property(a => a.Username).HasMaxLength(256);
            e.Property(a => a.Status).HasMaxLength(64);
            e.Property(a => a.EnvironmentLabel).HasMaxLength(128);
        });

        modelBuilder.Entity<ReportRecord>(e =>
        {
            e.ToTable("Reports");
            e.HasKey(r => r.AgentId);
            e.Property(r => r.AgentId).HasMaxLength(128);
            e.Property(r => r.TenantId).HasMaxLength(128);
            e.Property(r => r.Hostname).HasMaxLength(256);
            e.Property(r => r.IpAddress).HasMaxLength(64);
            e.Property(r => r.OsVersion).HasMaxLength(256);
            e.Property(r => r.Username).HasMaxLength(256);
            e.Property(r => r.Status).HasMaxLength(64);
            e.Property(r => r.EnvironmentLabel).HasMaxLength(128);
            e.Property(r => r.SecurityToolsJson).HasColumnType("nvarchar(max)");
            e.Property(r => r.CategoriesJson).HasColumnType("nvarchar(max)");
            e.Property(r => r.ScoreJson).HasColumnType("nvarchar(max)");
        });
    }
}

public class AgentRecord
{
    public string AgentId          { get; set; } = "";
    public string TenantId         { get; set; } = "default";
    public string Hostname         { get; set; } = "";
    public string IpAddress        { get; set; } = "";
    public string OsVersion        { get; set; } = "";
    public string Username         { get; set; } = "";
    public string Status           { get; set; } = "idle";
    public string EnvironmentLabel { get; set; } = "Production";
    public bool   HasReport        { get; set; }
    public DateTimeOffset LastUpdate { get; set; }
}

public class ReportRecord
{
    public string AgentId            { get; set; } = "";
    public string TenantId           { get; set; } = "default";
    public string Hostname           { get; set; } = "";
    public string IpAddress          { get; set; } = "";
    public string OsVersion          { get; set; } = "";
    public string Username           { get; set; } = "";
    public DateTimeOffset StartedAt  { get; set; }
    public string Status             { get; set; } = "Completed";
    public string EnvironmentLabel   { get; set; } = "Production";
    public string SecurityToolsJson  { get; set; } = "[]";
    public string CategoriesJson     { get; set; } = "[]";
    public string ScoreJson          { get; set; } = "{}";
    public DateTimeOffset LastUpdate { get; set; }
}
