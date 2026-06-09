using Microsoft.EntityFrameworkCore;
using SecureApiDemo.Functions.Models;

namespace SecureApiDemo.Functions.Data;

/// <summary>
/// Lightweight DbContext for Azure Functions.
/// Only includes tables the Functions need to access.
/// </summary>
public class FunctionsDbContext : DbContext
{
    public FunctionsDbContext(DbContextOptions<FunctionsDbContext> options)
        : base(options) { }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<SecurityAuditLog> SecurityAuditLogs => Set<SecurityAuditLog>();
    public DbSet<AppUser> Users => Set<AppUser>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Map to existing Identity tables
        modelBuilder.Entity<AppUser>().ToTable("AspNetUsers");
        modelBuilder.Entity<RefreshToken>().ToTable("RefreshTokens");
        modelBuilder.Entity<SecurityAuditLog>().ToTable("SecurityAuditLogs");
    }
}
