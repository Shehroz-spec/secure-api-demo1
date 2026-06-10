using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureApiDemo.Models;

namespace SecureApiDemo.Data;

public class AppDbContext : IdentityDbContext<ApplicationUser>
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<SecurityAuditLog> SecurityAuditLogs => Set<SecurityAuditLog>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // ✅ Fix: Map all string properties to 'text' for PostgreSQL compatibility
        foreach (var entity in builder.Model.GetEntityTypes())
        {
            foreach (var property in entity.GetProperties())
            {
                if (property.ClrType == typeof(string))
                    property.SetColumnType("text");
            }
        }

        // RefreshToken configuration
        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(r => r.Id);
            entity.HasIndex(r => r.Token).IsUnique();
            entity.HasOne(r => r.User)
                  .WithMany(u => u.RefreshTokens)
                  .HasForeignKey(r => r.UserId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        // SecurityAuditLog configuration
        builder.Entity<SecurityAuditLog>(entity =>
        {
            entity.HasKey(s => s.Id);
        });
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        // Suppress pending model changes warning
        optionsBuilder.ConfigureWarnings(w =>
            w.Ignore(Microsoft.EntityFrameworkCore.Diagnostics
                .RelationalEventId.PendingModelChangesWarning));
    }
}
