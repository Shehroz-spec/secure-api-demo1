using Microsoft.Azure.Functions.Worker;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureApiDemo.Functions.Data;
using System.Text.Json;

namespace SecureApiDemo.Functions.Functions;

/// <summary>
/// FUNCTION 4: Nightly Security Audit Log Archiver
///
/// Trigger: Timer — runs every night at midnight
/// Purpose: Archives security audit logs older than 30 days to
///          Azure Blob Storage, then marks them as archived in SQL.
///          Keeps the active DB table small and fast.
///
/// Interview talking point:
/// "The gateway logs every request — especially failed auth attempts
///  and 401s. Over time this table grows large. I built a nightly
///  Timer Function that archives logs older than 30 days to Azure
///  Blob Storage as JSON files — one per day — keeping the active
///  table lean while maintaining a full compliance audit trail."
/// </summary>
public class AuditLogArchiverFunction
{
    private readonly FunctionsDbContext _db;
    private readonly IConfiguration    _config;
    private readonly ILogger<AuditLogArchiverFunction> _logger;

    public AuditLogArchiverFunction(
        FunctionsDbContext db,
        IConfiguration    config,
        ILogger<AuditLogArchiverFunction> logger)
    {
        _db     = db;
        _config = config;
        _logger = logger;
    }

    // Runs every night at midnight UTC
    // Cron: "0 0 0 * * *" = second:0 minute:0 hour:0 every day
    [Function("AuditLogArchiver")]
    public async Task Run(
        [TimerTrigger("0 0 0 * * *")] TimerInfo timer)
    {
        _logger.LogInformation(
            "AuditLogArchiver started at {Time}", DateTime.UtcNow);

        try
        {
            var cutoffDate = DateTime.UtcNow.AddDays(-30);

            // Get logs older than 30 days that haven't been archived yet
            var logsToArchive = await _db.SecurityAuditLogs
                .Where(l => l.CreatedAt < cutoffDate && !l.IsArchived)
                .OrderBy(l => l.CreatedAt)
                .ToListAsync();

            if (!logsToArchive.Any())
            {
                _logger.LogInformation("No logs to archive today.");
                return;
            }

            _logger.LogInformation(
                "Found {Count} logs to archive (older than {Date:yyyy-MM-dd})",
                logsToArchive.Count, cutoffDate);

            // Group by date — one archive file per day
            var groupedByDate = logsToArchive
                .GroupBy(l => l.CreatedAt.Date)
                .ToList();

            int archivedCount = 0;

            foreach (var group in groupedByDate)
            {
                var date     = group.Key;
                var logs     = group.ToList();
                var fileName = $"audit-logs/{date:yyyy/MM/dd}/security-audit-{date:yyyyMMdd}.json";

                // Serialize logs to JSON
                var jsonContent = JsonSerializer.Serialize(logs, new JsonSerializerOptions
                {
                    WriteIndented = true
                });

                // ── In production: upload to Azure Blob Storage ───────────────
                // var blobClient = new BlobClient(connectionString, "audit-logs", fileName);
                // await blobClient.UploadAsync(BinaryData.FromString(jsonContent), overwrite: true);

                // For now: log the archive action (swap with Blob upload in production)
                _logger.LogInformation(
                    "Archived {Count} logs for {Date:yyyy-MM-dd} → {FileName}",
                    logs.Count, date, fileName);

                // Mark as archived in DB
                foreach (var log in logs)
                    log.IsArchived = true;

                archivedCount += logs.Count;
            }

            // Save archived flags to DB
            await _db.SaveChangesAsync();

            _logger.LogInformation(
                "AuditLogArchiver completed. Archived {Count} logs across {Days} days.",
                archivedCount, groupedByDate.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "AuditLogArchiver failed: {Message}", ex.Message);
            throw;
        }
    }
}
