using Microsoft.Azure.Functions.Worker;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureApiDemo.Functions.Data;

namespace SecureApiDemo.Functions.Functions;

/// <summary>
/// FUNCTION 1: Expired Refresh Token Cleanup
///
/// Trigger: Timer — runs every hour
/// Purpose: Deletes expired and revoked refresh tokens from SQL Server
///          to keep the RefreshTokens table lean and performant.
///
/// Interview talking point:
/// "Refresh tokens accumulate in the DB over time. Rather than cleaning
///  them up in the API (which adds latency), I offloaded this to a
///  Timer-triggered Azure Function that runs every hour serverlessly."
/// </summary>
public class CleanupExpiredTokensFunction
{
    private readonly FunctionsDbContext _db;
    private readonly ILogger<CleanupExpiredTokensFunction> _logger;

    public CleanupExpiredTokensFunction(
        FunctionsDbContext db,
        ILogger<CleanupExpiredTokensFunction> logger)
    {
        _db     = db;
        _logger = logger;
    }

    // Cron expression: "0 0 * * * *" = every hour at minute 0
    // Format: {second} {minute} {hour} {day} {month} {day-of-week}
    [Function("CleanupExpiredTokens")]
    public async Task Run(
        [TimerTrigger("0 0 * * * *")] TimerInfo timer)
    {
        _logger.LogInformation(
            "CleanupExpiredTokens started at {Time}", DateTime.UtcNow);

        try
        {
            var now = DateTime.UtcNow;

            // Find all expired OR revoked tokens
            var tokensToDelete = await _db.RefreshTokens
                .Where(t => t.ExpiresAt < now || t.RevokedAt != null)
                .ToListAsync();

            if (!tokensToDelete.Any())
            {
                _logger.LogInformation("No expired tokens found. Nothing to clean up.");
                return;
            }

            var count = tokensToDelete.Count;

            // Bulk delete
            _db.RefreshTokens.RemoveRange(tokensToDelete);
            await _db.SaveChangesAsync();

            _logger.LogInformation(
                "CleanupExpiredTokens completed. Deleted {Count} expired/revoked tokens.",
                count);

            // Log if timer was late (missed schedule)
            if (timer.ScheduleStatus?.Last != null)
            {
                _logger.LogInformation(
                    "Last run: {LastRun} | Next run: {NextRun}",
                    timer.ScheduleStatus.Last,
                    timer.ScheduleStatus.Next);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "CleanupExpiredTokens failed: {Message}", ex.Message);
            throw;
        }
    }
}
