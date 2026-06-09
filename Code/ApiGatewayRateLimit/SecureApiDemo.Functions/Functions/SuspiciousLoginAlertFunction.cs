using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using SecureApiDemo.Functions.Data;
using SecureApiDemo.Functions.Models;
using SecureApiDemo.Functions.Services;
using System.Net;
using System.Text.Json;

namespace SecureApiDemo.Functions.Functions;

/// <summary>
/// FUNCTION 3: Suspicious Login Alert
///
/// Trigger: HTTP POST
/// Purpose: Called by the SecurityLoggingMiddleware in the API when
///          it detects too many failed login attempts from the same IP.
///          Logs the event and sends an alert to the admin.
///
/// Interview talking point:
/// "Our SecurityLoggingMiddleware detects brute force attempts —
///  5+ failed logins from the same IP in 1 minute. Rather than
///  handling the alert in the middleware itself, it calls this
///  HTTP-triggered Azure Function which logs the event to the
///  SecurityAuditLogs table and sends an admin alert email,
///  keeping the security concern fully decoupled from the API."
/// </summary>
public class SuspiciousLoginAlertFunction
{
    private readonly FunctionsDbContext _db;
    private readonly IAlertService      _alertService;
    private readonly ILogger<SuspiciousLoginAlertFunction> _logger;

    public SuspiciousLoginAlertFunction(
        FunctionsDbContext db,
        IAlertService      alertService,
        ILogger<SuspiciousLoginAlertFunction> logger)
    {
        _db           = db;
        _alertService = alertService;
        _logger       = logger;
    }

    [Function("SuspiciousLoginAlert")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData request)
    {
        _logger.LogWarning("SuspiciousLoginAlert triggered at {Time}", DateTime.UtcNow);

        try
        {
            // Read and deserialize request body
            var body = await new StreamReader(request.Body).ReadToEndAsync();
            var alert = JsonSerializer.Deserialize<SuspiciousLoginAlert>(body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (alert is null)
            {
                var badResponse = request.CreateResponse(HttpStatusCode.BadRequest);
                await badResponse.WriteStringAsync("Invalid alert payload.");
                return badResponse;
            }

            _logger.LogWarning(
                "Suspicious login detected: {Username} | IP: {IP} | Attempts: {Attempts}",
                alert.Username, alert.IpAddress, alert.FailedAttempts);

            // ── 1. Log to SecurityAuditLogs table ────────────────────────────
            var auditLog = new SecurityAuditLog
            {
                EventType = "SUSPICIOUS_LOGIN",
                Username  = alert.Username,
                IpAddress = alert.IpAddress,
                Details   = $"Failed attempts: {alert.FailedAttempts} | Detected: {alert.DetectedAt:u}",
                CreatedAt = DateTime.UtcNow
            };

            _db.SecurityAuditLogs.Add(auditLog);
            await _db.SaveChangesAsync();

            // ── 2. Send admin alert email ─────────────────────────────────────
            await _alertService.SendSuspiciousLoginAlertAsync(alert);

            // ── 3. Return success ─────────────────────────────────────────────
            var response = request.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                message   = "Alert logged and admin notified.",
                loggedAt  = DateTime.UtcNow,
                username  = alert.Username,
                ipAddress = alert.IpAddress
            });

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SuspiciousLoginAlert failed: {Message}", ex.Message);

            var errorResponse = request.CreateResponse(HttpStatusCode.InternalServerError);
            await errorResponse.WriteStringAsync("Alert processing failed.");
            return errorResponse;
        }
    }
}
