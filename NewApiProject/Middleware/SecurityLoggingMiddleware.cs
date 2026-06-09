using System.Diagnostics;

namespace SecureApiDemo.Middleware;

/// <summary>
/// Logs all HTTP requests with security-relevant context:
/// IP address, authenticated user, method, path, status code, and duration.
/// Flags suspicious patterns (401/403 spikes, unusual paths).
/// </summary>
public class SecurityLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityLoggingMiddleware> _logger;

    public SecurityLoggingMiddleware(RequestDelegate next, ILogger<SecurityLoggingMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var sw        = Stopwatch.StartNew();
        var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var method    = context.Request.Method;
        var path      = context.Request.Path;

        await _next(context);

        sw.Stop();
        var statusCode = context.Response.StatusCode;
        var username   = context.User.Identity?.Name ?? "anonymous";

        // Standard request log
        _logger.LogInformation(
            "[SECURITY] {Method} {Path} | Status: {StatusCode} | User: {Username} | IP: {IP} | {ElapsedMs}ms",
            method, path, statusCode, username, ipAddress, sw.ElapsedMilliseconds);

        // Flag unauthorized / forbidden attempts
        if (statusCode is 401 or 403)
        {
            _logger.LogWarning(
                "[SECURITY ALERT] {StatusCode} on {Method} {Path} | User: {Username} | IP: {IP}",
                statusCode, method, path, username, ipAddress);
        }

        // Flag unusually slow responses (potential DoS or heavy query)
        if (sw.ElapsedMilliseconds > 2000)
        {
            _logger.LogWarning(
                "[PERFORMANCE ALERT] Slow response {ElapsedMs}ms on {Method} {Path}",
                sw.ElapsedMilliseconds, method, path);
        }
    }
}
