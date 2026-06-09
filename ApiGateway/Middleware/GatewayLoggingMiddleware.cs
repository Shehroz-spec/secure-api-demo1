namespace ApiGateway.Middleware;

/// <summary>
/// Logs every request passing through the gateway with:
/// - Timestamp, Method, Path, Status Code, Duration
/// - Client IP, User Agent
/// - Flags slow requests (>2s) and errors (4xx/5xx)
/// </summary>
public class GatewayLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GatewayLoggingMiddleware> _logger;

    public GatewayLoggingMiddleware(RequestDelegate next, ILogger<GatewayLoggingMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var start     = DateTime.UtcNow;
        var requestId = Guid.NewGuid().ToString("N")[..8].ToUpper();
        var method    = context.Request.Method;
        var path      = context.Request.Path;
        var clientIp  = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var userAgent = context.Request.Headers.UserAgent.ToString();

        // Add request ID header for tracing
        context.Response.Headers.Append("X-Request-Id", requestId);
        context.Response.Headers.Append("X-Gateway", "Ocelot/SecureApiDemo");

        _logger.LogInformation(
            "[{RequestId}] ➡ {Method} {Path} | IP: {ClientIp}",
            requestId, method, path, clientIp);

        await _next(context);

        var elapsed    = (DateTime.UtcNow - start).TotalMilliseconds;
        var statusCode = context.Response.StatusCode;

        // Flag errors
        if (statusCode >= 500)
        {
            _logger.LogError(
                "[{RequestId}] ❌ {Method} {Path} → {StatusCode} | {Elapsed}ms | IP: {ClientIp}",
                requestId, method, path, statusCode, elapsed, clientIp);
        }
        else if (statusCode >= 400)
        {
            _logger.LogWarning(
                "[{RequestId}] ⚠ {Method} {Path} → {StatusCode} | {Elapsed}ms | IP: {ClientIp}",
                requestId, method, path, statusCode, elapsed, clientIp);
        }
        else
        {
            _logger.LogInformation(
                "[{RequestId}] ✅ {Method} {Path} → {StatusCode} | {Elapsed}ms | IP: {ClientIp}",
                requestId, method, path, statusCode, elapsed, clientIp);
        }

        // Warn on slow requests
        if (elapsed > 2000)
        {
            _logger.LogWarning(
                "[{RequestId}] 🐢 SLOW REQUEST: {Method} {Path} took {Elapsed}ms",
                requestId, method, path, elapsed);
        }
    }
}
