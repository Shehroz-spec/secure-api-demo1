namespace ApiGateway.Middleware;

/// <summary>
/// Transforms requests and responses passing through the gateway:
/// - Adds gateway metadata headers to all requests
/// - Removes sensitive internal headers from responses
/// - Adds correlation ID for distributed tracing
/// - Adds security headers to all responses
/// </summary>
public class RequestTransformationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestTransformationMiddleware> _logger;

    // Headers to strip from downstream responses before sending to client
    private static readonly string[] SensitiveResponseHeaders =
    {
        "X-Powered-By",
        "Server",
        "X-AspNet-Version",
        "X-AspNetMvc-Version"
    };

    public RequestTransformationMiddleware(
        RequestDelegate next,
        ILogger<RequestTransformationMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // ── Request Transformation ────────────────────────────────────────────

        // Add correlation ID for distributed tracing
        var correlationId = context.Request.Headers["X-Correlation-Id"].FirstOrDefault()
                         ?? Guid.NewGuid().ToString();
        context.Request.Headers["X-Correlation-Id"] = correlationId;

        // Add gateway version header
        context.Request.Headers["X-Gateway-Version"] = "1.0.0";

        // Add timestamp of when request entered gateway
        context.Request.Headers["X-Gateway-Timestamp"] =
            DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();

        // Add client IP for downstream services
        var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        context.Request.Headers["X-Real-IP"]       = clientIp;
        context.Request.Headers["X-Forwarded-For"] = clientIp;

        await _next(context);

        // ── Response Transformation ───────────────────────────────────────────

        // Echo correlation ID back to client
        if (!context.Response.HasStarted)
        {
            context.Response.Headers.Append("X-Correlation-Id", correlationId);

            // Remove sensitive headers from response
            foreach (var header in SensitiveResponseHeaders)
                context.Response.Headers.Remove(header);

            // Add security headers
            context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Append("X-Frame-Options",         "DENY");
            context.Response.Headers.Append("Referrer-Policy",         "no-referrer");
        }
    }
}
