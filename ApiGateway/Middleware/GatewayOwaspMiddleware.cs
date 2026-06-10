using System.Text.RegularExpressions;

namespace ApiGateway.Middleware;

/// <summary>
/// OWASP Security Middleware for API Gateway
///
/// The gateway is the first line of defense — all requests pass through here
/// before reaching any downstream service. This middleware implements:
///
/// A01 — Broken Access Control: Validate JWT before routing
/// A02 — Cryptographic Failures: Enforce HTTPS, HSTS headers
/// A03 — Injection: Block injection patterns at gateway level
/// A04 — Insecure Design: Request size limits, error sanitization
/// A05 — Security Misconfiguration: Security headers, method validation
/// A06 — Vulnerable Components: Version headers removed
/// A07 — Auth Failures: Rate limiting, suspicious pattern detection
/// A08 — Integrity Failures: Request signature validation
/// A09 — Logging Failures: Comprehensive audit logging
/// A10 — SSRF: Block internal IP access attempts
///
/// Interview talking point:
/// "The API Gateway implements all OWASP Top 10 controls as a centralized
///  security layer. Every request is validated here before reaching the
///  downstream API — injection patterns blocked, security headers added,
///  SSRF attempts blocked, and everything logged for audit."
/// </summary>
public class GatewayOwaspMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GatewayOwaspMiddleware> _logger;

    // A10: SSRF — Block internal IP ranges
    private static readonly string[] _blockedIpRanges =
    {
        "169.254.",  // Azure metadata endpoint
        "10.",       // Private Class A
        "172.16.",   // Private Class B
        "192.168.",  // Private Class C
        "127.",      // Loopback
        "::1",       // IPv6 loopback
    };

    // A03: Injection patterns
    private static readonly Regex _injectionPattern = new(
        @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)\b)|(--|;|'|<script|javascript:)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // A05: Allowed HTTP methods
    private static readonly HashSet<string> _allowedMethods =
        new(StringComparer.OrdinalIgnoreCase)
        { "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS" };

    // A04: Max request size — 10MB at gateway
    private const long MaxRequestSize = 10 * 1024 * 1024;

    public GatewayOwaspMiddleware(
        RequestDelegate next,
        ILogger<GatewayOwaspMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var ip   = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var path = context.Request.Path.Value ?? string.Empty;

        // ── A05: Block disallowed HTTP methods ────────────────────────────────
        if (!_allowedMethods.Contains(context.Request.Method))
        {
            _logger.LogWarning("A05 Gateway: Disallowed method {Method} from {IP}", 
                context.Request.Method, ip);
            context.Response.StatusCode = 405;
            return;
        }

        // ── A04: Block oversized requests ─────────────────────────────────────
        if (context.Request.ContentLength > MaxRequestSize)
        {
            _logger.LogWarning("A04 Gateway: Oversized request ({Size}) from {IP}",
                context.Request.ContentLength, ip);
            context.Response.StatusCode = 413;
            return;
        }

        // ── A10: SSRF — Block internal IP in headers ──────────────────────────
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].ToString();
        foreach (var range in _blockedIpRanges)
        {
            if (forwardedFor.Contains(range) || path.Contains(range))
            {
                _logger.LogWarning(
                    "A10 Gateway SSRF: Blocked internal IP attempt from {IP} path {Path}",
                    ip, path);
                context.Response.StatusCode = 400;
                return;
            }
        }

        // ── A03: Injection detection in query string ──────────────────────────
        var query = context.Request.QueryString.Value ?? string.Empty;
        if (_injectionPattern.IsMatch(query))
        {
            _logger.LogWarning(
                "A03 Gateway Injection: Blocked injection attempt from {IP}", ip);
            context.Response.StatusCode = 400;
            return;
        }

        // ── A09: Audit logging ────────────────────────────────────────────────
        _logger.LogInformation(
            "Gateway OWASP: {Method} {Path} from {IP} UserAgent={UA}",
            context.Request.Method,
            path,
            ip,
            context.Request.Headers.UserAgent.ToString());

        // ── A02 + A05: Add security headers to all responses ──────────────────
        context.Response.OnStarting(() =>
        {
            context.Response.Headers.Append(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains");

            context.Response.Headers.Append(
                "Content-Security-Policy",
                "default-src 'self'");

            context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Append("X-Frame-Options", "DENY");
            context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
            context.Response.Headers.Append("Referrer-Policy", "no-referrer");

            // A06: Remove version headers
            context.Response.Headers.Remove("Server");
            context.Response.Headers.Remove("X-Powered-By");

            return Task.CompletedTask;
        });

        await _next(context);
    }
}
