using System.IO;
using System.Text.RegularExpressions;

namespace SecureApiDemo.Middleware;

/// <summary>
/// OWASP A03:2021 — Injection
///
/// Injection attacks (SQL, NoSQL, LDAP, OS) occur when untrusted data
/// is sent as part of a command or query.
/// This middleware enforces:
/// 1. SQL injection pattern detection in request body and query strings
/// 2. XSS (Cross-Site Scripting) pattern detection
/// 3. Command injection pattern detection
/// 4. Input length limits
///
/// Note: EF Core parameterized queries are the PRIMARY defense.
/// This middleware is a secondary defense-in-depth layer.
///
/// Interview talking point:
/// "I use EF Core parameterized queries as the primary SQL injection
///  defense. As a secondary layer I have middleware that detects common
///  injection patterns in incoming requests and blocks them before they
///  reach the controllers — defense in depth."
/// </summary>
public class InjectionProtectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<InjectionProtectionMiddleware> _logger;
    // ✅ Add this list at the top of the class
    private static readonly HashSet<string> _excludedPaths = new(StringComparer.OrdinalIgnoreCase)
{
    "/api/sso/callback",      // SSO auth code contains special characters
    "/api/sso/login",
    "/api/auth/refresh"       // Refresh tokens also contain special chars
};
    // SQL Injection patterns
    private static readonly Regex _sqlInjectionPattern = new(
        @"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|SCRIPT)\b)|" +
        @"(--|;|'|\bOR\b\s+\d+=\d+|\bAND\b\s+\d+=\d+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // XSS patterns
    private static readonly Regex _xssPattern = new(
        @"(<script|</script|javascript:|onerror=|onload=|eval\(|alert\()",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    // Command injection patterns
    private static readonly Regex _commandInjectionPattern = new(
        @"(;|\||&&|\$\(|`|>\s*/|<\s*/)",
        RegexOptions.Compiled);

    // Max request body size — 1MB
    private const int MaxRequestBodySize = 1024 * 1024;

    public InjectionProtectionMiddleware(
        RequestDelegate next,
        ILogger<InjectionProtectionMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Add this check at the very top
    var path = context.Request.Path.Value ?? string.Empty;
        if (_excludedPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        // A03: Check query string for injection
        var queryString = context.Request.QueryString.Value ?? string.Empty;
        if (ContainsInjection(queryString))
        {
            await BlockRequest(context, "Query string injection detected");
            return;
        }

        // A03: Check request body for injection (POST/PUT only)
        if (context.Request.Method is "POST" or "PUT" or "PATCH")
        {
            context.Request.EnableBuffering();

            // Enforce body size limit
            if (context.Request.ContentLength > MaxRequestBodySize)
            {
                _logger.LogWarning(
                    "A03 Injection: Request body too large ({Size} bytes) from {IP}",
                    context.Request.ContentLength,
                    context.Connection.RemoteIpAddress);

                context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Request body too large.",
                    owasp = "A03:2021 - Injection"
                });
                return;
            }

            using var reader = new StreamReader(
                context.Request.Body,
                leaveOpen: true);

            var body = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;

            if (ContainsInjection(body))
            {
                await BlockRequest(context, "Request body injection detected");
                return;
            }
        }

        await _next(context);
    }

    private bool ContainsInjection(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

        return _sqlInjectionPattern.IsMatch(input) ||
               _xssPattern.IsMatch(input) ||
               _commandInjectionPattern.IsMatch(input);
    }

    private async Task BlockRequest(HttpContext context, string reason)
    {
        _logger.LogWarning(
            "A03 Injection: {Reason} from {IP} on {Path}",
            reason,
            context.Connection.RemoteIpAddress,
            context.Request.Path);

        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        await context.Response.WriteAsJsonAsync(new
        {
            error = "Invalid input detected.",
            owasp = "A03:2021 - Injection"
        });
    }
}
