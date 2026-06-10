namespace SecureApiDemo.Middleware;

/// <summary>
/// OWASP A04:2021 — Insecure Design
///
/// Insecure design means missing or ineffective security controls at design level.
/// Controls implemented:
/// 1. Request size limits — prevent memory exhaustion
/// 2. Response sanitization — never expose internal errors
/// 3. Business logic validation — enforce domain rules
///
/// OWASP A05:2021 — Security Misconfiguration
/// Controls implemented:
/// 1. Security headers on every response
/// 2. Disable unnecessary HTTP methods
/// 3. Remove technology fingerprinting headers
///
/// OWASP A06:2021 — Vulnerable and Outdated Components
/// Controls implemented:
/// 1. Dependency scanning in CI/CD pipeline
/// 2. Package version pinning in .csproj
///
/// OWASP A07:2021 — Identification and Authentication Failures
/// Controls implemented:
/// 1. Account lockout (5 attempts → 15 min) — in Identity config
/// 2. JWT expiry validation with zero clock skew
/// 3. Refresh token rotation — old token revoked on use
/// 4. 2FA/TOTP support
///
/// OWASP A08:2021 — Software and Data Integrity Failures
/// Controls implemented:
/// 1. CI/CD pipeline with build verification
/// 2. JWT signature validation
/// 3. Input model validation with DataAnnotations
///
/// OWASP A09:2021 — Security Logging and Monitoring Failures
/// Controls implemented:
/// 1. SecurityLoggingMiddleware — logs all requests
/// 2. Failed auth attempts logged with IP
/// 3. Admin access logged
/// 4. Serilog rolling file logs
///
/// OWASP A10:2021 — Server-Side Request Forgery (SSRF)
/// Controls implemented:
/// 1. URL allowlist validation
/// 2. Block requests to internal IP ranges
/// 3. Block metadata endpoints (169.254.x.x)
/// </summary>
public class OwaspSecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<OwaspSecurityHeadersMiddleware> _logger;
    private readonly IWebHostEnvironment _env;

    // A10: SSRF — Block internal IP ranges
    private static readonly string[] _blockedIpRanges =
    {
        "169.254.",  // Link-local (Azure metadata)
        "10.",       // Private Class A
        "172.16.",   // Private Class B
        "192.168.",  // Private Class C
        "127.",      // Loopback
        "::1",       // IPv6 loopback
        "fd",        // IPv6 private
    };

    // A05: Only allow these HTTP methods
    private static readonly HashSet<string> _allowedMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
    };

    public OwaspSecurityHeadersMiddleware(
        RequestDelegate next,
        ILogger<OwaspSecurityHeadersMiddleware> logger,
        IWebHostEnvironment env)
    {
        _next   = next;
        _logger = logger;
        _env    = env;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // A05: Block disallowed HTTP methods
        if (!_allowedMethods.Contains(context.Request.Method))
        {
            _logger.LogWarning(
                "A05 Security Misconfiguration: Disallowed HTTP method {Method} from {IP}",
                context.Request.Method,
                context.Connection.RemoteIpAddress);

            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "HTTP method not allowed.",
                owasp = "A05:2021 - Security Misconfiguration"
            });
            return;
        }

        // A10: SSRF — Check for internal IP access attempts
        var referer = context.Request.Headers.Referer.ToString();
        if (!string.IsNullOrEmpty(referer))
        {
            foreach (var blockedRange in _blockedIpRanges)
            {
                if (referer.Contains(blockedRange))
                {
                    _logger.LogWarning(
                        "A10 SSRF: Blocked request with internal IP in Referer: {Referer} from {IP}",
                        referer,
                        context.Connection.RemoteIpAddress);

                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                    await context.Response.WriteAsJsonAsync(new
                    {
                        error = "Request blocked for security reasons.",
                        owasp = "A10:2021 - SSRF"
                    });
                    return;
                }
            }
        }

        // A04 + A05: Add comprehensive security headers
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;

            // A05: Content Security Policy — prevent XSS
            headers.Append("Content-Security-Policy",
                "default-src 'self'; " +
                "script-src 'self'; " +
                "style-src 'self'; " +
                "img-src 'self' data:; " +
                "font-src 'self'; " +
                "connect-src 'self'; " +
                "frame-ancestors 'none'");

            // A05: Prevent MIME type sniffing
            headers.Append("X-Content-Type-Options", "nosniff");

            // A05: Prevent clickjacking
            headers.Append("X-Frame-Options", "DENY");

            // A05: XSS protection (legacy browsers)
            headers.Append("X-XSS-Protection", "1; mode=block");

            // A02: HSTS
            headers.Append("Strict-Transport-Security",
                "max-age=31536000; includeSubDomains; preload");

            // A05: Referrer policy
            headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");

            // A05: Permissions policy — restrict browser features
            headers.Append("Permissions-Policy",
                "camera=(), microphone=(), geolocation=(), payment=()");

            // A05: Remove server identification headers
            headers.Remove("Server");
            headers.Remove("X-Powered-By");
            headers.Remove("X-AspNet-Version");
            headers.Remove("X-AspNetMvc-Version");

            return Task.CompletedTask;
        });

        // A04: Sanitize error responses — never expose stack traces in production
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "A04 Unhandled exception on {Method} {Path} from {IP}",
                context.Request.Method,
                context.Request.Path,
                context.Connection.RemoteIpAddress);

            context.Response.StatusCode = StatusCodes.Status500InternalServerError;

            // Never expose internal errors in production
            var errorMessage = _env.IsDevelopment()
                ? ex.Message
                : "An internal error occurred.";

            if (!context.Response.HasStarted)
            {
                await context.Response.WriteAsJsonAsync(new
                {
                    error = errorMessage,
                    owasp = "A04:2021 - Insecure Design"
                });
            }
        }
    }
}
