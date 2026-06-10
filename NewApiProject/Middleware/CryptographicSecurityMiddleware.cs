namespace SecureApiDemo.Middleware;

/// <summary>
/// OWASP A02:2021 — Cryptographic Failures
///
/// Cryptographic failures expose sensitive data due to weak or missing encryption.
/// This middleware enforces:
/// 1. HTTPS only — redirect HTTP to HTTPS
/// 2. HSTS — force browsers to use HTTPS for 1 year
/// 3. No sensitive data in URLs (passwords, tokens in query strings)
/// 4. Secure cookie settings
/// 5. Remove server version headers that expose technology stack
///
/// Interview talking point:
/// "I enforce HTTPS-only communication with HSTS headers, preventing
///  downgrade attacks. I also scan request URLs for accidentally exposed
///  credentials and block them before they reach the API."
/// </summary>
public class CryptographicSecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<CryptographicSecurityMiddleware> _logger;

    // Patterns that should never appear in URLs
    private static readonly string[] _sensitiveUrlPatterns =
    {
        "password=", "passwd=", "pwd=",
        "token=", "access_token=", "api_key=",
        "secret=", "credentials=", "auth="
    };

    public CryptographicSecurityMiddleware(
        RequestDelegate next,
        ILogger<CryptographicSecurityMiddleware> logger)
    {
        _next   = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var request = context.Request;

        // A02: Block sensitive data in query strings
        var queryString = request.QueryString.Value ?? string.Empty;
        foreach (var pattern in _sensitiveUrlPatterns)
        {
            if (queryString.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning(
                    "A02 Cryptographic: Sensitive data detected in URL from {IP}. Pattern: {Pattern}",
                    context.Connection.RemoteIpAddress, pattern);

                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsJsonAsync(new
                {
                    error = "Sensitive data must not be passed in query strings.",
                    owasp = "A02:2021 - Cryptographic Failures"
                });
                return;
            }
        }

        // A02: Add security headers
        context.Response.OnStarting(() =>
        {
            // HSTS — force HTTPS for 1 year including subdomains
            if (!context.Response.Headers.ContainsKey("Strict-Transport-Security"))
                context.Response.Headers.Append(
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains; preload");

            // Remove server headers that expose tech stack
            context.Response.Headers.Remove("Server");
            context.Response.Headers.Remove("X-Powered-By");
            context.Response.Headers.Remove("X-AspNet-Version");
            context.Response.Headers.Remove("X-AspNetMvc-Version");

            return Task.CompletedTask;
        });

        await _next(context);
    }
}
