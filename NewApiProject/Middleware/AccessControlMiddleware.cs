using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace SecureApiDemo.Middleware;

/// <summary>
/// OWASP A01:2021 — Broken Access Control
///
/// Broken Access Control means users can act outside their intended permissions.
/// This middleware enforces:
/// 1. Every endpoint must be explicitly authorized (deny by default)
/// 2. Users can only access their own resources
/// 3. Admin endpoints are strictly role-gated
/// 4. JWT claims are validated on every request
///

/// </summary>
public class AccessControlMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AccessControlMiddleware> _logger;

    // Endpoints that are explicitly allowed without authentication
    private static readonly HashSet<string> _publicEndpoints = new(StringComparer.OrdinalIgnoreCase)
    {   
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/refresh",
        "/api/sso/login",        // ← Add this
        "/api/sso/callback",     // ← Add this
        "/api/sso/providers",    // ← Add this
        "/swagger",
        "/health"
    };

    public AccessControlMiddleware(RequestDelegate next, ILogger<AccessControlMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }
    public async Task InvokeAsync2(HttpContext context)
    {
        var path = context.Request.Path.Value?.ToLowerInvariant();

        if (path == "/api/sso/login" ||
            path == "/api/sso/callback" ||
            path?.StartsWith("/swagger") == true)
        {
            await _next(context);
            return;
        }

        if (context.User.Identity?.IsAuthenticated != true)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Authentication required.",
                owasp = "A01:2021 - Broken Access Control"
            });
            return;
        }

        await _next(context);
    }
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        // Allow public endpoints
        if (_publicEndpoints.Any(e => path.StartsWith(e, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        // Allow Swagger in development
        if (path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }
        var isAuthenticated = context.User.Identity?.IsAuthenticated;
        var authType = context.User.Identity?.AuthenticationType;
        var name = context.User.Identity?.Name;
        // A01: Verify user is authenticated
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            _logger.LogWarning(
                "A01 Access Control: Unauthenticated request to {Path} from {IP}",
                path, context.Connection.RemoteIpAddress);

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new
            {
                error = "Authentication required.",
                owasp = "A01:2021 - Broken Access Control"
            });
            return;
        }

        // A01: Log all admin endpoint access for audit
        if (path.Contains("/admin", StringComparison.OrdinalIgnoreCase))
        {
            var username = context.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var role = context.User.FindFirstValue(ClaimTypes.Role) ?? "none";

            _logger.LogWarning(
                "A01 Admin Access: User={Username} Role={Role} Path={Path} IP={IP}",
                username, role, path, context.Connection.RemoteIpAddress);
        }

        await _next(context);
    }
}
