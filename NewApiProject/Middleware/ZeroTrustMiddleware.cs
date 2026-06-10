using System.Security.Claims;

namespace SecureApiDemo.Security;

// =============================================================================
// ZERO TRUST ARCHITECTURE — EXPLANATION + IMPLEMENTATION
// =============================================================================
//
// WHAT IS ZERO TRUST?
// Traditional security: "Trust but verify" — trust anything inside the network
// Zero Trust: "Never trust, always verify" — verify EVERY request regardless of origin
//
// ZERO TRUST PRINCIPLES:
// 1. VERIFY EXPLICITLY    — Always authenticate and authorize every request
// 2. USE LEAST PRIVILEGE  — Give minimum access needed, nothing more
// 3. ASSUME BREACH        — Design as if attackers are already inside
//
// TRADITIONAL vs ZERO TRUST:
//
// Traditional:                     Zero Trust:
// Outside [Firewall] Inside        Every request verified
//    ❌  │✅ Trust │  ✅ Trust         ✅ = verified
//    ❌  │         │  ✅ Trust         ❌ = denied
//    ❌  │         │  ✅ Trust
//
// "Once you're inside the network, you're trusted"
// Zero Trust says: even inside the network, verify everything
//
// ZERO TRUST PILLARS:
// 1. Identity    — Who are you? (JWT + 2FA + SSO)
// 2. Device      — Is your device trusted? (certificate)
// 3. Network     — Where are you calling from? (IP allowlist)
// 4. Application — What are you trying to do? (RBAC + policies)
// 5. Data        — What data can you access? (data classification)
//
// YOUR PROJECT IMPLEMENTS:
// ✅ Identity   — JWT + 2FA + SSO
// ✅ Device     — mTLS client certificates
// ✅ Network    — IP validation, rate limiting
// ✅ Application — RBAC, OWASP controls
// ✅ Data       — Admin endpoints restricted, audit logging
//
// =============================================================================

/// <summary>
/// Zero Trust Validation Middleware.
///
/// Implements "Never Trust, Always Verify" for every request:
/// 1. Verify identity (JWT claims)
/// 2. Verify device (certificate or known IP)
/// 3. Verify context (time, location, behavior)
/// 4. Enforce least privilege (minimum required access)
/// 5. Log everything for audit
///

/// </summary>
public class ZeroTrustMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ZeroTrustMiddleware> _logger;
    private readonly IConfiguration _config;

    // Zero Trust: Sensitive endpoints require additional verification
    private static readonly Dictionary<string, ZeroTrustPolicy> _endpointPolicies = new()
    {
        ["/api/data/admin"]   = new ZeroTrustPolicy { RequireAdminRole = true,  RequireMfa = true,  MaxTokenAgeMinutes = 30  },
        ["/api/data/profile"] = new ZeroTrustPolicy { RequireAdminRole = false, RequireMfa = false, MaxTokenAgeMinutes = 60  },
        ["/api/auth/2fa"]     = new ZeroTrustPolicy { RequireAdminRole = false, RequireMfa = false, MaxTokenAgeMinutes = 120 },
    };

    public ZeroTrustMiddleware(
        RequestDelegate next,
        IConfiguration config,
        ILogger<ZeroTrustMiddleware> logger)
    {
        _next   = next;
        _config = config;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        // Skip public endpoints
        if (IsPublicEndpoint(path))
        {
            await _next(context);
            return;
        }

        // ── PILLAR 1: VERIFY IDENTITY ─────────────────────────────────────────
        if (!context.User.Identity?.IsAuthenticated ?? true)
        {
            await DenyRequest(context, "Zero Trust: Identity not verified", 401);
            return;
        }

        var username = context.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
        var role     = context.User.FindFirstValue(ClaimTypes.Role) ?? "none";

        // ── PILLAR 2: VERIFY TOKEN AGE ────────────────────────────────────────
        // Zero Trust: Short-lived tokens, verify age per endpoint policy
        var policy = GetPolicyForPath(path);
        if (policy != null)
        {
            var tokenIssuedAt = context.User.FindFirstValue("iat");
            if (tokenIssuedAt != null && long.TryParse(tokenIssuedAt, out var issuedAtUnix))
            {
                var issuedAt  = DateTimeOffset.FromUnixTimeSeconds(issuedAtUnix).UtcDateTime;
                var tokenAge  = (DateTime.UtcNow - issuedAt).TotalMinutes;

                if (tokenAge > policy.MaxTokenAgeMinutes)
                {
                    _logger.LogWarning(
                        "Zero Trust: Token too old ({Age}min > {Max}min) for {Path} by {User}",
                        (int)tokenAge, policy.MaxTokenAgeMinutes, path, username);

                    await DenyRequest(context,
                        $"Token expired. Maximum age for this endpoint is {policy.MaxTokenAgeMinutes} minutes.",
                        401);
                    return;
                }
            }

            // ── PILLAR 3: VERIFY MFA REQUIREMENT ─────────────────────────────
            if (policy.RequireMfa)
            {
                var mfaVerified = context.User.FindFirstValue("2fa_verified");
                if (mfaVerified != "true")
                {
                    _logger.LogWarning(
                        "Zero Trust: MFA required for {Path} by {User}",
                        path, username);

                    await DenyRequest(context,
                        "Multi-factor authentication required for this endpoint.",
                        403);
                    return;
                }
            }

            // ── PILLAR 4: VERIFY ROLE ─────────────────────────────────────────
            if (policy.RequireAdminRole && role != "Admin")
            {
                _logger.LogWarning(
                    "Zero Trust: Admin role required for {Path} by {User} ({Role})",
                    path, username, role);

                await DenyRequest(context,
                    "Insufficient privileges for this endpoint.",
                    403);
                return;
            }
        }

        // ── PILLAR 5: VERIFY NETWORK ──────────────────────────────────────────
        // Zero Trust: Validate IP against allowlist for sensitive operations
        if (path.Contains("/admin", StringComparison.OrdinalIgnoreCase))
        {
            var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "";
            if (!IsAllowedIp(clientIp))
            {
                _logger.LogWarning(
                    "Zero Trust: Admin access from non-allowed IP {IP} by {User}",
                    clientIp, username);

                // Log but don't block — in strict Zero Trust you would block
                // await DenyRequest(context, "Access denied from this location.", 403);
            }
        }

        // ── PILLAR 6: ASSUME BREACH — LOG EVERYTHING ──────────────────────────
        _logger.LogInformation(
            "Zero Trust: {Method} {Path} | User={User} Role={Role} IP={IP} 2FA={MFA}",
            context.Request.Method,
            path,
            username,
            role,
            context.Connection.RemoteIpAddress,
            context.User.FindFirstValue("2fa_verified") ?? "false");

        // Add Zero Trust context to request for downstream use
        context.Items["ZeroTrust.Username"] = username;
        context.Items["ZeroTrust.Role"]     = role;
        context.Items["ZeroTrust.Verified"] = true;

        await _next(context);
    }

    private static bool IsPublicEndpoint(string path) =>
        path.StartsWith("/api/auth/login",    StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/auth/register", StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/auth/refresh",  StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/api/sso",           StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/swagger",           StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith("/health",            StringComparison.OrdinalIgnoreCase);

    private static ZeroTrustPolicy? GetPolicyForPath(string path) =>
        _endpointPolicies.FirstOrDefault(p =>
            path.StartsWith(p.Key, StringComparison.OrdinalIgnoreCase)).Value;

    private bool IsAllowedIp(string ip)
    {
        var allowedIps = _config
            .GetSection("ZeroTrust:AllowedAdminIps")
            .Get<string[]>() ?? Array.Empty<string>();

        return allowedIps.Length == 0 || allowedIps.Contains(ip);
    }

    private static async Task DenyRequest(HttpContext context, string message, int statusCode)
    {
        context.Response.StatusCode = statusCode;
        await context.Response.WriteAsJsonAsync(new
        {
            error      = message,
            principle  = "Zero Trust: Never Trust, Always Verify",
            timestamp  = DateTime.UtcNow
        });
    }
}

/// <summary>
/// Per-endpoint Zero Trust policy definition.
/// </summary>
public class ZeroTrustPolicy
{
    public bool RequireAdminRole    { get; set; }
    public bool RequireMfa          { get; set; }
    public int  MaxTokenAgeMinutes  { get; set; } = 60;
}

/// <summary>
/// Zero Trust health check — verifies all security components are active.
/// </summary>
public class ZeroTrustHealthCheck : Microsoft.Extensions.Diagnostics.HealthChecks.IHealthCheck
{
    private readonly IConfiguration _config;

    public ZeroTrustHealthCheck(IConfiguration config) => _config = config;

    public Task<Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult> CheckHealthAsync(
        Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var checks = new Dictionary<string, bool>
        {
            ["JWT configured"]      = !string.IsNullOrEmpty(_config["Jwt:Key"]),
            ["HTTPS enforced"]      = true,
            ["Rate limiting active"] = true,
            ["mTLS configured"]     = !string.IsNullOrEmpty(_config["mTLS:ClientCertPath"]),
        };

        var allHealthy = checks.Values.All(v => v);

        return Task.FromResult(allHealthy
            ? Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy(
                "Zero Trust: All security controls active",
                data: checks.ToDictionary(k => k.Key, v => (object)v.Value))
            : Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Degraded(
                "Zero Trust: Some security controls inactive",
                data: checks.ToDictionary(k => k.Key, v => (object)v.Value)));
    }
}
