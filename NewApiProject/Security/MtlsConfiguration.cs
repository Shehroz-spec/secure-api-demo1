using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace SecureApiDemo.Security;

// =============================================================================
// mTLS (Mutual TLS) — EXPLANATION + IMPLEMENTATION
// =============================================================================
//
// WHAT IS mTLS?
// In regular TLS, only the SERVER proves its identity via certificate.
// In mTLS, BOTH server AND client prove their identity via certificates.
//
// TLS vs mTLS:
//
//  Regular TLS:                    mTLS:
//  Client ──────────────► Server   Client ──────────────► Server
//         "Who are you?"                  "Who are you?"
//  Client ◄──Certificate─ Server   Client ◄──Certificate─ Server
//         "I trust you"                   "I trust you, who are YOU?"
//  Client ──────────────► Server   Client ──Certificate──► Server
//         [sends data]                    "I trust you too"
//                                  Client ──────────────► Server
//                                         [sends data]
//
// USE CASES FOR mTLS:
// ✅ Service-to-service communication (microservices)
// ✅ API Gateway → Downstream API
// ✅ Zero Trust architecture
// ✅ B2B APIs where clients are known partners
// ❌ Public APIs (clients don't have certificates)
// ❌ Browser-based apps (browsers don't manage certs easily)
//
// YOUR PROJECT:
// Gateway → API communication uses mTLS
// External clients → Gateway uses regular TLS + JWT
//
// =============================================================================

/// <summary>
/// mTLS Certificate Validator Middleware.
///
/// Validates client certificates on incoming requests.
/// Used for service-to-service communication between:
/// - ApiGateway → NewApiProject
/// - Azure Functions → NewApiProject
///
/// Interview talking point:
/// "I implemented mTLS for service-to-service communication. The API Gateway
///  presents a client certificate when calling the downstream API. The API
///  validates the certificate thumbprint against a known allowlist — ensuring
///  only trusted services can call internal endpoints, even if they have a
///  valid JWT token."
/// </summary>
public class MtlsValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<MtlsValidationMiddleware> _logger;
    private readonly IConfiguration _config;

    // Paths that require mTLS client certificate
    private static readonly HashSet<string> _mtlsRequiredPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/data/admin",
        "/api/internal"
    };

    public MtlsValidationMiddleware(
        RequestDelegate next,
        IConfiguration config,
        ILogger<MtlsValidationMiddleware> logger)
    {
        _next   = next;
        _config = config;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        // Only enforce mTLS on specific paths
        if (!_mtlsRequiredPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            await _next(context);
            return;
        }

        // Get client certificate from request
        var clientCert = context.Connection.ClientCertificate;

        if (clientCert == null)
        {
            _logger.LogWarning(
                "mTLS: No client certificate presented for {Path} from {IP}",
                path, context.Connection.RemoteIpAddress);

            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsJsonAsync(new
            {
                error  = "Client certificate required for this endpoint.",
                detail = "mTLS authentication required."
            });
            return;
        }

        // Validate certificate
        if (!ValidateClientCertificate(clientCert, out var validationError))
        {
            _logger.LogWarning(
                "mTLS: Invalid client certificate from {IP}: {Error}",
                context.Connection.RemoteIpAddress, validationError);

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                error  = "Invalid client certificate.",
                detail = validationError
            });
            return;
        }

        _logger.LogInformation(
            "mTLS: Valid certificate from {Subject} for {Path}",
            clientCert.Subject, path);

        // Add certificate info to request context for controllers
        context.Items["ClientCertificate"]    = clientCert;
        context.Items["ClientCertSubject"]    = clientCert.Subject;
        context.Items["ClientCertThumbprint"] = clientCert.Thumbprint;

        await _next(context);
    }

    private bool ValidateClientCertificate(X509Certificate2 cert, out string error)
    {
        error = string.Empty;

        // ── Check 1: Certificate not expired ─────────────────────────────────
        if (cert.NotAfter < DateTime.UtcNow)
        {
            error = "Certificate has expired.";
            return false;
        }

        // ── Check 2: Certificate not yet valid ────────────────────────────────
        if (cert.NotBefore > DateTime.UtcNow)
        {
            error = "Certificate is not yet valid.";
            return false;
        }

        // ── Check 3: Thumbprint allowlist ─────────────────────────────────────
        // In production store thumbprints in Azure Key Vault or config
        var allowedThumbprints = _config
            .GetSection("mTLS:AllowedThumbprints")
            .Get<string[]>() ?? Array.Empty<string>();

        if (allowedThumbprints.Length > 0 &&
            !allowedThumbprints.Contains(cert.Thumbprint, StringComparer.OrdinalIgnoreCase))
        {
            error = $"Certificate thumbprint not in allowlist: {cert.Thumbprint}";
            return false;
        }

        // ── Check 4: Certificate chain validation ─────────────────────────────
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode    = X509RevocationMode.NoCheck; // Online in production
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        if (!chain.Build(cert))
        {
            error = "Certificate chain validation failed.";
            return false;
        }

        return true;
    }
}

/// <summary>
/// mTLS Client — used by ApiGateway to present certificate when calling downstream API.
/// </summary>
public class MtlsHttpClientFactory
{
    private readonly IConfiguration _config;
    private readonly ILogger<MtlsHttpClientFactory> _logger;

    public MtlsHttpClientFactory(IConfiguration config, ILogger<MtlsHttpClientFactory> logger)
    {
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// Creates an HttpClient that presents a client certificate (for mTLS).
    /// Used by ApiGateway when calling NewApiProject internal endpoints.
    /// </summary>
    public HttpClient CreateMtlsClient()
    {
        // Load client certificate from file or Key Vault
        // In production: load from Azure Key Vault
        // var cert = LoadCertificateFromKeyVault();

        // For development: load from file
        var certPath     = _config["mTLS:ClientCertPath"]     ?? "certs/client.pfx";
        var certPassword = _config["mTLS:ClientCertPassword"] ?? "";

        var cert = new X509Certificate2(certPath, certPassword);

        var handler = new HttpClientHandler();
        handler.ClientCertificates.Add(cert);
        handler.ClientCertificateOptions = ClientCertificateOption.Manual;

        // In production also validate server certificate
        // handler.ServerCertificateCustomValidationCallback = ValidateServerCert;

        _logger.LogInformation(
            "mTLS: Created client with certificate {Thumbprint}", cert.Thumbprint);

        return new HttpClient(handler);
    }
}

/// <summary>
/// Kestrel configuration for mTLS — requires client certificates.
/// Add to Program.cs WebHost configuration.
/// </summary>
public static class MtlsKestrelConfiguration
{
    public static WebApplicationBuilder ConfigureMtls(this WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.ConfigureHttpsDefaults(httpsOptions =>
            {
                // Require client certificate for mTLS
                httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;

                // Validate client certificate
                httpsOptions.ClientCertificateValidation = (cert, chain, errors) =>
                {
                    // Basic validation — enhance with thumbprint check in production
                    return cert != null && errors == System.Net.Security.SslPolicyErrors.None;
                };

                // TLS 1.2+ only
                httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
            });
        });

        return builder;
    }
}
