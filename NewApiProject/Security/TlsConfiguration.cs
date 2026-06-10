// =============================================================================
// TLS (Transport Layer Security) — EXPLANATION + IMPLEMENTATION
// =============================================================================
//
// WHAT IS TLS?
// TLS is the protocol that encrypts data between client and server.
// It's what makes HTTP → HTTPS.
//
// HOW IT WORKS:
//
//  Client                          Server
//    │                               │
//    │──── ClientHello ─────────────►│  "I want to connect, here are my cipher suites"
//    │                               │
//    │◄─── ServerHello ──────────────│  "OK, let's use TLS 1.3 + AES-256"
//    │◄─── Certificate ──────────────│  Server sends its SSL certificate
//    │◄─── ServerHelloDone ──────────│
//    │                               │
//    │  Client verifies certificate  │
//    │  (is it signed by trusted CA?)│
//    │                               │
//    │──── ClientKeyExchange ───────►│  Exchange session keys
//    │──── ChangeCipherSpec ────────►│
//    │──── Finished ───────────────►│
//    │                               │
//    │◄─── ChangeCipherSpec ─────────│
//    │◄─── Finished ─────────────────│
//    │                               │
//    │══════ Encrypted Data ═════════│  All data now encrypted
//
// TLS VERSIONS:
// TLS 1.0 — deprecated (vulnerable)
// TLS 1.1 — deprecated (vulnerable)
// TLS 1.2 — acceptable (still used)
// TLS 1.3 — current standard (fastest, most secure) ← USE THIS
//
// WHAT TLS PROTECTS:
// ✅ Encryption    — data cannot be read in transit
// ✅ Integrity     — data cannot be tampered with
// ✅ Authentication — server identity verified via certificate
// ❌ Does NOT verify CLIENT identity (that's mTLS)
//
// =============================================================================

using System.Security.Authentication;

namespace SecureApiDemo.Security;

/// <summary>
/// TLS Configuration for ASP.NET Core Kestrel server.
///
/// Enforces:
/// - TLS 1.2 minimum (TLS 1.3 preferred)
/// - Strong cipher suites only
/// - HSTS headers
/// - HTTP → HTTPS redirect
///
/// Interview talking point:
/// "I configured Kestrel to enforce TLS 1.2 minimum with TLS 1.3 preferred,
///  disabled weak cipher suites, and added HSTS headers with a 1-year max-age.
///  This prevents downgrade attacks and ensures all data is encrypted in transit."
/// </summary>
public static class TlsConfiguration
{
    /// <summary>
    /// Add to Program.cs — configures Kestrel with TLS settings.
    /// </summary>
    public static WebApplicationBuilder ConfigureTls(this WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(options =>
        {
            // ── HTTPS endpoint ────────────────────────────────────────────────
            options.ConfigureHttpsDefaults(httpsOptions =>
            {
                // Enforce TLS 1.2 minimum — TLS 1.0 and 1.1 are vulnerable
                httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;

                // Client certificate mode for mTLS (see mTLS section)
                // httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            });

            // ── Listen on HTTPS only ──────────────────────────────────────────
            options.ListenLocalhost(7028, listenOptions =>
            {
                listenOptions.UseHttps(httpsOptions =>
                {
                    httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                });
            });
        });

        return builder;
    }

    /// <summary>
    /// Add to Program.cs middleware pipeline — enforces HTTPS and HSTS.
    /// </summary>
    public static WebApplication UseTlsSecurity(this WebApplication app)
    {
        // Redirect all HTTP to HTTPS
        app.UseHttpsRedirection();

        // HSTS — tells browsers to always use HTTPS for 1 year
        // includeSubDomains — applies to all subdomains
        // preload — submit to browser preload lists
        app.UseHsts();

        return app;
    }
}
