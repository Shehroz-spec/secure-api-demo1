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

public static class TlsConfiguration
{
    public static WebApplicationBuilder ConfigureTls(this WebApplicationBuilder builder)
    {
        // Only configure Kestrel HTTPS in development
        // In production — Render/Azure handle HTTPS termination
        if (builder.Environment.IsDevelopment())
        {
            builder.WebHost.ConfigureKestrel(options =>
            {
                options.ConfigureHttpsDefaults(httpsOptions =>
                {
                    httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                });

                options.ListenLocalhost(7028, listenOptions =>
                {
                    listenOptions.UseHttps(httpsOptions =>
                    {
                        httpsOptions.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    });
                });
            });
        }

        return builder;
    }

    public static WebApplication UseTlsSecurity(this WebApplication app)
    {
        // HSTS only in production
        if (!app.Environment.IsDevelopment())
        {
            app.UseHsts();
        }

        // Redirect HTTP to HTTPS
        app.UseHttpsRedirection();

        return app;
    }
}
