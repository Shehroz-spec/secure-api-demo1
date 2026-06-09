# Secure REST API — .NET 8 Reference Implementation

A production-ready reference implementation demonstrating security best practices for ASP.NET Core REST APIs. Built from real-world patterns applied across enterprise fintech and cloud-native systems.

## Security Features

| Feature | Implementation |
|---|---|
| **JWT Authentication** | HS256-signed tokens, 1-hour expiry, zero clock skew tolerance |
| **Role-Based Access Control** | `Admin` and `User` roles enforced via ASP.NET Core policy engine |
| **Rate Limiting** | 100 req/min global; 5 req/min on auth endpoints (brute-force protection) |
| **Secrets Management** | Azure Key Vault abstraction — no secrets in config files or environment variables |
| **Security Logging** | Every request logged with IP, user, status code, and latency; 401/403 patterns flagged |
| **Security Headers** | `X-Content-Type-Options`, `X-Frame-Options`, `CSP`, `Referrer-Policy` on all responses |
| **Password Hashing** | BCrypt with work factor 12 |

## Project Structure

```
SecureApiDemo/
├── Controllers/
│   ├── AuthController.cs        # Login endpoint (rate-limited)
│   └── DataController.cs        # Protected endpoints with RBAC
├── Middleware/
│   └── SecurityLoggingMiddleware.cs  # Request logging + anomaly flagging
├── Models/
│   └── LoginRequest.cs          # Validated input model
├── Services/
│   ├── TokenService.cs          # JWT generation
│   └── SecretService.cs         # Azure Key Vault abstraction
└── Program.cs                   # Security pipeline configuration
```

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/secure-api-demo
cd SecureApiDemo
dotnet run
```

Navigate to `https://localhost:5001/swagger` to explore the API.

## API Endpoints

### Authentication
```
POST /api/auth/login
Body: { "username": "alice", "password": "password123" }
Returns: { "token": "eyJ...", "expiresIn": 3600 }
```

### Protected Endpoints
```
GET /api/data/profile        → Requires: Any authenticated user
GET /api/data/admin/secret   → Requires: Admin role
GET /api/data/admin/users    → Requires: Admin role
```

**Test users:**
- `alice / password123` — Admin role
- `bob / securepass` — User role

## Key Security Decisions

**Why `ClockSkew = TimeSpan.Zero`?**
Default .NET clock skew tolerance is 5 minutes, meaning a token can be used 5 minutes after expiry. Setting it to zero enforces strict expiry — important for short-lived tokens.

**Why separate rate limits for auth vs general endpoints?**
Login endpoints are the primary target for credential stuffing and brute-force attacks. A 5 req/min limit stops automated attacks while not impacting legitimate users who rarely need to log in more than once.

**Why BCrypt work factor 12?**
Work factor 12 (~250ms hash time) makes offline dictionary attacks computationally expensive while remaining imperceptible to end users during login.

**Why log 401/403 separately?**
A spike in 401s from a single IP is a brute-force signal. A 403 from an authenticated user may indicate privilege escalation attempt. Both warrant immediate alerting in production.

## Production Checklist

- [ ] Replace simulated `SecretService` with real `Azure.Security.KeyVault.Secrets.SecretClient`
- [ ] Replace in-memory user store with ASP.NET Identity + SQL Server
- [ ] Set JWT key via Azure Key Vault (never in `appsettings.json`)
- [ ] Enable HTTPS-only with HSTS
- [ ] Add refresh token rotation
- [ ] Connect security logs to Azure Sentinel or SIEM

## Author

Shehroz Reaz — Software Engineer specializing in secure cloud-native systems.
[LinkedIn] | [Email]
