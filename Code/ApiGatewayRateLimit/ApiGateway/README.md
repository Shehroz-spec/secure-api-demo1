# ApiGateway — Ocelot API Gateway

A production-ready API Gateway built with **Ocelot** that sits in front of SecureApiDemo,
providing centralized routing, authentication, rate limiting, caching, and logging.

## Architecture

```
Client
  │
  ▼
ApiGateway (http://localhost:5000)       ← This project
  │  - JWT Validation
  │  - Rate Limiting
  │  - Request Transformation
  │  - Response Caching
  │  - Logging & Monitoring
  ▼
SecureApiDemo (https://localhost:7028)   ← Downstream API
  │  - Business Logic
  │  - SQL Server
  │  - 2FA / Identity
```

## Features

| Feature | Implementation |
|---|---|
| **Request Routing** | Ocelot route configuration in ocelot.json |
| **JWT Auth at Gateway** | Validates token before forwarding to downstream |
| **Rate Limiting** | Per-route limits (5/min auth, 100/min data) |
| **Response Caching** | Profile endpoint cached 30s via CacheManager |
| **Request Transformation** | Adds correlation ID, gateway headers, client IP |
| **Logging & Monitoring** | Serilog — console + rolling file logs |
| **CORS** | Centralized CORS policy at gateway level |
| **Security Headers** | Added to all responses at gateway level |

## Quick Start

### Step 1 — Start SecureApiDemo first
```bash
cd ../NewApiProject
dotnet run
# Running on https://localhost:7028
```

### Step 2 — Start ApiGateway
```bash
cd ../ApiGateway
dotnet run
# Running on http://localhost:5000
```

## Gateway Routes

All client requests go through `http://localhost:5000/gateway/...`

### Auth (No token required)
```
POST http://localhost:5000/gateway/auth/register
POST http://localhost:5000/gateway/auth/login
POST http://localhost:5000/gateway/auth/refresh
```

### Auth (Token required)
```
POST http://localhost:5000/gateway/auth/logout
POST http://localhost:5000/gateway/auth/2fa/setup
POST http://localhost:5000/gateway/auth/2fa/verify
POST http://localhost:5000/gateway/auth/2fa/disable
```

### Data (Token required)
```
GET http://localhost:5000/gateway/data/profile
GET http://localhost:5000/gateway/data/my-sessions
```

### Admin (Token + Admin role required)
```
GET http://localhost:5000/gateway/data/admin/secret
GET http://localhost:5000/gateway/data/admin/users
```

## Rate Limits

| Route | Limit |
|---|---|
| `/gateway/auth/register` | 5 req/min |
| `/gateway/auth/login` | 5 req/min |
| `/gateway/auth/refresh` | 10 req/min |
| `/gateway/data/profile` | 100 req/min |
| `/gateway/data/admin/*` | 20 req/min |

## Request Headers Added by Gateway

Every request forwarded to downstream includes:
```
X-Gateway-Source: OcelotGateway
X-Gateway-Version: 1.0.0
X-Gateway-Timestamp: <unix timestamp>
X-Correlation-Id: <unique per request>
X-Real-IP: <client IP>
X-Forwarded-For: <client IP>
X-Forwarded-By: ApiGateway/1.0
```

## Response Headers Added by Gateway

Every response back to client includes:
```
X-Request-Id: <8 char unique ID>
X-Gateway: Ocelot/SecureApiDemo
X-Correlation-Id: <same as request>
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
```

## Logs

Gateway logs are written to:
- **Console** — real-time during development
- **logs/gateway-YYYYMMDD.log** — rolling daily files, kept 7 days

Log format:
```
[10:32:15 INF] [A3F9C1B2] ➡ POST /gateway/auth/login | IP: 127.0.0.1
[10:32:15 INF] [A3F9C1B2] ✅ POST /gateway/auth/login → 200 | 142ms | IP: 127.0.0.1
```

## Author

Shehroz Reaz — Software Engineer specializing in secure cloud-native systems.
